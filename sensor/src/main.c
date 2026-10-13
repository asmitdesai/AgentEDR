// SPDX-License-Identifier: Apache-2.0
/*
 * agentedr-sensor: loads the BPF programs, streams events as JSON lines on
 * stdout and accepts control commands on stdin (SPEC 6.6, 7).
 *
 * Event loop: one epoll set with four fds
 *   - the ring buffer (libbpf exposes an epoll fd for it)
 *   - stdin (commands)
 *   - a signalfd for SIGINT/SIGTERM (clean shutdown without async handlers)
 *   - a timerfd for periodic STATS lines
 */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "agentedr.skel.h"
#include "events.h"
#include "json.h"
#include "protocol.h"

#define AGENTEDR_MAP_TYPES_ONLY
#include "maps.h"

#define SENSOR_VERSION "0.1.0"
#define CMD_LINE_MAX   4096

enum exit_code {
    EXIT_OK = 0, EXIT_BAD_ARGS = 2, EXIT_UNSUPPORTED = 3,
    EXIT_LOAD = 4, EXIT_ATTACH = 5,
};

static struct {
    unsigned ringbuf_kib;
    const char *mode;       /* "auto" | "lsm" | "fentry" as requested */
    unsigned stats_interval;
} opts = { 256, "auto", 10 };

static __u64 events_emitted;
static bool stdout_broken;

/* ------------------------------------------------------------ event output */

static void hdr_fields(struct jbuf *jb, const char *type, const struct event_hdr *h)
{
    jb_str(jb, "type", type, 16);
    jb_int(jb, "ts_ns", (int64_t)h->ts_ns);
    jb_int(jb, "pid", h->pid);
    jb_int(jb, "tid", h->tid);
    jb_int(jb, "ppid", h->ppid);
    jb_int(jb, "uid", h->uid);
    jb_int(jb, "session_id", (int64_t)h->session_id);
    jb_int(jb, "agent_kind", h->agent_kind);
    jb_str(jb, "comm", h->comm, sizeof(h->comm));
}

/* Ring buffer callback: one kernel event -> one JSON line. */
static int handle_event(void *ctx, void *data, size_t size)
{
    const struct event_hdr *h = data;
    struct jbuf jb;
    (void)ctx;

    if (size < sizeof(*h))
        return 0;
    jb_begin(&jb);
    switch (h->type) {
    case EV_EXEC: {
        const struct exec_event *e = data;
        __u32 alen = e->argv_len < ARGV_MAX_BPF ? e->argv_len : ARGV_MAX_BPF;

        if (size < sizeof(*e))
            return 0;
        hdr_fields(&jb, "EXEC", h);
        jb_str(&jb, "filename", e->filename, sizeof(e->filename));
        jb_str_list(&jb, "argv", e->argv, alen);
        jb_bool(&jb, "argv_truncated", e->argv_truncated);
        jb_bool(&jb, "session_start", e->session_start);
        jb_bool(&jb, "untagged", e->untagged);
        break;
    }
    case EV_EXIT: {
        const struct exit_event *e = data;

        if (size < sizeof(*e))
            return 0;
        hdr_fields(&jb, "EXIT", h);
        jb_int(&jb, "exit_code", e->exit_code);
        jb_bool(&jb, "is_root", e->is_root);
        break;
    }
    default:
        return 0; /* other event types arrive in M1 */
    }
    if (jb_end(&jb) < 0) {
        stdout_broken = true;
        return -1; /* stops ring_buffer__consume */
    }
    events_emitted++;
    return 0;
}

/* --------------------------------------------------------- control output */

static void simple_line(const char *type)
{
    struct jbuf jb;

    jb_begin(&jb);
    jb_str(&jb, "type", type, 16);
    if (jb_end(&jb) < 0)
        stdout_broken = true;
}

static __u64 read_counter(struct agentedr_bpf *skel, __u32 idx)
{
    __u64 v = 0;

    bpf_map__lookup_elem(skel->maps.counters, &idx, sizeof(idx), &v, sizeof(v), 0);
    return v;
}

static void print_stats(struct agentedr_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.agent_pids);
    __u32 key, next, *prev = NULL;
    __u64 tagged = 0;
    struct timespec ts;
    struct jbuf jb;

    /* Count entries by walking keys; cheap at 16k entries every few seconds. */
    while (bpf_map_get_next_key(fd, prev, &next) == 0) {
        tagged++;
        key = next;
        prev = &key;
    }
    clock_gettime(CLOCK_BOOTTIME, &ts);

    jb_begin(&jb);
    jb_str(&jb, "type", "STATS", 8);
    jb_int(&jb, "ts_ns", (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    jb_int(&jb, "ringbuf_drops", (int64_t)read_counter(skel, CTR_RINGBUF_DROPS));
    jb_int(&jb, "tag_map_full", (int64_t)read_counter(skel, CTR_TAG_MAP_FULL));
    jb_int(&jb, "tagged_pids", (int64_t)tagged);
    jb_int(&jb, "events_emitted", (int64_t)events_emitted);
    if (jb_end(&jb) < 0)
        stdout_broken = true;
}

/* ----------------------------------------------------------------- setup */

static void usage(FILE *f)
{
    fprintf(f, "usage: agentedr-sensor [--ringbuf-kib N] [--mode auto|lsm|fentry]"
               " [--stats-interval SECONDS]\n");
}

static int parse_args(int argc, char **argv)
{
    static const struct option long_opts[] = {
        { "ringbuf-kib", required_argument, NULL, 'r' },
        { "mode", required_argument, NULL, 'm' },
        { "stats-interval", required_argument, NULL, 's' },
        { "help", no_argument, NULL, 'h' },
        { 0 },
    };
    unsigned long page_kib = (unsigned long)sysconf(_SC_PAGESIZE) / 1024;
    char *end;
    int c;

    while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (c) {
        case 'r':
            opts.ringbuf_kib = (unsigned)strtoul(optarg, &end, 10);
            /* Kernel requirement: power of two and a multiple of page size. */
            if (*end || opts.ringbuf_kib < page_kib ||
                (opts.ringbuf_kib & (opts.ringbuf_kib - 1)) ||
                opts.ringbuf_kib > 1024 * 1024)
                return -1;
            break;
        case 'm':
            if (strcmp(optarg, "auto") && strcmp(optarg, "lsm") && strcmp(optarg, "fentry"))
                return -1;
            opts.mode = optarg;
            break;
        case 's':
            opts.stats_interval = (unsigned)strtoul(optarg, &end, 10);
            if (*end || opts.stats_interval == 0)
                return -1;
            break;
        case 'h':
            usage(stdout);
            exit(EXIT_OK);
        default:
            return -1;
        }
    }
    return optind == argc ? 0 : -1;
}

/* True if "bpf" is one of the comma-separated active LSMs. */
static bool bpf_lsm_active(void)
{
    char buf[512], *tok, *save;
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    bool found = false;

    if (!f)
        return false;
    if (fgets(buf, sizeof(buf), f))
        for (tok = strtok_r(buf, ",\n", &save); tok; tok = strtok_r(NULL, ",\n", &save))
            if (strcmp(tok, "bpf") == 0)
                found = true;
    fclose(f);
    return found;
}

/* libbpf log callback: warnings and errors (including the verifier log on a
 * failed load) go to stderr, which the engine forwards to its log. */
static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, ap);
}

static int add_epoll(int epfd, int fd)
{
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };

    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

/* Reads available stdin bytes and runs each complete line as a command.
 * Returns false on EOF (engine closed the pipe) or stdout failure. */
static bool handle_stdin(struct agentedr_bpf *skel)
{
    static char buf[CMD_LINE_MAX];
    static size_t len;
    static bool discarding; /* inside an over-long line */
    ssize_t n = read(STDIN_FILENO, buf + len, sizeof(buf) - len - 1);
    char *line, *nl;

    if (n == 0)
        return false;
    if (n < 0)
        return errno == EINTR || errno == EAGAIN;
    len += (size_t)n;
    buf[len] = '\0';

    line = buf;
    while ((nl = memchr(line, '\n', len - (size_t)(line - buf)))) {
        *nl = '\0';
        if (nl > line && nl[-1] == '\r')
            nl[-1] = '\0';
        if (discarding)
            discarding = false;
        else if (*line && protocol_handle_line(skel, line) < 0)
            return false;
        line = nl + 1;
    }
    len -= (size_t)(line - buf);
    memmove(buf, line, len);
    if (len == sizeof(buf) - 1) {
        /* No newline in a full buffer: drop this line, report it once. */
        len = 0;
        if (!discarding) {
            discarding = true;
            fprintf(stderr, "agentedr-sensor: command line too long, ignored\n");
        }
    }
    return true;
}

int main(int argc, char **argv)
{
    struct agentedr_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct utsname uts;
    const char *mode;
    int epfd = -1, sigfd = -1, tfd = -1, rbfd, err, ret = EXIT_OK;
    sigset_t mask;

    if (parse_args(argc, argv) < 0) {
        usage(stderr);
        return EXIT_BAD_ARGS;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN); /* a dead engine shows up as a write error */
    libbpf_set_print(libbpf_print);

    if (access("/sys/kernel/btf/vmlinux", R_OK) != 0) {
        fprintf(stderr, "agentedr-sensor: kernel BTF not available (/sys/kernel/btf/vmlinux)\n");
        return EXIT_UNSUPPORTED;
    }

    /* Kernels before 5.11 charge BPF maps against RLIMIT_MEMLOCK. */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0)
        fprintf(stderr, "agentedr-sensor: warning: cannot raise RLIMIT_MEMLOCK: %s\n",
                strerror(errno));

    /* Mode selection. M0 only has tracepoint programs, which are identical
     * in both modes; the LSM/fentry program sets arrive in M1. */
    if (strcmp(opts.mode, "auto") == 0)
        mode = bpf_lsm_active() ? "lsm" : "fentry";
    else if (strcmp(opts.mode, "lsm") == 0 && !bpf_lsm_active()) {
        fprintf(stderr, "agentedr-sensor: --mode lsm requested but BPF LSM is not active\n");
        return EXIT_UNSUPPORTED;
    } else
        mode = opts.mode;

    skel = agentedr_bpf__open();
    if (!skel) {
        fprintf(stderr, "agentedr-sensor: failed to open BPF object\n");
        return EXIT_LOAD;
    }
    bpf_map__set_max_entries(skel->maps.events, opts.ringbuf_kib * 1024);
    if ((err = agentedr_bpf__load(skel)) != 0) {
        fprintf(stderr, "agentedr-sensor: failed to load BPF programs: %s\n", strerror(-err));
        ret = EXIT_LOAD;
        goto out;
    }
    if ((err = agentedr_bpf__attach(skel)) != 0) {
        fprintf(stderr, "agentedr-sensor: failed to attach BPF programs: %s\n", strerror(-err));
        ret = EXIT_ATTACH;
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "agentedr-sensor: failed to create ring buffer reader\n");
        ret = EXIT_LOAD;
        goto out;
    }

    /* Block SIGINT/SIGTERM and receive them through a signalfd instead. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    sigfd = signalfd(-1, &mask, SFD_CLOEXEC);

    struct itimerspec its = {
        .it_interval = { .tv_sec = opts.stats_interval },
        .it_value = { .tv_sec = opts.stats_interval },
    };
    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    timerfd_settime(tfd, 0, &its, NULL);

    rbfd = ring_buffer__epoll_fd(rb);
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (sigfd < 0 || tfd < 0 || epfd < 0 || add_epoll(epfd, rbfd) ||
        add_epoll(epfd, STDIN_FILENO) || add_epoll(epfd, sigfd) || add_epoll(epfd, tfd)) {
        fprintf(stderr, "agentedr-sensor: event loop setup failed: %s\n", strerror(errno));
        ret = EXIT_LOAD;
        goto out;
    }

    uname(&uts);
    {
        struct jbuf jb;

        jb_begin(&jb);
        jb_str(&jb, "type", "READY", 8);
        jb_str(&jb, "version", SENSOR_VERSION, 16);
        jb_str(&jb, "mode", mode, 8);
        jb_str(&jb, "kernel", uts.release, sizeof(uts.release));
        jb_int(&jb, "ringbuf_kib", opts.ringbuf_kib);
        if (jb_end(&jb) < 0)
            goto out;
    }

    for (bool running = true; running && !stdout_broken;) {
        struct epoll_event evs[4];
        int n = epoll_wait(epfd, evs, 4, -1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;

            if (fd == rbfd) {
                ring_buffer__consume(rb);
            } else if (fd == STDIN_FILENO) {
                if (!handle_stdin(skel))
                    running = false;
            } else if (fd == sigfd) {
                running = false;
            } else if (fd == tfd) {
                __u64 expirations;

                if (read(tfd, &expirations, sizeof(expirations)) > 0)
                    print_stats(skel);
            }
        }
    }

out:
    /* Destroying the skeleton detaches all programs and frees the maps. */
    ring_buffer__free(rb);
    agentedr_bpf__destroy(skel);
    if (epfd >= 0)
        close(epfd);
    if (ret == EXIT_OK && !stdout_broken)
        simple_line("BYE");
    return ret;
}
