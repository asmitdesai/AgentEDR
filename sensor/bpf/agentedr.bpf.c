// SPDX-License-Identifier: GPL-2.0
/*
 * AgentEDR kernel programs.
 *
 * M0 scope: process lifecycle only (SPEC 6.3).
 *   handle_exec  tp_btf/sched_process_exec   tag agent roots, emit EXEC
 *   handle_fork  tp_btf/sched_process_fork   copy the tag to child processes
 *   handle_exit  tp_btf/sched_process_exit   emit EXIT, drop the tag
 *
 * "tp_btf" programs attach to raw tracepoints but receive the tracepoint's
 * real, BTF-typed arguments (e.g. struct task_struct *), which is easier and
 * cheaper than classic tracepoints. Available since 5.5.
 *
 * Every program checks agent_pids first and returns as early as possible for
 * untagged processes, so non-agent processes pay only a hash lookup. The exec
 * hook is the one exception: it must also look at untagged execs to decide
 * whether a new agent session starts.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "events.h"
#include "maps.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * A name of at most 15 chars, NUL padded to 16 bytes. Comparing two of these
 * as two u64 words is cheap for the verifier (no per-char loop) and gives the
 * "first 15 chars" semantics of SPEC 6.2 for free.
 */
union name16 {
    char  c[MATCHER_NAME_LEN];
    __u64 w[2];
};

/* Basenames that may be an agent in disguise (e.g. `node .../claude-code/cli.js`).
 * Execs of these are emitted untagged so the engine can apply argv matchers. */
static const union name16 candidates[] = {
    { .c = "node" }, { .c = "bun" }, { .c = "deno" }, { .c = "python3" }, { .c = "env" },
};
#define NUM_CANDIDATES (sizeof(candidates) / sizeof(candidates[0]))

/* ---------------------------------------------------------------- helpers */

static __always_inline void counter_inc(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);

    /* Array map lookups with an in-range key never fail, but the verifier
     * cannot know that, so the NULL check is mandatory. */
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline __u64 next_session_id(void)
{
    __u32 idx = CTR_NEXT_SESSION_ID;
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);

    if (!v)
        return 0;
    /* +1 so the first session is 1; 0 means "no session" in events. */
    return __sync_fetch_and_add(v, 1) + 1;
}

static __always_inline void fill_hdr(struct event_hdr *h, __u32 type,
                                     struct task_struct *task,
                                     const struct agent_info *info)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    h->type = type;
    h->pid = pid_tgid >> 32;
    h->tid = (__u32)pid_tgid;
    h->ppid = BPF_CORE_READ(task, real_parent, tgid);
    h->uid = (__u32)bpf_get_current_uid_gid(); /* low 32 bits: real uid */
    h->ts_ns = bpf_ktime_get_boot_ns();
    h->session_id = info ? info->session_id : 0;
    h->agent_kind = info ? info->agent_kind : 0;
    bpf_get_current_comm(h->comm, sizeof(h->comm));
}

/*
 * Return the offset of the basename inside a NUL-terminated path.
 * The loop has a constant bound, which is what the verifier needs to prove
 * termination (bounded loops are supported since 5.3; bpf_loop is 5.17+ and
 * therefore avoided for 5.15 compatibility).
 */
static __always_inline __u32 basename_off(const char *path)
{
    __u32 off = 0;

    for (__u32 i = 0; i < PATH_MAX_BPF; i++) {
        char c = path[i];

        if (c == '\0')
            break;
        if (c == '/')
            off = i + 1;
    }
    return off;
}

static __always_inline bool name16_eq(const union name16 *a, const void *b)
{
    const __u64 *w = b;

    return a->w[0] == w[0] && a->w[1] == w[1];
}

/* Reads argv from the new process image. Must run after the new mm is
 * installed, which is the case in sched_process_exec. */
static __always_inline void read_argv(struct exec_event *e, struct task_struct *task)
{
    unsigned long start = BPF_CORE_READ(task, mm, arg_start);
    unsigned long end = BPF_CORE_READ(task, mm, arg_end);
    __u64 len = end > start ? end - start : 0;

    e->argv_truncated = 0;
    if (len > ARGV_MAX_BPF) {
        len = ARGV_MAX_BPF;
        e->argv_truncated = 1;
    }
    /* The explicit bound check right before the call lets the verifier prove
     * that the copy fits in e->argv. */
    if (len > ARGV_MAX_BPF)
        return;
    if (bpf_probe_read_user(e->argv, len, (void *)start) < 0)
        len = 0;
    e->argv_len = len;
}

static __always_inline void emit_exec(struct task_struct *task,
                                      struct linux_binprm *bprm,
                                      const struct agent_info *info,
                                      __u8 session_start, __u8 untagged)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e) {
        /* Ring buffer full: count and drop, never block or retry. */
        counter_inc(CTR_RINGBUF_DROPS);
        return;
    }
    fill_hdr(&e->h, EV_EXEC, task, info);
    e->session_start = session_start;
    e->untagged = untagged;
    e->_pad = 0;
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
                              BPF_CORE_READ(bprm, filename));
    read_argv(e, task);
    bpf_ringbuf_submit(e, 0);
}

/* ---------------------------------------------------------------- programs */

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec, struct task_struct *p, pid_t old_pid,
             struct linux_binprm *bprm)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    union name16 base = {}; /* zeroed: bytes after the NUL stay 0 */
    struct agent_info *info;
    char fname[PATH_MAX_BPF];
    const char *kfname;
    __u32 off;

    /* 1. Already tagged: exec keeps the tgid, so the tag persists. */
    info = bpf_map_lookup_elem(&agent_pids, &tgid);
    if (info) {
        emit_exec(p, bprm, info, 0, 0);
        return 0;
    }

    /* 2. Untagged: get the exe basename to compare against matchers.
     *
     * Verifier note: the full path is copied to the stack only to find the
     * offset of the last '/'. The basename itself is then read again from
     * kernel memory at filename + off. Using `off` only as a pointer offset
     * for a helper (never to index the stack) keeps it "imprecise" for the
     * verifier, so it does not explore every possible offset separately;
     * indexing the stack with it made the program too complex to load. */
    kfname = BPF_CORE_READ(bprm, filename);
    if (bpf_probe_read_kernel_str(fname, sizeof(fname), kfname) <= 0)
        return 0;
    off = basename_off(fname);
    bpf_probe_read_kernel_str(base.c, sizeof(base.c), kfname + off);

    for (__u32 i = 0; i < MAX_MATCHERS; i++) {
        __u32 key = i;
        struct matcher *m = bpf_map_lookup_elem(&agent_matchers, &key);

        if (!m || !m->enabled || !name16_eq(&base, m->basename))
            continue;

        struct agent_info new_info = {
            .session_id = next_session_id(),
            .agent_kind = m->agent_kind,
            .root_tgid = tgid,
        };
        if (bpf_map_update_elem(&agent_pids, &tgid, &new_info, BPF_ANY) < 0)
            counter_inc(CTR_TAG_MAP_FULL);
        emit_exec(p, bprm, &new_info, 1, 0);
        return 0;
    }

    /* 3. Candidate interpreter: emit untagged so argv matchers can run. */
    for (__u32 i = 0; i < NUM_CANDIDATES; i++) {
        if (name16_eq(&base, &candidates[i])) {
            emit_exec(p, bprm, NULL, 0, 1);
            return 0;
        }
    }
    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 child_pid = BPF_CORE_READ(child, pid);
    __u32 child_tgid = BPF_CORE_READ(child, tgid);
    __u32 parent_tgid = BPF_CORE_READ(parent, tgid);
    struct agent_info *info;

    /* New thread, not a new process: nothing to tag (maps are keyed by tgid). */
    if (child_pid != child_tgid)
        return 0;

    info = bpf_map_lookup_elem(&agent_pids, &parent_tgid);
    if (!info)
        return 0;

    /* The child joins the parent's session: same session id, kind and root. */
    if (bpf_map_update_elem(&agent_pids, &child_tgid, info, BPF_ANY) < 0)
        counter_inc(CTR_TAG_MAP_FULL);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *p)
{
    __u32 pid = BPF_CORE_READ(p, pid);
    __u32 tgid = BPF_CORE_READ(p, tgid);
    struct agent_info *info;
    struct exit_event *e;

    /* Fires once per thread; only the thread-group leader's exit counts. */
    if (pid != tgid)
        return 0;

    info = bpf_map_lookup_elem(&agent_pids, &tgid);
    if (!info)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        /* exit_code is a wait(2) status: low 7 bits = signal, bits 8-15 =
         * exit status. Report it the way shells do: status, or 128 + signal. */
        int code = BPF_CORE_READ(p, exit_code);
        int sig = code & 0x7f;

        fill_hdr(&e->h, EV_EXIT, p, info);
        e->exit_code = sig ? 128 + sig : (code >> 8) & 0xff;
        e->is_root = tgid == info->root_tgid;
        bpf_ringbuf_submit(e, 0);
    } else {
        counter_inc(CTR_RINGBUF_DROPS);
    }

    bpf_map_delete_elem(&agent_pids, &tgid);
    return 0;
}
