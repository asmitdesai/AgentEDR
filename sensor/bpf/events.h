/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Event structs shared between the BPF programs and the userspace sensor.
 *
 * This header is included from two very different worlds:
 *   - BPF C (agentedr.bpf.c), where the __u32/__u64 types come from vmlinux.h
 *   - userspace C (sensor/src), where they come from <linux/types.h>
 * so it must not include anything itself. The includer provides the types.
 *
 * Layout rules: every struct starts with struct event_hdr so userspace can
 * read h.type first and then cast to the right struct. Fields are ordered to
 * avoid surprising padding; both sides are compiled for the same machine, so
 * padding is identical anyway.
 */
#ifndef AGENTEDR_EVENTS_H
#define AGENTEDR_EVENTS_H

#define PATH_MAX_BPF 256
#define ARGV_MAX_BPF 512
#define COMM_LEN     16

enum event_type {
    EV_EXEC = 1, EV_EXIT, EV_FILE_OPEN, EV_EXEC_CHECK,
    EV_NET_CONNECT, EV_FILE_DELETE, EV_FILE_RENAME, EV_PTRACE,
};

/*
 * Common header of every event. 64 bytes, laid out so that the compiler adds
 * no padding (every field sits at a multiple of its own size); the static
 * asserts below fail the build if that ever stops being true.
 *
 *   offset size field
 *        0    4 type
 *        4    4 pid                    tgid of the process
 *        8    4 tid                    thread that triggered the event
 *       12    4 ppid
 *       16    4 uid                    real uid
 *       20    4 agent_kind             index into the matcher table
 *       24    4 session_root_tgid      session identity, part 1 (ADR 0024)
 *       28    4 _reserved              always 0
 *       32    8 ts_ns                  boot clock (bpf_ktime_get_boot_ns)
 *       40    8 session_root_start_ns  session identity, part 2 (ADR 0024)
 *       48   16 comm
 *
 * The session is identified by its root process: (session_root_tgid,
 * session_root_start_ns), where the start time is the root's
 * task->start_boottime. 0/0 means the process is not tagged.
 */
struct event_hdr {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 agent_kind;
    __u32 session_root_tgid;
    __u32 _reserved;
    __u64 ts_ns;
    __u64 session_root_start_ns;
    char  comm[COMM_LEN];
};

_Static_assert(sizeof(struct event_hdr) == 64, "event_hdr must stay 64 bytes");
_Static_assert(__builtin_offsetof(struct event_hdr, ts_ns) == 32, "event_hdr layout changed");
_Static_assert(__builtin_offsetof(struct event_hdr, session_root_start_ns) == 40,
               "event_hdr layout changed");
_Static_assert(__builtin_offsetof(struct event_hdr, comm) == 48, "event_hdr layout changed");

struct exec_event {
    struct event_hdr h;
    __u8  session_start;
    __u8  untagged;
    __u8  argv_truncated;
    __u8  _pad;
    __u32 argv_len;
    char  filename[PATH_MAX_BPF];
    char  argv[ARGV_MAX_BPF];
};

struct exit_event   { struct event_hdr h; __s32 exit_code; __u8 is_root; };

struct file_event {
    struct event_hdr h;
    __u32 f_mode;
    __u32 f_flags;
    __u8  truncated;
    char  path[PATH_MAX_BPF];
};

struct net_event {
    struct event_hdr h;
    __u16 family;
    __u16 dport;        /* host byte order */
    __u16 socktype;
    __u8  daddr[16];    /* v4 in first 4 bytes */
};

struct rename_event {
    struct event_hdr h;
    __u8 truncated;
    char old_path[PATH_MAX_BPF];
    char new_path[PATH_MAX_BPF];
};

struct ptrace_event { struct event_hdr h; __u32 target_pid; __u32 mode; };

#endif /* AGENTEDR_EVENTS_H */
