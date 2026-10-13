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

struct event_hdr {
    __u32 type;
    __u32 pid;          /* tgid */
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 agent_kind;
    __u64 ts_ns;
    __u64 session_id;
    char  comm[COMM_LEN];
};

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
