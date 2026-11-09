# ADR 0023: Sensor size budget and file layout

Status: Accepted (2026-11-07)
Milestone: M0.5 (budget), M1a (file split)
Related: the M0 sensor already exceeded its line budget; decision N6; SPEC 4.1, 18; contributor sensor rules

## Context

SPEC 4.1 budgets userspace C at about 600 lines and BPF C at about 800. M0 userspace is
already 672 non-blank, non-comment lines (`main.c` 346, `protocol.c` 152, `json.c` 149,
headers 25). The approved re-cut adds, in userspace:

| Item | Lines (approx.) |
|---|---|
| TAG/UNTAG with `/proc` walk and start-time checks | 150 |
| SET_PATH_FILTER | 40 |
| Serializers for new event types | 150 |
| Second ring buffer | 20 |
| Map sizing args | 15 |
| Watchlist commands (v0.2) | 60 |

In BPF, it adds LSM and fentry variants of the file, exec-check, connect, rename and
sendmsg hooks, plus tamper hooks. The budgets cannot hold. Letting `main.c` absorb the growth
would hurt the owner's ability to review C, which is the point of the budget.

## Decision

1. **Budgets**, counted as non-blank lines that are not comment-only:
   - userspace C (excluding the generated skeleton): about 1200 in total, no file above
     about 400;
   - BPF C: about 1400 in total.
2. **Userspace layout** (`sensor/src/`):

   | File | Contents |
   |---|---|
   | `main.c` | Argument parsing, mode detection, load and attach, epoll loop |
   | `protocol.c/.h` | Command parsing and ACKs |
   | `json.c/.h` | JSON line writer |
   | `proc_walk.c/.h` | `/proc` descendant walk, `/proc/<pid>/stat` field 22 check |
   | `events_out.c/.h` | Per-event-type serializers (moves `handle_event` out of `main.c`) |

3. **BPF layout** (`sensor/bpf/`): `agentedr.bpf.c` holds the license, includes and the
   program definitions only. Hook bodies live in headers by family:

   | Header | Contents |
   |---|---|
   | `common.h` | `fill_hdr`, emit helpers, counters, path rendering |
   | `hooks_proc.h` | exec, fork, exit |
   | `hooks_file.h` | file_open, bprm_check, path_rename |
   | `hooks_net.h` | socket_connect, socket_sendmsg |
   | `hooks_tamper.h` | bpf, task_kill and similar (M1b) |

   - Each LSM and fentry program is a thin wrapper around one `__always_inline` body, so
     the two modes cannot drift.
   - These headers are GPL-2.0 (ADR 0017: only `events.h` and `maps.h` are dual-licensed).
4. **Logic stays in Python.** DNS parsing, matching, and any decision that is not needed for
   in-kernel filtering stay in the engine. The sensor ships raw fields, such as the first N
   bytes of a DNS payload.
5. **Measuring.** Count with
   `grep -v '^\s*$' FILE | grep -v '^\s*\(/\*\|\*\|//\)' | wc -l` (the method used for M0),
   recorded with the milestone summary at each milestone end.
6. The contributor rule "Userspace sensor stays under ~600 lines" is updated to these budgets.

## Alternatives considered

- **Keep about 600 and push more into Python.** The remaining userspace code (map updates,
  `/proc` walk for TAG, serialization) has to be in C to avoid a round trip per event.
  Rejected.
- **No budget.** The budget exists to keep the C reviewable for an owner new to eBPF.
  Rejected.

## Consequences

- Each future growth beyond these numbers needs an ADR update.
- The M1a file split is a refactor with no behaviour change; it is done first in M1a, with
  the existing tests as the safety net.

## Kernel-version notes

None.

## Tests

None. The integration suite must pass unchanged after the split.
