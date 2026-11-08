# ADR 0001: Group-exit-aware tag lifetime

Status: Accepted (2026-11-07)
Milestone: M0.5
Related: review NEW-1, NEW-2; SPEC 6.3, 8.2, gotcha 1

## Context

`handle_exit` (`sensor/bpf/agentedr.bpf.c`) returns early for `pid != tgid` and, for the
thread with `pid == tgid`, emits EXIT and deletes the `agent_pids` entry. That treats "the
main thread exited" as "the process exited", and the two are not the same:

1. **Exec from a non-main thread.** `de_thread()` kills every other thread, including the
   old main thread, before the exec completes. The old main thread's exit deletes the tag,
   so when `sched_process_exec` fires for the same tgid the process is untagged. All later
   activity of the new image and its children is invisible.
2. **Main thread exits first.** If the main thread calls `pthread_exit` while workers keep
   running, the tag is deleted and a false EXIT (with `is_root` for a session root) is
   emitted, while the process continues untracked.

Both were reproduced on 6.8 with one `python3 -c` line each. The payloads ran and the sensor
emitted no events for them. Either case is reachable by the SPEC 2.2 adversary, because an
injected instruction can make the agent run such a one-liner.

When the main thread exits first, the last thread to die is a worker (`pid != tgid`). Any
fix that only looks at the main thread cannot see the real end of the process.

## Decision

1. Remove the `pid != tgid` early return from `handle_exit`.
2. In `tp_btf/sched_process_exit`, read `p->signal->live` with CO-RE. If it is not 0, other
   threads of the group are still alive: return without touching the tag. The process is
   still running, and still tagged.
3. If `live == 0`, the group is dead. Look up `agent_pids[tgid]` (the map stays keyed by
   tgid). If there is no entry, return.
4. Copy the entry to the stack, then `bpf_map_delete_elem(&agent_pids, &tgid)`. Emit EXIT
   only if the delete returned 0. This makes the delete the exactly-once arbiter:
   - `live` is read after the decrement, so two threads that exit at nearly the same time
     can both observe `live == 0`.
   - Only one of them can delete the entry, so exactly one EXIT is emitted.
5. EXIT fields:
   - `pid` = tgid; `tid` = the dying thread's id, which may differ from `pid`.
   - `exit_code` = `signal->group_exit_code` when `SIGNAL_GROUP_EXIT` (0x4) is set in
     `signal->flags`, else the dying thread's `exit_code`. Both use the wait(2) status
     encoding and are decoded as today: status, or 128 + signal.
   - `is_root = (tgid == root_tgid)`, unchanged.
6. `SIGNAL_GROUP_EXIT` is a `#define`, not in BTF, so the BPF code defines it locally with
   a comment, and its value is checked on each target kernel.
7. `handle_fork` is unchanged: threads (`child pid != tgid`) are still not inserted, because
   the map is keyed by tgid and a new thread already belongs to a tagged tgid.
8. `handle_exec` is unchanged: after `de_thread()` the exec'ing thread takes over the tgid,
   and the tag (no longer deleted early) persists across exec.

## Alternatives considered

- **`tp_btf/sched_process_free`.** Fires when the task struct is freed, which only happens
  after the parent reaps it. An unreaped zombie would never produce EXIT, and timestamps
  would be late. Rejected.
- **fentry on `release_task` or `exit_notify`.** These are internal functions, not a stable
  attach surface, and may be inlined. Rejected.
- **Check `thread_group_empty()`-style list state in the tracepoint.** Racy, and the list is
  harder to read reliably with CO-RE than an atomic counter. Rejected.
- **Per-tgid thread refcount maintained in BPF on fork and exit.** It duplicates
  `signal->live`, and every missed event corrupts it. Rejected.

## Consequences

- EXIT now marks the real end of the process, so session end (SPEC 9.5) is no longer
  triggered by a root that calls `pthread_exit`.
- EXIT `tid` can differ from `pid`. The engine must not assume `tid == pid` for EXIT. The
  decoder already accepts any `tid`.
- Cost: one extra CO-RE read on every thread exit system-wide before the map lookup.
  Negligible.
- About 15 lines of BPF change. No userspace protocol change; the EXIT schema is unchanged.

## Kernel-version notes

- 6.8 (Ubuntu 24.04, aarch64): verified on 2026-11-07 that `signal->live` is decremented
  before `trace_sched_process_exit`. A single-threaded exit sees `live == 0`; with
  main-first exit, the main thread sees 1 and the last worker sees 0; in the exec-from-thread
  case, the old main thread sees 1. `group_exit_code` uses the wait-status encoding. Results
  are in the review, section 5.1.
- 5.15 (Ubuntu 22.04): **VERIFY** the same ordering and the `SIGNAL_GROUP_EXIT` value before
  M1a closes. If the ordering differs, fall back to treating `live <= 1` at the tracepoint
  plus the delete arbiter, and document it here.
- `signal_struct.live` and `group_exit_code` exist on every supported kernel; CO-RE
  relocates the offsets.

## Tests

Integration tests (`make vm-test`), each through a fake agent:

1. Exec from a worker thread: the new image and a child it spawns carry the session id.
2. Main thread `pthread_exit`, worker returns last: exactly one EXIT, after the worker's
   activity, with `pid == tgid`; the worker's activity before exit is tagged.
3. Main thread `pthread_exit`, worker `os._exit(5)` last: exactly one EXIT with `exit_code 5`.
4. The fake agent root itself exits main-first with a worker last: EXIT with `is_root=true`
   fires exactly once and session end fires exactly once (asserted at the engine, by
   counting session-end notifications).
5. Regression: single-threaded exit unchanged (exit code, `is_root`).

Cases 1 to 3 are also the first entries of `bench/evasions/` (EVA-001, EVA-002).
