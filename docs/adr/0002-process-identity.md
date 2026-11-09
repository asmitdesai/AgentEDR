# ADR 0002: Process identity is (pid, start time)

Status: Accepted (2026-11-07)
Milestone: M1a
Related: pid reuse between an untagged EXEC and TAG, and within long sessions; SPEC 7.2, 8.1, 8.3, 9.4, 9.5; ADR 0024 (session identity, which uses the same start time for the session root)

## Context

Processes are identified by tgid alone, in the kernel map, in the protocol (`TAG <tgid>
<kind>`) and in the engine. Pids are reused. The `TAG` path is asynchronous: the engine sees
an untagged EXEC, decides, and sends `TAG`, by which time the pid may in principle belong to
a different process. Within a long session (default idle TTL 6 h), the engine's pid tree
can also confuse a dead process with a new one that got the same pid.

Exploitability is low (64-bit Ubuntu `pid_max` is 4194304, so reuse inside a millisecond
window needs a full wrap), but the fix is cheap and makes every later identity question
exact.

## Decision

1. Add `__u64 start_ns` to `struct event_hdr`: the thread group leader's
   `task->group_leader->start_boottime`, in boot-clock ns. This is the same clock as
   `ts_ns`.
   - Use `start_boottime`, not `start_time`. `start_time` is CLOCK_MONOTONIC.
   - Use the group leader's value so that every thread of a process reports the same
     identity.
2. The engine's process key is `(pid, start_ns)` everywhere: session pid trees, the
   per-pid cache of last EXEC, `/proc` cache entries, and stored events.
3. Protocol: `TAG <tgid> <start_ns> <kind>` and `UNTAG <tgid> <start_ns>`. Before inserting,
   the sensor:
   1. reads `/proc/<tgid>/stat` field 22 (`starttime`, in clock ticks since boot). Parsing
      starts after the last `)`, because `comm` may contain spaces and parentheses;
   2. converts the commanded `start_ns` to ticks with `sysconf(_SC_CLK_TCK)` using the
      kernel's truncating division (`start_ns / (1e9 / HZ)`);
   3. refuses with `ACK ok:false error:"start time mismatch"` if they differ, or
      `"no such process"` if the file is gone;
   4. after inserting, re-reads field 22 and rolls the insert back if it changed. This
      closes the window between the check and the insert.
4. Descendants found by the `/proc` walk (ADR 0003) are inserted after the same
   check-insert-recheck, using their own field 22.
5. Protocol version bump (ADR 0014).

## Alternatives considered

- **pidfds (`pidfd_open`) for TAG.** They give stable identity in the sensor, but the
  engine would have to hold an fd per process, and pidfds do not help events already in
  flight. Rejected for v1.
- **Kernel-side verification via a `TAG` map that the BPF exec or fork hook checks.**
  Moves logic into BPF for no gain. Rejected.
- **Using `start_time` (monotonic).** It does not match `/proc` field 22, which is derived
  from `start_boottime`. Rejected.

## Consequences

- Every event grows by 8 bytes.
- The engine can tell a reused pid from the original in replay and in rules.
- `/proc` field 22 is shifted by the reader's time namespace (`timens_add_boottime_ns`).
  The sensor runs in the init time namespace, where the offset is 0. A sensor started inside
  a time namespace would fail all TAGs; `doctor` checks for this.

## Kernel-version notes

- `start_boottime` exists since 5.5 (renamed from `real_start_time`), so it is present on
  5.15 and 6.8; CO-RE relocates it.
- Verified on 5.15 and 6.8 (aarch64, 2026-11-08) that `de_thread()` copies `start_boottime`
  from the old leader to the exec'ing thread, so the start time is stable across exec from
  a non-main thread (ADR 0001 case 1): an integration test compares the kernel's session
  key of such a root with `/proc/<pid>/stat` field 22 (ADR 0024).
- The session root's start time already travels in `agent_info` and the event header
  since M0.5 (ADR 0024). This ADR adds the per-process `start_ns` in M1a.

## Tests

- Unit (Python): `/proc/<pid>/stat` field 22 parsing with `comm` values containing spaces and
  `)`; ns-to-ticks conversion at tick boundaries.
- Protocol: TAG with a wrong start time is refused; TAG of an exited pid is refused.
- Integration: every event of a fake agent carries the same `start_ns` per process; exec
  from a worker thread keeps `start_ns`.
