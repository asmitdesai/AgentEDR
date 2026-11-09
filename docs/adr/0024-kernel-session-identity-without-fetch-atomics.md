# ADR 0024: Kernel session identity without fetch atomics

Status: Accepted (2026-11-08)
Milestone: M0.5
Related: the M0 sensor failed to load on Ubuntu 22.04 arm64; ADR 0001 (exit handling), ADR 0002 (process identity), ADR 0003 (adoption), ADR 0014 (protocol version); SPEC 6.2, 6.3, 7.1, 8.1, 8.3, 8.4, 9.3, 9.5, 13, gotcha 25

## Context

The M0 sensor gave each new session a kernel id from a global counter:
`__sync_fetch_and_add(&counters[0], 1) + 1`. Because the return value is used, clang emits
a fetch-and-add (`BPF_ATOMIC | BPF_ADD | BPF_FETCH`).

On Ubuntu 22.04 arm64 (`5.15.0-203-generic`) `handle_exec` then fails to load with
`-524` (ENOTSUPP), in both LSM and fentry mode, after the verifier has accepted it:

- The kernel log shows `bpf_jit: unknown atomic op code 01` (0x01 is `BPF_ADD | BPF_FETCH`).
- `arch/arm64/net/bpf_jit_comp.c` in that kernel's source handles `BPF_STX | BPF_ATOMIC`
  only when `insn->imm == BPF_ADD`. Any other atomic returns `-EINVAL` with that message.
- Ubuntu sets `CONFIG_BPF_JIT_ALWAYS_ON=y`, so there is no interpreter fallback.
  `bpf_prog_select_runtime()` turns the failed JIT into `-ENOTSUPP`.
- A throwaway build that kept the atomic add but ignored its result loaded and reached
  READY on the same kernel.
- The x86_64 JIT in the same 5.15 source supports `BPF_FETCH`, `BPF_XCHG` and
  `BPF_CMPXCHG`. The 6.8 arm64 JIT supports them too, so 22.04 arm64 is the only target
  that fails.

The obvious replacement, a per-CPU counter combined with the CPU number, is not safe. The
read-modify-write is not atomic, and a tracing program can be preempted in the middle of it
by another program on the same CPU, which would produce duplicate ids. `cmpxchg` and
`xchg` are fetch-class atomics with the same JIT problem, and tracing programs cannot use
`bpf_spin_lock` on 5.15.

A kernel session id also never needed to be allocated. A session is defined by its root
process, and a process already has a stable identity: its tgid plus its start time
(ADR 0002).

## Decision

1. **Session identity is the session root's process identity.** `agent_info` becomes:

   ```c
   struct agent_info {
       __u64 root_start_ns;  /* task->start_boottime of the session root, boot ns */
       __u32 root_tgid;      /* tgid of the session root */
       __u32 agent_kind;     /* index into matcher table */
   };                        /* 16 bytes, no padding */
   ```

   `handle_exec` fills it when a matcher hits, reading `start_boottime` with CO-RE.
   `handle_fork` copies it to children unchanged. The global session counter and
   `CTR_NEXT_SESSION_ID` are removed; the remaining counters are renumbered
   (`CTR_RINGBUF_DROPS = 0`, `CTR_TAG_MAP_FULL = 1`).
2. **Event header.** `session_id` is replaced by `session_root_tgid` (u32) and
   `session_root_start_ns` (u64). `0`/`0` means not tagged (only candidate EXECs are
   emitted untagged). The header is 64 bytes with no padding:

   | Offset | Size | Field |
   |---|---|---|
   | 0 | 4 | `type` |
   | 4 | 4 | `pid` (tgid) |
   | 8 | 4 | `tid` |
   | 12 | 4 | `ppid` |
   | 16 | 4 | `uid` |
   | 20 | 4 | `agent_kind` |
   | 24 | 4 | `session_root_tgid` |
   | 28 | 4 | `_reserved` (always 0) |
   | 32 | 8 | `ts_ns` |
   | 40 | 8 | `session_root_start_ns` |
   | 48 | 16 | `comm` |

   `_Static_assert`s on the size and on the offsets of `ts_ns`, `session_root_start_ns`
   and `comm` fail the build if the layout drifts. The M1a fields from ADR 0002 and open
   decision 1 (`start_ns`, `cgroup_id`) are inserted before `comm`, keeping the same rule.
3. **Engine key.** The engine's kernel session key is
   `(root_tgid, root_start_ns // TICK_NS * TICK_NS)`, where `TICK_NS` is
   `1e9 / sysconf(_SC_CLK_TCK)` (10 ms on Ubuntu). It maps the key to the globally unique
   session uid (SPEC 9.5). Events carry the full nanosecond value; only the key is
   truncated.
4. **Why the key survives a sensor restart.** A restart loses every kernel tag. The engine
   then adopts running agents from `/proc` (ADR 0003):
   - It reads the root's start time from `/proc/<pid>/stat` field 22. The kernel computes
     that field as `start_boottime / (1e9 / USER_HZ)` with truncating division, which is
     exactly the truncation in step 3. So the key the engine builds from `/proc` equals
     the key it built from the original kernel events, without a lookup table or any state
     kept across the restart.
   - `TAG <tgid> <start_ns> <kind>` (ADR 0002, M1a) sends that tick-precision start time.
     The sensor stores it as `root_start_ns` in the new `agent_info`, so later events of
     the adopted session produce the same key again.
   - This lets the engine find the interrupted session deterministically, by key, and set
     `continues` on the new session (SPEC 9.3). Late events after eviction are reloaded
     by key from SQLite instead of by `(sensor_run, kernel_id)`.
   - Uniqueness: two processes with the same tgid and the same start tick would need the
     pid to be reused within one tick, which needs a full pid wrap (`pid_max` 4194304 on
     64-bit Ubuntu) inside 10 ms.
   - `/proc` field 22 is shifted by the reader's time namespace. The engine and sensor run
     in the init time namespace, where the offset is 0 (as in ADR 0002).
   - It relies on `de_thread()` copying the old leader's `start_boottime` to a thread that
     execs. An integration test reads field 22 after an exec from a worker thread and
     compares it with the kernel key; it passes on 5.15 and 6.8. That also answers the
     open VERIFY in ADR 0002.
5. **No fetch-class atomics in BPF.** The BPF object must not contain `atomic_fetch_*`,
   `xchg` or `cmpxchg` in any width. Plain atomic adds whose result is unused
   (`lock *(u64 *)(r0 + 0) += r1`) stay, for counters. `make sensor` disassembles the
   object and fails if it finds a forbidden instruction, or an instruction `llvm-objdump`
   cannot decode (`<unknown>`, which some versions print for atomic encodings). CI runs
   `make sensor`, so CI enforces it as well.
6. **Protocol version stays 1.** Protocol 1 was introduced in M0.5 and has never been
   released, so changing its event fields does not bump it. The rule in ADR 0014 applies
   from the first release onwards.

## Alternatives considered

- **Per-CPU counter with the CPU number in the high bits.** No atomic needed, but the
  read-modify-write can be interrupted on the same CPU (a tracing program can be preempted
  by another), which can produce duplicate ids. Rejected.
- **`cmpxchg` loop or `xchg`.** Fetch-class; the 5.15 arm64 JIT rejects them. Rejected.
- **`bpf_spin_lock` around the counter.** Not available to tracing programs on 5.15.
  Rejected.
- **Let userspace allocate ids and push them into the map.** The kernel would need to tag
  the root before userspace has seen it, so the first events of every session would have
  no id. Rejected.
- **Use the root tgid alone.** Not unique over time (pid reuse) and gives no way to match a
  session across a sensor restart safely. Rejected.

## Consequences

- No shared mutable state in the kernel for session creation, so nothing can race.
- The header stays 64 bytes. M0's header had a single 8-byte session id; the identity now
  takes 12 bytes plus 4 reserved.
- The engine needs `TICK_NS`. It is read once at import with `os.sysconf("SC_CLK_TCK")`.
- Every consumer of `session_id` changes: engine models, decoder, CLI output, the fake
  sensor and the tests. The CLI prints the global session uid instead of the kernel id.
- SPEC 9.5 `kernel_id` and the SQLite `(sensor_run, kernel_id)` index are replaced by the
  key (SPEC v0.4.1).

## Kernel-version notes

- `task_struct.start_boottime` exists since 5.5; CO-RE relocates it on 5.15 and 6.8.
- 5.15 arm64 JIT: only non-fetch `BPF_ADD` atomics (checked in the Ubuntu
  `linux_5.15.0-203.213` source). 5.15 x86_64 JIT and 6.8 arm64 JIT: all atomics.
- The build check is the only guard: an x86_64 or 6.8 test run would not catch a
  regression.

## Tests

- Unit: an EXEC line decodes to the expected `SessionKey`; an untagged event has no key;
  the key built from a `/proc` tick value equals the key built from any nanosecond value
  inside that tick, and differs across ticks and tgids.
- Protocol: the fake sensor emits the new fields; children of a session share the root's
  key.
- Integration (all VMs, both modes): every existing session assertion uses the key; the
  kernel key of a live multi-threaded root, and of a root that exec'd from a worker
  thread, equals the key rebuilt from `/proc/<pid>/stat` field 22.
- Build: `make sensor` fails on an object containing a fetch-class atomic. Checked by hand
  with test objects for `atomic_fetch_add`, `atomic_fetch_or`, `atomic_fetch_and`,
  `atomic_fetch_xor`, `xchg_64` and `cmpxchg_64`.
