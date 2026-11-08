# ADR 0003: Session adoption and the argv-tag race

Status: Accepted (2026-11-07)
Milestone: M1a
Related: review SE-2, SE-3, NEW-12, NEW-19, decision N3; SPEC 2.5, 6.3, 9.3, 9.4, 9.5, gotcha 12

## Context

Two gaps leave agents untracked:

- **Pre-existing agents (SE-2).** Tags are created only on exec. An agent that started
  before AgentEDR, or before a sensor restart (which loses every kernel tag, SPEC 9.3), is
  invisible.
- **The argv-tag race (SE-3).** Agents launched through an interpreter (`node .../cli.js`)
  are tagged by the engine after an untagged candidate EXEC. Between the EXEC and the `TAG`,
  the process can fork. The `/proc` descendant walk in `TAG` catches children that are still
  alive, but not actions already taken.

The SPEC 2.2 adversary controls text, and that text reaches the agent seconds after process
start (after at least one model round trip), while `TAG` latency is milliseconds. The race
matters in practice only when the engine is down or backlogged, which adoption covers.

## Decision

### Adoption

1. After every sensor `READY` (first start and every restart), the engine first sends
   `SET_MATCHERS`, then scans `/proc`. Order matters: once the matchers are live, the
   kernel catches new execs itself, so anything the scan misses is caught by the kernel.
2. For each `/proc/<pid>` that is a thread group leader:
   - **Exe check:** match the basename of `/proc/<pid>/exe` and the basename of `argv[0]`
     from `/proc/<pid>/cmdline` against `exe_basename`. Both are checked because the kernel
     matcher sees the path as invoked (`bprm->filename`, e.g. a `claude` symlink), while
     `/proc/<pid>/exe` is resolved (e.g. a versioned binary; NEW-19).
   - **Argv check:** apply `argv_contains` to the cmdline.
3. For each match, walk ancestors via `/proc/<pid>/stat` field 4 (ppid). Adopt only the
   topmost matching process. Nested agents belong to the outer session.
4. Adopt with `TAG <tgid> <start_ns> <kind>` (ADR 0002). The sensor inserts the root and
   walks `/proc/<tgid>/task/*/children` recursively, with the same identity checks for each
   descendant.
5. `TAG` of a tgid that is already tagged is a no-op that returns
   `ACK ok:true note:"already tagged"`, so adoption never creates a second session for a
   process the kernel matcher just tagged.
6. Adopted sessions get:
   - `adopted=true`;
   - `started_at` from the root's `start_ns`, the real start;
   - `observed_from` = adoption time;
   - a coverage gap record from `started_at` to `observed_from`.
   History before adoption is missing, and `replay` says so.
7. After a sensor restart, an adopted session whose root `(pid, start_ns)` equals the root
   of a session that was marked `interrupted` gets `continues=<previous uid>`, so the two
   halves can be read as one story.
8. Privacy (ADR 0021): cmdlines read during the scan are used only for matching. Nothing is
   stored or logged for non-matching processes.

### Argv-tag race

1. Keep userspace `TAG` with the `/proc` walk (no in-kernel change).
2. Measure `tag_latency_ms` = ACK receipt time minus EXEC `ts_ns`, both on the boot clock.
   Record it on the session and log a warning above 100 ms.
3. A race test is required (gotcha 12): a candidate interpreter that forks children
   immediately after exec; assert that every live child is tagged after `TAG`.
4. Revisit (a) or (b) below only if benchmark p95 `tag_latency_ms` exceeds 50 ms or a
   working exploit of the window is demonstrated.

## Alternatives considered

- **(a) Provisional in-kernel tags.** Every candidate interpreter (`node`, `python3`, `bun`,
  `deno`, `env`) gets a PENDING tag at exec, its events and its children's flow marked
  `provisional`, and the engine confirms with `TAG` or clears with a cascading `UNTAG`.
  Closes the window completely, but:
  - every interpreter on the host (editor servers, language servers, cron jobs) streams
    events until the engine untags it;
  - `UNTAG` must cascade to children forked in the meantime;
  - the provisional event volume competes with real agent events for the ring buffer
    (SE-5).
  Not adopted now; recorded as the fallback.
- **(b) In-kernel argv substring match** against a small pattern map. Closes the window
  without extra events, but a bounded substring search over 512 bytes of argv times N
  patterns runs straight into the verifier complexity limit hit in M0 (worklog section 4).
  Not adopted.
- **No adoption; document "start AgentEDR first".** This leaves the sensor-restart case
  permanently blind. Rejected.

## Consequences

- Restarting the sensor or the engine no longer silently ends coverage of running agents.
- Adopted sessions are honest about missing history.
- One `/proc` scan per (re)start: a few thousand small file reads, done once, off the event
  path (`asyncio.to_thread`).
- Sessions gain `adopted`, `observed_from`, `continues` and `tag_latency_ms` (SPEC 9.5, 13).

## Kernel-version notes

- `/proc/<pid>/task/<tid>/children` needs `CONFIG_PROC_CHILDREN`, which is set on Ubuntu
  22.04 and 24.04 (**VERIFY** in M1a, and have `doctor` check for the file). The kernel
  documents it as not reliable for a group whose members are not frozen. The walk is
  best-effort, which is acceptable because new children of a tagged process are tagged by
  the fork hook once the parent is tagged.

## Tests

- Unit: matching on exe basename, argv[0] basename and cmdline; topmost-ancestor selection;
  `continues` linking.
- Protocol: `TAG` of an already-tagged tgid returns ok with `note`.
- Integration: an agent started before the engine is adopted with its existing children;
  the agent survives a sensor restart and its new session has `continues`; the argv race
  test.
