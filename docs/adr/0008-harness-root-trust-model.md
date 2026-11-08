# ADR 0008: The harness root process is not trusted

Status: Accepted (2026-11-07)
Milestone: M1a (rule fields and lists); M2 (egress rules)
Related: review NEW-6, SE-7d, SE-9, open decision 7; SPEC 9.6, 11.5

## Context

Several tuning ideas assume the agent harness process (the session root) is benign and its
children are where hijacked behaviour shows up:

- "exclude writes by the agent root process" (open decision 7, AEDR-003 note);
- "exclude the harness root" when it reads its own credential store (SE-9);
- "root egress is normal web fetch and model API, child egress is suspicious" (SE-7).

That assumption is wrong for current agents:

- Claude Code's built-in file tools (Read, Write, Edit) and its web fetch run inside the
  harness process, not in a child. An injected "read `~/.aws/credentials`" carried out with
  the Read tool shows up as a FILE_OPEN by the root tgid.
- With Claude Code's sandbox enabled, children's network access goes through a proxy
  (Claude Code sandboxing docs), so child egress may appear as a connection to a local proxy
  or Unix socket, with the real destination contacted by another process.
- Remote MCP servers are contacted by the harness process; MCP tool arguments are an
  exfiltration channel.

Exempting the root would exempt the main path of an injected agent.

## Decision

1. No rule exempts the session root as a blanket condition.
2. The enrichment field `process.is_root` (event tgid == session root tgid) is available to
   rules as a signal, for example to raise severity for child behaviour or to describe the
   actor in alerts. It is never an implicit allow.
3. Narrow exemptions live in a per-agent list `harness_managed_paths` in the agent config
   (SPEC 10). Each entry is a `(path glob, operation)` pair that the harness root performs
   in normal use. Examples, to be measured in M1a and M2:
   - the agent's own state file (likely `~/.claude.json`);
   - its auto-memory directory;
   - its own credential store, for reads.
   Exemptions apply only when the actor is the root. The same operation by a child process
   is not exempt.
4. Exemptions are never allowed for permission settings, hook definitions, MCP server
   configuration or global instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
   commands, skills, agents). `rules lint` rejects a `harness_managed_paths` entry that
   overlaps those.
5. Credential stores of agents:
   - the root reading its own store is expected (exempt via `harness_managed_paths`);
   - a child reading it alerts;
   - any process reading *another* agent's store alerts.
6. Egress (M2): root and child egress are both evaluated. Each agent kind lists its expected
   model API destinations (`api.anthropic.com` for Claude Code, and so on) as an allowlist
   that applies to the root only. Child connections to a local proxy or a Unix socket are
   recorded with the socket path (ADR 0006, M1a `sun_path` capture). If a session is found
   to route child egress through a harness proxy, the session gets `egress_via_proxy=true`,
   and alerts state that destination attribution is degraded.
7. M1a verification task: for Claude Code (sandbox on and off), Codex CLI and Gemini CLI,
   record which process performs file reads, file writes, web fetches and shell commands, and
   what child egress looks like with the sandbox on. Results go in `docs/compatibility.md`.

## Alternatives considered

- **Exempt the root and rely on child behaviour.** Simple and low-noise, but blind to the
  primary attack path. Rejected.
- **Use harness hooks to learn which tool call caused a root action.** That is the hook
  bridge (post-v0.1). It would allow better attribution later, but does not change this
  default.

## Consequences

- More root activity is evaluated, which makes false-positive control depend on the
  expected-consumer model (ADR 0009) and measured `harness_managed_paths`.
- Open decision 7 is resolved: no blanket exclusion, narrow per-path exclusions only.
- Alerts can say "the agent itself did this" versus "a command the agent ran did this", which
  helps triage.

## Kernel-version notes

None. This is an engine and rule decision.

## Tests

- Unit: `rules lint` rejects `harness_managed_paths` entries overlapping protected paths.
- Golden: the root reading `~/.aws/credentials` alerts (AEDR-001 TP with `pid == root`); the
  root writing its own state file does not alert (near-miss); a child writing the same state
  file alerts.
