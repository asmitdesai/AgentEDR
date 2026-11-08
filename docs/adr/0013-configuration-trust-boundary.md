# ADR 0013: Configuration trust boundary

Status: Accepted (2026-11-07)
Milestone: M1a
Related: configuration read from user-writable paths would let the agent weaken the policy; SPEC 2, 5, 10, 11.1, 15

## Context

The attacker controls the repository and any text the agent reads, and the agent runs as
the user. Anything AgentEDR reads as policy (config, rules, lists, allowlists, suppressions)
from a path the user can write is under attacker control: one injected write could disable a
rule or allowlist an exfiltration host.

Today the engine reads only the packaged defaults, `/etc/agentedr/config.yaml` and an
explicit `--config` path, so nothing is violated yet. But nothing checks ownership or mode,
and later features (rule directories, suppressions, per-project exceptions) would make the
mistake easy.

## Decision

1. **Invariant (SPEC 2.6):** AgentEDR never reads policy, allowlists, suppressions, lists or
   rule files from a session workspace, from any user's home directory, or from any path
   writable by a non-root user.
2. **Allowed sources:**
   - packaged data inside the root-owned install (integrity covered by ADR 0011);
   - `/etc/agentedr/config.yaml`;
   - `/etc/agentedr/rules.d/*.yaml` and other `rules.extra_dirs`;
   - suppressions under `/var/lib/agentedr/` (M2);
   - an explicit `--config PATH`.
3. **Check.** Every policy file, and every directory from it up to `/`, must be root-owned
   and not writable by group or other, or loading fails with an error naming the path. This
   applies to `--config` too: an operator running under `sudo` with `--config ~/x.yaml` is
   refused, with a message saying how to fix it.
4. **Watched, not read.** Agent `config_paths` such as `{workspace}/.claude/settings.json`
   are patterns for rules to match against events. AgentEDR never opens them. The code
   comment on `config_paths` says so.
5. **Per-project exceptions,** if added later, live in root-owned config and are keyed by
   absolute path.
6. **Dev mode.** `--allow-unsafe-install` (ADR 0011) also relaxes the ownership check for
   the packaged defaults inside a dev checkout, but not for `/etc` files or `--config`.

## Alternatives considered

- **Warn instead of refuse.** Warnings scroll by; a silently weakened policy is the attack.
  Rejected.
- **Hash-pin config files.** Adds operator burden without protecting against a root-owned
  but world-writable file that is changed before startup. Ownership and mode checks are
  sufficient. Rejected.

## Consequences

- Operators must keep `/etc/agentedr` root-owned. The default install does this.
- Loading config becomes a privileged-path operation; `doctor` reports violations without
  needing root.

## Kernel-version notes

None.

## Tests

- Unit, with an injected stat: every refusal case (user-owned file, group-writable file,
  writable parent, user-owned `--config`).
- Invariant test: during `load_config` and rule loading, patch the file-opening functions
  and assert that every opened path is under the packaged data directory, `/etc/agentedr`, a
  configured `extra_dirs` entry or the explicit `--config` path, and never under a home
  directory or a session workspace.
- Source test: `config_paths` values are never passed to a file-opening function.
