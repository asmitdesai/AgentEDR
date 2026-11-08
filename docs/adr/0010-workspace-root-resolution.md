# ADR 0010: Workspace root resolution and degraded mode

Status: Accepted (2026-11-07)
Milestone: M1a
Related: review SE-11, open decision 2; SPEC 9.6, 10, 11.4, 11.5

## Context

Rules decide "inside the workspace" (normal) versus "outside" (suspicious) against the
session's workspace root. The current default is the root process's working directory at
session start (`root_cwd`). Two failure modes:

- An agent launched from a subdirectory under-covers the project.
- An agent launched from `$HOME` (common) makes everything under `$HOME` "inside the
  workspace". AEDR-001 then never fires for `~/.aws/credentials`, silently.

`git_root` alone has the same problem when `$HOME` is itself a git repository (dotfiles
repos). Agents can also be granted extra directories on the command line (Claude Code
`--add-dir`).

## Decision

1. **Default `engine.workspace_root: git_root`** (open decision 2). Start from the root
   process's cwd (`/proc/<root>/cwd` at session start or adoption). Walk up to the nearest
   directory containing `.git`, which may be a directory or a file (worktrees and
   submodules). If none is found, fall back to the cwd.
2. **Extra roots.** Each agent config entry may list `extra_root_flags` (for example
   `["--add-dir"]`) and `cwd_flags` (flags that set the working directory, for example
   Codex `-C`/`--cd`; **VERIFY**). The engine parses the root argv for these:
   - extra roots are added to the session's workspace roots;
   - a cwd flag replaces the starting directory for step 1.
   Flag names are verified per agent in M1a and recorded in `docs/compatibility.md`.
3. **Degraded mode.** A resolved root (main or extra) is too broad if any of these hold:
   - it is `/`, `/home`, `/root`, `/tmp`, `/var/tmp`, or the session user's home;
   - it is an ancestor of the session user's home;
   - it has fewer than two path components below `/`, except for directories under the
     user's home.
   A too-broad main root sets `workspace_root_degraded=true` on the session; a too-broad
   extra root is dropped and recorded. Both are logged at WARNING and shown in `status`,
   `sessions` and `replay`.
4. **Credential files are never "in the workspace"**, regardless of mode, with one
   exception: project `.env` and `.env.*` files under a non-degraded workspace root. In
   degraded mode, the `.env` exception also does not apply. AEDR-001 implements this through
   an enrichment field `in_workspace_for_credentials` used instead of a plain `not_under`.
5. `in_workspace` (the general field) keeps its meaning for non-credential rules. In degraded
   mode it is false for every path under `$HOME` outside the cwd's own git root, if one
   exists.

## Alternatives considered

- **Keep `root_cwd`.** Simple, and wrong in the most common launch case. Rejected.
- **Ask the user to configure workspaces.** Adds setup friction and still fails silently when
  they forget. Rejected as the default; per-path configuration may come later in root-owned
  config (ADR 0013).

## Consequences

- Launching from `$HOME` no longer disables AEDR-001; the session is visibly marked
  degraded.
- The share of degraded sessions is a product metric (PM-7).
- Agents add flags over time; `extra_root_flags` and `cwd_flags` are config, not code, so
  users can update them without a release.

## Kernel-version notes

None.

## Tests

- Unit: git root discovery with `.git` as a directory and as a file; fallback; every
  degraded rule; `--add-dir` parsing with `--add-dir=x` and `--add-dir x` forms; an extra
  root of `$HOME` is dropped.
- Golden AEDR-001: a session rooted at `$HOME` reading `~/.aws/credentials` alerts and is
  marked degraded; a workspace `.env` read in a normal session does not alert.
