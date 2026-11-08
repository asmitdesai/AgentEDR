# ADR 0012: Safe output paths

Status: Accepted (2026-11-07)
Milestone: M1a (before any output code lands)
Related: review SA-1, NEW-9, decision N4; SPEC 5, 9.1, 10, 13, 15

## Context

The engine runs as root and writes alerts, events, the SQLite store, the daemon log and
optional raw recordings. Two risks:

- **Root writes through attacker-placed links.** If any directory on an output path is
  writable by the user, the user (or the agent) can pre-create `alerts.jsonl` as a symlink
  or hardlink to a system file, and the root engine will append to or truncate that file.
- **`--dev` writes into the agent's workspace.** `--dev` uses `./.agentedr/`, relative to the
  current directory. Run from a repository, alerts and events land where the agent can read,
  delete or `git add` them, and possibly push them to a remote.

## Decision

1. **Directories.** The output directory, the database directory and the raw recording
   directory are created with mode 0700, root:root, or 0750 root:agentedr when group read is
   enabled (decision N4, opt-in). After creating, or when the directory already exists, the
   engine checks:
   - `lstat` shows a real directory, not a symlink;
   - owner is root;
   - no group or other write;
   - every parent up to `/` is root-owned and not writable by group or other, except
     sticky directories (`/tmp`, `/var/tmp`).
   Any mismatch is a hard error naming the path. The engine never repairs ownership of a
   directory it did not create.
2. **Files.** Every output file is opened relative to an `O_DIRECTORY | O_NOFOLLOW` fd of
   its verified directory with `O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC` and
   mode 0600 (0640 with group read). After opening, `fstat` must show:
   - a regular file owned by root;
   - `st_nlink == 1` (defeats pre-placed hardlinks);
   - the expected mode (fixed with `fchmod` only if the file was just created).
3. **Rotation** renames within the directory fd (`os.rename` with `src_dir_fd` and
   `dst_dir_fd`) and reopens with the same checks.
4. **SQLite** cannot take an fd. The database file is checked with `lstat` (regular file,
   root, `nlink == 1`) before `sqlite3.connect`. Its WAL and SHM sidecar files live in the
   same verified directory, which no other user can write.
5. **`--dev` location.** `--dev` writes to `/var/tmp/agentedr-dev/` (root:root, 0700),
   created and checked with the rules above. A pre-existing `/var/tmp/agentedr-dev` that is
   not root-owned is refused. `./.agentedr/` is no longer used.
6. **Raw recordings** (`--record PATH`) follow the same file rules. The directory must
   satisfy the directory rules, which keeps raw streams out of user-writable locations.
   Redaction of recordings is ADR 0021.
7. All of this lives in one small module (`safefs.py`). Output, store and recording code may
   not call `open()` on output paths directly; a test enforces this by searching the
   source.

## Alternatives considered

- **Drop privileges before writing.** The engine still needs a location the agent cannot
  write; that is the same problem. Rejected.
- **Keep `./.agentedr/` for `--dev` and refuse inside git worktrees.** Still writes into
  user-controlled directories. Rejected.

## Consequences

- Viewing dev output needs `sudo`, the same as production.
- `.agentedr/` in `.gitignore` becomes unnecessary; it stays for old checkouts.
- Operators who point `output.dir` at a user-owned directory get a clear startup error.

## Kernel-version notes

None.

## Tests

Unit tests, run as an unprivileged user with an injected owner check:
- a symlink planted at the file path;
- a symlink at the directory;
- a hardlink at the file path (`nlink > 1`);
- a pre-existing directory with the wrong owner or mode;
- a writable parent;
- a rotation with a symlink planted at the rotated name.

Integration (VM, root):
- `--dev` creates `/var/tmp/agentedr-dev` with 0700;
- a user-owned `/var/tmp/agentedr-dev` is refused.

Source test: no direct `open(` on output paths outside `safefs.py`.
