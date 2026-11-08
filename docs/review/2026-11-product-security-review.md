# AgentEDR product and security review (Phase A)

Date: 2026-11-07
Commit reviewed: `main` at `41c665d` (merge of PR #2, README for M0)
Status: approved by the owner on 2026-11-07 with corrections; see section 11.

The first pass was done on the stale branch `m0-skeleton` at `d2c1e78`. `main` at `41c665d`
differs from it only in `README.md` (`git diff --stat d2c1e78 41c665d`: 1 file changed), so
every code, spec, CI and test reference below is unchanged. Items that depend on the README
were rechecked against `41c665d`.

---

## 1. Method

- Read `CLAUDE.md`, `SPEC.md` (v0.3, all 23 sections), `docs/progress.md`, `docs/worklog.md`,
  the README, all of `sensor/` (BPF and userspace), all of `src/agentedr/`, the tests, CI,
  Makefiles and the Lima VM definition.
- Checked each finding from the brief against the source and the spec. Where a claim was about
  kernel behaviour and the M0 sensor could test it, I tested it in the Lima VM
  (Ubuntu 24.04, `6.8.0-142-generic`, aarch64, BPF LSM active). No 5.15 kernel was available,
  so every kernel claim about 5.15 is still **VERIFY**.
- Searched the web for agent CLI flags, competitor features and one kernel behaviour (TCP Fast
  Open). Sources are listed in section 10. Vendor and blog sources are marked as secondary.

Legend for the "Verified" column:

| Value | Meaning |
|---|---|
| yes | Confirmed in the code, the spec, or a test I ran |
| partly | Part of the claim holds; the rest is wrong or overstated (explained) |
| no | The claim is wrong; dropped or rewritten |
| needs-VM | Plausible from kernel knowledge but not yet tested; must be tested before shipping a rule or hook that depends on it |
| design | A proposal, not a factual claim; nothing to verify |

Severity is for security findings only: critical, high, medium, low. Effort: S (under 1 day),
M (1 to 3 days), L (more than 3 days).

---

## 2. Summary

The most important results, in priority order:

1. **The M0 tagging logic has a verified evasion (NEW-1, NEW-2).** A tagged process loses its
   tag if it calls `exec` from a non-main thread, or if its main thread exits while other
   threads keep running. Both are one line of `python3 -c` and both were reproduced on 6.8:
   the commands ran and the sensor emitted no events for them. This is a bug in shipped M0
   code and should be fixed before any M1 work.
2. **Installing as the user and running as root is a privilege escalation (NEW-8).** SPEC G4
   promises `pip install agentedr` or `uv tool install agentedr`. Both put the engine and the
   sensor in paths the user, and so the agent, can write. `sudo agentedr run` then runs
   agent-modifiable code as root. The SHA-256 check in SA-3 does not help, because the code that
   would do the check is itself user-writable. The supported install method must change.
3. **Several MVP rules miss common, non-adversarial behaviour**, not only evasions:
   - AEDR-002 and AEDR-003 match only on open-for-write. `sed -i`, editors and most config
     writers write a temp file and `rename` it over the target, so they never open the target
     for writing (NEW-4).
   - The default kernel path filter drops `/dev/`, which hides `/dev/shm`, a listed staging
     path for AEDR-004 (NEW-5).
   - AEDR-001 will fire on routine work such as `ssh` reading its key during `git push` or `npm`
     reading `~/.npmrc` on every install. The 1 alert per agent-hour target is unreachable
     without a model of which program is expected to read which credential (NEW-7).
4. **The harness root process is not a safe process to exempt (NEW-6).** Claude Code's own
   file and fetch tools run in the root process. With Claude Code's sandbox on, child egress
   also goes through a proxy. Several proposals in the brief (exclude the root from credential
   rules, treat root egress as normal) would therefore exempt exactly the path an injected
   agent takes.
5. **TCP Fast Open bypasses `security_socket_connect` (NEW-3).** Reported on the kernel
   security list in June 2026 and reproduced in the VM on 6.8 with the default sysctl
   (section 5.2). AEDR-005 needs a `sendmsg` hook for TCP as well as UDP.
6. Most of the brief's findings hold. Some are overstated, and one technical detail is wrong
   (section 3).
7. The proposed scope is roughly two to two and a half times the original 28-day plan
   (section 6). I propose a cut line for v0.1.

---

## 3. Corrections to the brief

These items in the brief are wrong or overstated. Each one has been corrected in the tables
below.

| Brief item | Correction |
|---|---|
| Section 2: CI "has no ... permissions" hardening (SA-8) | `permissions: contents: read` is already set (`.github/workflows/ci.yml`). Actions are pinned by tag (`@v4`, `@v6`), not by SHA. Dependabot and a release workflow are missing. |
| SE-3 severity "high" | The race exists (SPEC 6.3, gotcha 12). The SPEC 2.2 adversary controls only text, and that text reaches the agent after a model round trip, seconds after process start. TAG latency is milliseconds. The race only matters if the engine is down or backlogged, and SE-2 adoption covers that case. Downgraded to low. Recommendation in 7.2. |
| SE-4 "`task->start_time`, boot ns" | `task->start_time` is CLOCK_MONOTONIC. The boot-based field that matches `/proc/<pid>/stat` field 22 is `task->start_boottime` (renamed from `real_start_time` in 5.5). Field 22 is in clock ticks (`USER_HZ`), not ns. **VERIFY** on 5.15. Exploitability is also low: pid reuse inside the ms-scale TAG window needs a full pid wrap, and `pid_max` is 4194304 on 64-bit Ubuntu. Downgraded to low. Still cheap and still worth doing for long-session process identity. |
| SE-6 "paths through `/proc/<pid>/root/...`" | Probably not a bypass. `bpf_d_path` renders the opened file's `struct path` (mount + dentry), not the string the caller passed, so an open through the magic link should render the real path. needs-VM. |
| SE-6 "reads through mmap, sendfile and splice" | All three need an fd, and getting an fd needs an open, which `file_open` sees. The only real variant is an fd passed over a Unix socket (`SCM_RIGHTS`) from a process outside the tree. That is exotic, so it is recorded as a limitation only. |
| SE-6 bind mounts | These need root or an unprivileged user namespace. Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor (`kernel.apparmor_restrict_unprivileged_userns`); 22.04 does not. needs-VM on both. |
| SE-7 "root process egress = normal web fetch and model API" | Unsafe as a trust rule. See NEW-6. |
| SE-9 "exclude the harness root" for agent credential stores | Correct only for the agent's *own* store. The root reading *another* agent's store, or anything in `credential_paths`, must still alert (NEW-6). |
| Section 6 "`dns.c`" in the sensor | DNS parsing is logic and belongs in Python under CLAUDE.md. The sensor should ship the first N payload bytes; the engine parses them. |

---

## 4. Findings from the brief

### 4.1 Security engineering (SE)

| ID | Finding | Verified | Evidence | Sev | Effort | Milestone |
|---|---|---|---|---|---|---|
| SE-1 | Process-tree escape (tmux, systemd-run, docker, at, ssh, sockets of existing servers) | yes (by design) | Tags are inherited only on fork: `sensor/bpf/agentedr.bpf.c:220-240`, SPEC 6.3. AF_UNIX captures family only: SPEC 6.4 | high | M (sun_path S, rules M) | sun_path M1a; rules M2 |
| SE-2 | Agents started before AgentEDR, or after a sensor restart, are untracked | yes | No `/proc` scan anywhere in `src/agentedr/`. SPEC 2.5 assumes AgentEDR starts first; SPEC 9.3 says restart loses all tags | high | M | M1a |
| SE-3 | Argv-tagging race between candidate EXEC and TAG | partly | Race is real (SPEC 6.3, 9.4, gotcha 12). Exploitability by the SPEC 2.2 adversary is low (section 3) | low | S (test + metric); L (provisional tags) | M1a test + metric; ADR only for in-kernel options |
| SE-4 | PID reuse on TAG/UNTAG; no start time in the header | partly | `event_hdr` has no start time: `sensor/bpf/events.h:27-37`. Correct field is `start_boottime` (section 3) | low | S | M1a |
| SE-5a | `agent_pids` fixed at 16384 entries; full map is only logged | yes | `sensor/bpf/maps.h:42`; `src/agentedr/supervisor.py:274-275` | high | S | M1a |
| SE-5b | One shared ring buffer; a burst can overflow it before the malicious action | yes | `sensor/bpf/maps.h:54-57` | high | M | M1b |
| SE-5c | System-wide candidate EXECs share the agent ring buffer | yes | `sensor/bpf/agentedr.bpf.c:41-43, 210-216` | medium | S | M1b |
| SE-5d | Per-session in-kernel token bucket | design | Needs a per-session state map and adds verifier complexity | medium | L | M1b, or v0.2 (cut line) |
| SE-6a | Hardlink to a credential file opens under a workspace path | needs-VM | `bpf_d_path` renders the dentry used to open, which is the link name. `fs.protected_hardlinks` does not stop the file's owner | high | M (with watchlist) | M1b |
| SE-6b | `/proc/<pid>/root` bypass | no (likely) | See section 3 | - | - | test only, M1a |
| SE-6c | Bind mounts, chroot, mount namespaces change the rendered path | needs-VM | Overlaps with NEW-13 | medium | M | M1a verify; M1b fix |
| SE-6d | `O_TMPFILE` + `linkat` creates a persistence file without a named write open | needs-VM | Applies to *new* persistence files (autostart, systemd user units). `linkat` cannot replace an existing file. Covered by the `path_link` hook | medium | M | M1b |
| SE-6e | Inode watchlist map | design | Caveat: atomic replace (NEW-4) changes the inode of `~/.bashrc`-type files. Watch the parent directory inode plus name for persistence, and file inodes for credentials. **VERIFY** `(dev, ino)` stability on btrfs subvolumes and overlayfs | high | L | M1b |
| SE-6f | io_uring opens attributed to the right tgid | needs-VM | Since 5.12, io-wq workers are threads of the submitting process (`PF_IO_WORKER`), so the tgid should match | medium | S (test) | M1a test |
| SE-7a | Unconnected UDP `sendto`/`sendmsg` never hits `socket_connect` | yes (kernel semantics) | `security_socket_connect` is called only from `connect(2)` and the io_uring connect path | high | M | M1b |
| SE-7b | DNS exfiltration through `127.0.0.53` is allowed loopback | yes | `allow_loopback: true`: `src/agentedr/data/default_config.yaml:48`. glibc `connect()`s its UDP resolver socket, so per-process query *counts* are already visible as NET_CONNECT to port 53. Query *names* need payload capture from `sendmsg`; reading `msg_iter` across 5.15 (`iov`) and 6.x (`ubuf`/`__iov`) layouts is fiddly CO-RE. **VERIFY** | high | L | M1b capture; M2 rule |
| SE-7c | CDN-fronted allowlist; github.com as an exfiltration channel | yes (design) | SPEC 9.8 already admits CDN churn; SPEC 10 allowlists `github.com`, `api.github.com` | high | M | M2 |
| SE-7d | Distinguish root egress from child egress | partly | Useful as a field, unsafe as a trust rule (NEW-6) | medium | S | M2 |
| SE-8 | AEDR-005 evaded by waiting more than 2 minutes | yes | SPEC 11.5 AEDR-005 `within: 2m` | medium | M | M2 |
| SE-9a | Credential list gaps; `~/.ssh/*.pub` false positives; `~/.aws/config` severity | yes | SPEC 11.4: `~/.ssh/id_*` matches `id_ed25519.pub`. `~/.aws/config` rarely holds secrets but is read by every `aws` command. Recommend moving it to low | medium | S | M1a (lists) |
| SE-9b | Persistence list gaps (git config, ssh config, environment.d, editors, package-manager redirects) | yes | SPEC 11.4. Note: `/etc/ld.so.preload` would be hidden by SPEC 6.5's `/etc/ld.so` kernel filter (NEW-5) | high | S | M1a (lists) |
| SE-9c | New rule: agent instruction persistence (global CLAUDE.md, AGENTS.md, GEMINI.md, commands, skills, hooks) | design | Strong differentiator. Caveat: Claude Code's auto-memory (`~/.claude/projects/*/memory/`) is written by the harness root in normal use, so root writes there are routine. The rule must key on writer and path, not path alone. Hooks in `~/.claude/settings.json` are already AEDR-003 paths | high | M | M1a (global, single-event); workspace variant M2 |
| SE-10a | `bash /tmp/x.sh` and `python /tmp/x.py` evade AEDR-004 | yes | SPEC 11.5: step 2 is `EXEC_CHECK` only | high | M | M2 |
| SE-10b | Fileless exec (`memfd_create` + `fexecve`) | needs-VM | Expect `bprm->filename` = `/dev/fd/N` and `d_path` = `/memfd:<name> (deleted)` | high | S | M2 |
| SE-10c | Pipe-to-shell (AEDR-006); promote | design | Agents usually issue `bash -c "curl ... \| sh"`, so the full pipeline is in argv. An argv heuristic is cheap | high | S-M | M2 |
| SE-10d | Rename into staging | yes | SPEC 11.5 note under AEDR-004 | medium | S | M2 |
| SE-10e (new) | `ld.so /tmp/payload` runs a staged binary without exec'ing it | needs-VM | The dynamic loader is exec'd and maps the payload. Covered by the "interpreter or loader reads a staged file" variant of SE-10a | high | S | M2 |
| SE-11 | `workspace_root: root_cwd` launched from `$HOME` silently disables AEDR-001 | yes | `default_config.yaml:38`; AEDR-001 `not_under: $session.workspace_root`. Also applies to `git_root` when `$HOME` is a dotfiles git repo. `--add-dir` exists (sources 2, 3) | high | M | M1a |
| SE-12a | Promote AEDR-009 (sudo, su, pkexec, doas, setuid exec) | design | Cheap; becomes critical on hosts with passwordless sudo (NEW-10) | high | S | M2 |
| SE-12b | Tamper hooks: `lsm/bpf`, `lsm/task_kill`, writes to AgentEDR paths, ptrace of AgentEDR | design | Ubuntu sets `kernel.unprivileged_bpf_disabled=2`, so `bpf()` from the tree implies root; pair with AEDR-009 | high | M | M1b |
| SE-12c | Heartbeat | partly | The engine sees sensor EOF at once, so the gap is *engine* death, which nobody observes. Proposal: the engine writes a heartbeat timestamp to SQLite; on start it records a "coverage gap" for any session open at the last heartbeat. systemd `Restart=` covers the rest | high | S | M1a |
| SE-13 | Long-lived detached descendants | yes | Tags already survive root exit (fork inheritance), so the data exists. Session lifecycle does not handle it (NEW-12) | medium | M | M2 |
| SE-14 | `unsupervised` flag from root argv | partly | Flags confirmed (sources 2-6): Claude Code `--dangerously-skip-permissions` and `--permission-mode bypassPermissions`; Codex `--dangerously-bypass-approvals-and-sandbox` (alias `--yolo`); Gemini `--approval-mode=yolo` (`--yolo` deprecated). The mode can also come from settings files and can be toggled at runtime (Claude shift+tab, Gemini Ctrl+Y), so argv alone gives "yes" or "unknown", never a reliable "no". Read settings files at session start as a second signal. Cursor flags still **VERIFY** | medium | S | M1a |
| SE-15 | Honeytoken canaries | design | Caveat: decoys at decoy paths catch broad sweeps (`cat ~/.ssh/*`, `grep -r AKIA ~`), not targeted reads of the real path. Never modify real credential files. Canary content must not look like real key formats (agree) | high | M | M2 |
| SE-16 | Redaction coverage, raw recording, property tests | yes | SPEC 9.7 misses `sk_live_`, Slack, Google, JWT, npm, GitLab, Vault and `-p<pw>`/`--password=`. `record_raw` exists with no mode rule: `default_config.yaml:61`. Also NEW-15 | medium | M | M1a |

### 4.2 Security architecture (SA)

| ID | Finding | Verified | Evidence | Sev | Effort | Milestone |
|---|---|---|---|---|---|---|
| SA-1 | Root-owned writes into user-controlled paths (symlink clobber) | partly | No output code exists yet, so nothing is exploitable today. `DEV_DIR = Path(".agentedr")` is relative to the current directory: `src/agentedr/config.py:19, 201-204`. The risk becomes real in M1a. Extended by NEW-9 | high | M | M1a (before outputs land) |
| SA-2 | Never read config or policy from the workspace or user-writable paths | partly | No violation today: config comes from `/etc/agentedr/config.yaml` or `--config` (`config.py:186-200`). There is no ownership or mode check on `/etc/agentedr/config.yaml` or on `rules.extra_dirs` | high | S | M1a |
| SA-3 | Sensor binary integrity check | yes | `locate_sensor` checks only `is_file` and `X_OK`: `src/agentedr/supervisor.py:53-59`. Insufficient without NEW-8 | high | S | M1a, with NEW-8 |
| SA-4a | Protocol version in READY; engine refuses incompatible sensors | yes | READY `version` is logged and ignored: `supervisor.py:135-138`. Worse today: `extra="forbid"` (`src/agentedr/models.py:16`) turns version skew into silent per-line "malformed" drops (NEW-14) | medium | S | M1a |
| SA-4b | `schema_version` on stored events | design | SPEC 13 has `meta.schema_version` for the DB only | low | S | M1a |
| SA-4c | Fuzz `protocol.c`, `json.c` (libFuzzer) and the decoder (Hypothesis) | design | `protocol_handle_line` takes the skeleton pointer; a small refactor separates parsing from map updates. Hypothesis is a new dev dependency and needs approval | medium | M | M1b |
| SA-5 | Least privilege, systemd hardening, MDWE, privilege-split ADR | design | SPEC 15 lists the capabilities. **VERIFY** that `MemoryDenyWriteExecute` works with CPython plus ctypes/libffi closures; drop it if not | medium | M | M3 (unit), ADR in Phase B |
| SA-6 | Data access model (group vs query socket) | design | See 7.2, decision N4 | medium | M | M2 |
| SA-7 | Licensing of `events.h`/`maps.h` | yes | `SPDX-License-Identifier: GPL-2.0` at `sensor/bpf/events.h:1`, `sensor/bpf/maps.h:1`; both included by Apache-2.0 `sensor/src/main.c:32,37` and `protocol.c:17`. Open question in the worklog | low | S | M0.5 |
| SA-8 | Supply chain: SHA-pinned actions, Dependabot, release workflow, SBOM, provenance, Sigstore, reproducible builds | partly | See section 3. CI installs unpinned `clang` from apt, so builds are not reproducible | medium | M-L | pinning M0.5; release M3 |
| SA-9 | Kernel matrix CI (virtme-ng, LSM and fentry, 5.15 / 6.8 / mainline) | yes | No integration job in `ci.yml`. **VERIFY** KVM availability on GitHub-hosted runners for both architectures | high | L | M1b |

### 4.3 Product (PM)

| ID | Finding | Verified | Evidence / note | Effort | Milestone |
|---|---|---|---|---|---|
| PM-1 | Personas, positioning, sourced comparison | design | Initial search: Tetragon `matchBinaries` with `followChildren` already gives in-kernel tree following (source 1). AgentSight (eunomia-bpf) is an eBPF observability tool for agents using TLS uprobes and process trees (sources 7, 8). Per-session attribution alone is therefore not unique. The differentiator is agent-specific detections plus session semantics plus an honest public benchmark. The full comparison is a Phase C deliverable | M | M3 |
| PM-2a | `doctor` first, no root, copy-pasteable fixes | design | SPEC 14 already lists `doctor`. Must include NEW-10, NEW-17, NEW-18 checks | M | M1a |
| PM-2b | `agentedr demo` | design | Proposal: two variants. `demo --offline` replays a bundled recording through `analyze` with no root and no sensor, so it runs anywhere (even macOS). `demo --live` (root) runs a scripted fake agent against canaries in a temp HOME | M | M1a |
| PM-2c | Automatic fentry fallback and explain the loss | yes | Already automatic: `sensor/src/main.c:319-325`. Missing: telling the user. In fentry mode nothing is lost in monitor mode; only future enforcement needs LSM | S | M1a |
| PM-3 | Actionable alerts, likely injection source, `explain`, incidents | design | Caveat: content fetched by WebFetch or returned by MCP tools never touches disk, so the "likely injection source" will often be unknown. `userspace_path_ignore` drops `/node_modules/`, which is where poisoned dependency READMEs live (NEW-16). Expect a modest hit rate; PM-7 measures it | L | M2 |
| PM-4 | Notifier ADR | design | Caveat: a same-uid agent can eavesdrop on the session bus, so desktop notifications are visible to a hijacked agent. Same trade-off as SA-6 | M | M3 |
| PM-5a | OCSF output | design | No dependencies; mapping only | M | M2 |
| PM-5b | Wazuh integration; Elastic and Splunk docs | design | A `wazuh-logtest` CI test needs a Wazuh install. Recommend docs plus sample lines in M3; test optional | M | M3 |
| PM-5c | Sigma export | design | See 7.1, decision 5 | - | - |
| PM-6 | `suppress`, tuning loop, visible suppressions | design | Writing a root-owned suppression needs root, which is correct | M | M2 |
| PM-7 | Success metrics | design | Add one: share of sessions with `workspace_root_degraded` or `unsupervised` | S | M3 |
| PM-8 | SECURITY.md, CONTRIBUTING.md, evasion corpus with xfails | design | Add NEW-1 to NEW-5 and SE-10e to the evasion corpus | M | M3 (corpus seeded in M1a with the NEW-1/2 regression tests) |

---

## 5. New findings

| ID | Finding | Verified | Evidence | Sev | Effort | Milestone |
|---|---|---|---|---|---|---|
| NEW-1 | Exec from a non-main thread drops the tag | **yes (VM, 6.8)** | Test below | critical | S-M | M0.5 |
| NEW-2 | Main-thread exit with live worker threads drops the tag and emits a false EXIT | **yes (VM, 6.8)** | Test below | critical | same fix | M0.5 |
| NEW-3 | TCP Fast Open (`sendto(MSG_FASTOPEN)`) connects without `security_socket_connect` | **yes (VM, 6.8)**; 5.15 unverified | Sources 9, 10; reproduced in section 5.2 with the default `net.ipv4.tcp_fastopen=1` | high | M (with SE-7a) | M1b |
| NEW-4 | Atomic replace (temp file + rename) bypasses AEDR-002/003 | needs-VM (high confidence) | AEDR-002/003 match FILE_OPEN write/create only (SPEC 11.5). GNU `sed -i` and many editors and config writers create a temp file in the same directory and `rename()` it over the target. Whether each agent's own Write/Edit tool does this is **VERIFY** | high | S (rules), needs `inode_rename` in M1a | M1a |
| NEW-5 | Kernel path filter defaults hide attack-relevant paths | yes | `/dev/` (`default_config.yaml:33`) hides `/dev/shm/*`, which `staging_paths` lists (SPEC 11.4). `/proc/` hides reads of other processes' `/proc/<pid>/environ` (same-uid secret theft). SPEC 6.5's `/etc/ld.so` prefix (absent from the default config, an inconsistency) would hide `/etc/ld.so.preload` | high | S | M1a |
| NEW-6 | The harness root process is the main actor, not a trusted one | partly (needs-VM per agent) | Claude Code's Read/Write/Edit/WebFetch tools run in the harness process, so injected file reads and fetches originate from the root tgid. With Claude Code's sandbox, children's network traffic goes through a proxy (source 11), so child egress may look like root egress or loopback/Unix-socket traffic. Any root exemption (decision 7, SE-9, SE-7d) must be narrow: specific path, specific operation | high | design | ADR, M1a |
| NEW-7 | AEDR-001 has no model of expected consumers and will be noisy | yes (by spec) | `ssh` reads `~/.ssh/id_*` on every `git push` over SSH; `npm` reads `~/.npmrc` on every install; also `aws`, `kubectl`, `docker`, `git-credential-store`. SPEC 11.5 lists these as false positives without a mitigation. Proposal: a list mapping credential path to expected consumer exe (from the EXEC filename), e.g. `/usr/bin/ssh` may read `~/.ssh/id_*` but `scp`, `cat`, `python3`, `node` may not. Consumer identity is path-based, so document the evasion (copy `cat` to `/tmp/ssh`) and catch it with a staged-exec rule | high (noise) | M | M1a list format; M2 tuning |
| NEW-8 | User-writable install run as root = privilege escalation and trivial blinding | yes (by spec and README) | SPEC 1.1 G4 (`pip install`, `uv tool install`) plus SPEC 14 `sudo agentedr run`. The README quickstart runs `sudo .venv/bin/agentedr run --dev` from a user-owned checkout and venv (`README.md:149`), which is the same pattern. `uv tool install` puts the package under `~/.local/share/uv/tools/`, writable by the user and the agent. `sudo` `secure_path` hides `~/.local/bin`, so users will type `sudo $(which agentedr)`, which is exactly the unsafe path. Proposal: the supported install is root-owned (e.g. a system venv under `/opt/agentedr` or `sudo uv tool install` with root-owned `UV_TOOL_DIR`/`UV_TOOL_BIN_DIR`), and at startup the engine refuses to run as root if any path in its own package, its interpreter or the sensor is writable by a non-root user | critical | M | M1a |
| NEW-9 | `--dev` places telemetry inside the agent's workspace | yes | `DEV_DIR` is relative to the current directory (`config.py:19`); the README documents this (`README.md:156`). Run from a repo, alerts and events land where the agent can read, delete or `git add` them (and push them to a remote). Proposal: `--dev` uses `/var/tmp/agentedr-dev/` (root, 0700) or refuses to run inside a git worktree | high | S | M1a |
| NEW-10 | Passwordless or cached sudo voids the "root attacker out of scope" boundary | design | Common on cloud dev VMs and personal machines. `doctor` should detect `NOPASSWD` for the user and say that tamper resistance is void on this host; AEDR-009 then becomes critical | medium | S | M1a (doctor), M2 (rule) |
| NEW-11 | Credential access without any file read | yes (by design) | Environment variables inherited by the agent (`env`, `printenv`), D-Bus Secret Service (`secret-tool`, `git-credential-libsecret`, keyring-backed `gh auth token`), ssh-agent and gpg-agent sockets. The daemons are out of tree. Partial coverage: EXEC rules for known secret-dumping commands, sun_path capture (SE-1), document the rest | medium | S-M | M2 + limitations |
| NEW-12 | Session lifecycle vs lingering kernel tags | yes (by spec) | SPEC 9.5 ends sessions on TTL or all_exited and evicts state after 10 min, but kernel tags of detached descendants persist, so events can arrive for an evicted session. Kernel session ids also restart at 1 after a sensor restart. The engine must reopen or attribute "late" events and never merge ids across sensor runs | medium | M | M1a |
| NEW-13 | Mount namespaces change `bpf_d_path` output | needs-VM | `d_path` is relative to the task's root. Claude Code's bubblewrap sandbox (source 11), devcontainers, snaps and chroot can render paths that do not match `~/...` lists. Mainstream for Claude Code users | medium | M | M1a verify |
| NEW-14 | Engine/sensor version skew fails silently | yes | `extra="forbid"` (`models.py:16`) plus no version check: a newer sensor's events are all counted as malformed, one WARNING per line, and the result is zero detections with no hard error | medium | S | M1a (with SA-4a) |
| NEW-15 | Untagged candidate EXECs carry other users' argv into the engine | yes | Every `node`, `python3`, `env` on the host, including root cron jobs (`agentedr.bpf.c:210-216`), with argv that may contain secrets. These must be dropped after argv matching, never stored, and excluded from `--record` unless explicitly enabled | medium | S | M1a |
| NEW-16 | Userspace ignore of `/node_modules/` removes injection-source evidence | yes | `default_config.yaml:36` vs SPEC 2.2 ("poisoned dependency README"). Keep a small per-session ring of doc-like reads (`*.md`, `README*`) even under ignored paths | low | S | M2 |
| NEW-17 | The BPF LSM fix can weaken the host if done naively | yes (README) | The README says "append `bpf` to the `lsm=` kernel parameter" without saying the full current list must be kept (`README.md:130-132`). `lsm=` replaces the whole list; a user who sets `lsm=bpf` disables AppArmor, Yama and Landlock. `doctor` must print the current list plus `bpf` (as `bench/vm/lima-dev.yaml` does). It should also detect `lockdown=confidentiality`, which blocks `bpf_probe_read_kernel` | medium (harms user) | S | M1a |
| NEW-18 | IDE-embedded agents get silent zero coverage | design | Cursor's in-editor agent, VS Code agent modes and editor-launched agents run commands from an editor extension host with no matching CLI basename. A first-time user sees "no sessions" and concludes the tool is broken. `status` and `doctor` should say "no agent sessions observed" with likely reasons; scope is a new open decision | product | S (messaging) | M1a |
| NEW-19 | Exe-basename matching for native installs | needs-VM | Claude Code's native installer uses `~/.local/bin/claude` (source 2). If the real binary is exec'd by its versioned path (e.g. on self-update relaunch), the basename may not be `claude`. Check during the M0 real-agent test | medium | S | M0.5 |
| NEW-20 | No retention limit on stored telemetry | yes | SPEC 13 has no time-based purge; rotation bounds JSONL only. The SQLite store becomes an unbounded sensitive journal. Add `output.retention_days` (default 14) | low | S | M1a |

### 5.1 Reproduction of NEW-1 and NEW-2

Run in the Lima VM as root with the M0 sensor (`sensor/build/agentedr-sensor-aarch64`) and
`SET_MATCHERS [{"basename":"claude","kind":0}]`. The fake agent `claude` is a copy of
`/bin/bash` and runs:

```
python3 -c "import threading,os; t=threading.Thread(target=lambda: os.execv('/bin/sh', ['sh','-c','/bin/true marker_thread_exec; /bin/true marker_thread_exec_child'])); t.start(); t.join()"
python3 -c "
import threading,os,time,ctypes
def w():
    time.sleep(0.5); os.system('/bin/true marker_after_leader_exit')
threading.Thread(target=w).start()
ctypes.CDLL(None).pthread_exit(None)
"
```

Observed sensor output (abridged):

```
EXEC pid 7153 sess 1 comm python3 python3 -c import threading,os; t=threading.Thread(...)
EXIT pid 7153 sess 1 comm python3
EXEC pid 7157 sess 1 comm python3 python3 -c  import threading,os,time,ctypes ...
EXIT pid 7157 sess 1 comm python3
```

No EXEC event appeared for `sh`, `marker_thread_exec`, `marker_thread_exec_child` or
`marker_after_leader_exit`. A separate run outside the sensor confirmed that both payloads
executed (each wrote a marker file).

Cause:
- `handle_exit` (`agentedr.bpf.c:242-274`) deletes the tag when the thread with
  `pid == tgid` exits.
- In case 1, `de_thread()` during exec kills the old leader first, so the tag is gone before
  `sched_process_exec` fires for the same tgid.
- In case 2, the leader's exit removes the tag while the worker threads keep running.

Fix (ADR 0001, `docs/adr/0001-group-exit-aware-tag-lifetime.md`):
- Remove the `pid != tgid` early return in `handle_exit`. When the main thread exits first,
  the last thread to die is a worker (`pid != tgid`).
- Act on whichever thread observes `p->signal->live == 0`, and key the tag by tgid.
- Report `signal->group_exit_code` when `SIGNAL_GROUP_EXIT` is set in `signal->flags`, else
  the dying thread's `exit_code`.
- `is_root` follows the same rule.
- Both cases, plus a main-first/worker-last case, become permanent integration tests and the
  first entries in `bench/evasions/`.

Ordering check on 6.8: a throwaway BPF program on `tp_btf/sched_process_exit` printed
`signal->live`, `signal->flags`, `signal->group_exit_code` and `exit_code` for marked tasks:

| Case | Thread | pid / tgid | live | flags | group_exit_code | exit_code |
|---|---|---|---|---|---|---|
| single thread, `sys.exit(3)` | main | 1926 / 1926 | 0 | 0x4 | 768 | 768 |
| main `pthread_exit`, worker returns | main | 1929 / 1929 | 1 | 0x0 | 0 | 0 |
| | worker (last) | 1930 / 1929 | 0 | 0x4 | 0 | 0 |
| main `pthread_exit`, worker `os._exit(5)` | main | 1933 / 1933 | 1 | 0x0 | 0 | 0 |
| | worker (last) | 1934 / 1933 | 0 | 0x4 | 1280 | 1280 |
| exec from a worker thread | old main | 1937 / 1937 | 1 | 0x0 | 0 | 0 |

Conclusions:
- On 6.8, `signal->live` is decremented before `trace_sched_process_exit`: a single-threaded
  exit already sees 0.
- The last thread to exit sees `live == 0`, whether or not it is the main thread.
- In the exec-from-thread case, the old main thread exits with `live == 1`, so the fix keeps
  the tag and the process continues tagged after `exec`.
- `group_exit_code` uses the same wait-status encoding as `exit_code` (768 = 3 << 8,
  1280 = 5 << 8), so the existing shell-convention decoding applies unchanged.
- When the last thread simply returns, glibc ends the process with `exit_group`, so
  `SIGNAL_GROUP_EXIT` is set with code 0.

5.15 is still unverified.

### 5.2 Reproduction of NEW-3

Same throwaway program, with `lsm/socket_connect`, `fentry/security_socket_connect` and
`lsm/socket_sendmsg` attached. A marked client process talks to a local Python listener with
`TCP_FASTOPEN` set on 127.0.0.1. VM kernel 6.8, `net.ipv4.tcp_fastopen=1` (Ubuntu default)
unless stated; the sysctl was restored afterwards.

| Case | Data delivered | `lsm/socket_connect` | `fentry/security_socket_connect` | `lsm/socket_sendmsg` |
|---|---|---|---|---|
| control: `connect()` + `send()` | yes | fired | fired | fired, flags 0x0 |
| `sendto(MSG_FASTOPEN)`, sysctl 1 | yes | **not fired** | **not fired** | fired, flags 0x20000000 |
| `sendto(MSG_FASTOPEN)`, sysctl 3, no cookie | yes | **not fired** | **not fired** | fired, flags 0x20000000 |
| `sendto(MSG_FASTOPEN)`, sysctl 3, cookie cached | yes | **not fired** | **not fired** | fired, flags 0x20000000 |

Conclusions:
- TCP Fast Open connects and delivers data without calling `security_socket_connect`, with
  the default sysctl and whether or not the server returns a cookie. Both LSM and fentry
  modes are blind to it.
- `security_socket_sendmsg` fires with `MSG_FASTOPEN` (0x20000000), so a `socket_sendmsg`
  hook that treats `MSG_FASTOPEN` on a TCP socket as a connect closes the gap (ADR 0006,
  M1b).

5.15 is still unverified.

---

## 6. Proposed milestone re-cut

Estimates are working days for one developer using an AI assistant, based on M0 pace. The
original M0 to M3 plan was 28 days. This plan is about 60, so a cut line follows the table.

| Milestone | Contents | Estimate |
|---|---|---|
| **M0.5 - Fix and close M0** | NEW-1/NEW-2 fix and regression tests; real `claude` session check (also covers NEW-19); green CI; actions pinned by SHA plus Dependabot (SA-8 part); header licensing decision (SA-7); size-budget decision | 2-3 |
| **M1a - Minimal honest vertical slice** | BPF: `file_open`, `bprm_check`, `socket_connect` (with AF_UNIX `sun_path`, incl. abstract names), `inode_rename` (moved up for NEW-4), LSM and fentry variants. `start_boottime` in the header (SE-4); `protocol_version` in READY (SA-4a, NEW-14); fixed path filter defaults (NEW-5); `agent_pids` size from config (SE-5a); TAG/UNTAG with `/proc` walk; SET_PATH_FILTER. Engine: tagger, `/proc` adoption (SE-2), session tracker including lingering tags (NEW-12), enrichment, workspace safeguards (SE-11), `unsupervised` (SE-14), redaction (SE-16, NEW-15), safe outputs (SA-1, NEW-9), install self-check and sensor hash (NEW-8, SA-3), config trust checks (SA-2), SQLite with retention (NEW-20), heartbeat and coverage gaps (SE-12c), blind-spot records for map-full and drops (SE-5a), restart policy. Rules: single-event engine and lists only, AEDR-001 (with expected-consumer list, NEW-7), AEDR-002 and AEDR-003 (including rename, NEW-4), global agent-instruction persistence (SE-9c). CLI: `doctor` (NEW-10, NEW-17, NEW-18), `status`, `sessions`, `replay`, `demo --offline`, `demo --live`. Tests: race test (SE-3), io_uring and `/proc/<pid>/root` checks, mount namespace check (NEW-13) | 16-20 |
| **M1b - Telemetry breadth and tamper** | `inode_unlink`, `ptrace`, `path_link`/`inode_symlink`, `socket_sendmsg` (UDP plus TCP `MSG_FASTOPEN`, NEW-3), DNS payload bytes, `lsm/bpf`, `lsm/task_kill`, writes to AgentEDR paths; inode watchlist (SE-6e); split ring buffers and a separate candidate buffer (SE-5b, SE-5c); token bucket (SE-5d, cut-line candidate); fuzzing (SA-4c); aarch64 CI; virtme-ng kernel matrix (SA-9) | 12-15 |
| **M2 - Detections** | Sequence engine with captures and the session taint model (SE-8); egress with DNS attribution (SE-7); AEDR-004 extended (SE-10a to e); AEDR-005; AEDR-006 argv heuristic; AEDR-009 (SE-12a); process-tree escape rules (SE-1); detached descendants (SE-13); non-file credential access (NEW-11); canaries (SE-15); incidents, likely injection source, `explain` (PM-3, NEW-16); `suppress` (PM-6); OCSF (PM-5a); data access model (SA-6) | 14-16 |
| **M3 - Benchmark and release** | Attack, benign and evasion corpora (PM-8); overhead; micro-benchmark gate; root-owned packaging and install docs (NEW-8); release workflow with SHA256SUMS, SBOM, provenance, Sigstore, PyPI trusted publishing (SA-8); systemd unit (SA-5); notifier (PM-4); `docs/product.md` with sourced comparison (PM-1), compat matrix, limitations, SECURITY.md, CONTRIBUTING.md; Wazuh docs and samples (PM-5b) | 12-15 |

**Cut line option for v0.1** (about 12 days less). Move to v0.2:
- SE-5d token bucket
- DNS payload capture (keep per-process port-53 counts)
- inode watchlist and link hooks (keep a hardlink xfail in the evasion corpus)
- canaries
- OCSF
- notifier
- Wazuh

Keep:
- every critical and high item that a shell one-liner can trigger
- NEW-8, because v0.1 must not ship a privilege escalation

**Sensor size budget.** M0 userspace is already 672 non-blank, non-comment lines (`main.c` 346,
`protocol.c` 152, `json.c` 149, headers 25). Rough additions:
- TAG/UNTAG plus `/proc` walk: about 120
- start-time check: about 30
- path filter: about 40
- serializers for new events: about 150
- watchlist and second ring buffer: about 80

Proposal:
- Userspace: about 1200 lines, split as `main.c` (setup, loop), `protocol.c` (commands),
  `json.c` (writer), `proc_walk.c` (TAG descendants, start-time check) and `events_out.c`
  (per-event serializers). No file over about 400 lines.
- BPF: about 1400 lines (SPEC says 800), split by hook family into headers included by
  `agentedr.bpf.c`, with the LSM and fentry variants sharing `__always_inline` bodies.

---

## 7. Decisions for the owner

### 7.1 SPEC section 22 open decisions

| # | Decision | Recommendation | Reasoning |
|---|---|---|---|
| 1 | Containerized agents in v1 | No for agents running inside containers. Yes for detecting an agent tree that *launches* containers (SE-1 rule on `docker.sock`). Add `cgroup_id` to the event header now | Inside-container coverage needs pid-namespace and cgroup-aware sessions (L). The escape rule is cheap and closes the bigger hole. `bpf_get_current_cgroup_id()` costs 8 bytes and makes v0.2 easier |
| 2 | Workspace root | `git_root` with fallback to `root_cwd`, plus `--add-dir` roots, plus degraded mode when the result is `$HOME`, `/` or another broad directory (SE-11) | `root_cwd` from a subdirectory under-covers; `$HOME` silently disables AEDR-001. Degraded mode must apply after git-root resolution because of dotfiles repos |
| 3 | Egress default | Keep the strict list, used only by AEDR-005 and the taint model. Never alert on egress alone | Untainted egress is the agent's normal job; alerting on it breaks the FP target |
| 4 | Event retention | `retained` (all tagged events of the session) plus `retention_days` (NEW-20) and a per-session cap | `replay` and injection-source attribution need the full session. Unlimited retention is a liability |
| 5 | Sigma export | No for v0.2 | MVP rules are session-scoped sequences with captures; Sigma correlation rules do not express per-session state. Revisit for single-event rules after v0.2 |
| 6 | Name | Keep until M3; do a name search before tagging v0.1.0 | Does not block engineering |
| 7 | AEDR-003 root exclusion | No blanket exclusion. Narrow per-path exclusions only for harness-managed state files (likely `~/.claude.json`), measured in M2. Never for permission, hook or MCP settings | NEW-6: the root is where injected edits happen. Consider moving `~/.claude.json` from AEDR-003 to an info-level rule if it is pure state |
| 8 | Threshold rule type | No in v1 | No MVP rule needs it; AEDR-011 is post-v0.1 |

### 7.2 New decisions raised by this review

| # | Decision | Recommendation | Reasoning |
|---|---|---|---|
| N1 | Supported install method (NEW-8) | Root-owned venv (e.g. `/opt/agentedr`) created by a documented one-liner, plus the startup self-check. Rewrite G4 as "one command, no compilers or headers" without naming user-level `pip`/`uv tool` | User-level installs cannot be made safe while the engine runs as root |
| N2 | Where NEW-1/2 is fixed | M0.5 patch before M1a | It is a bug in shipped tagging logic, and every later rule depends on tags |
| N3 | SE-3 approach | Neither (a) nor (b) now. Ship the race test, a TAG-latency metric, and SE-2 adoption. The ADR records (a) provisional tags as the fallback if measured latency is bad | (a) puts every `node`/`python3` on the host into the event stream until UNTAG, which is costly and noisy. (b) bounded in-kernel substring search over 512 bytes of argv times N patterns runs into the verifier complexity limits already hit in M0. The exploitability is low (section 3) |
| N4 | Data access model (SA-6) | An `agentedr` group with read access to a redacted `alerts.jsonl` only; events and DB stay root-only; the user opts in with `usermod -aG` | The user and the agent share a uid, so anything the user can read without a password, the agent can read. Alerts are the least sensitive data and the most useful to the user. A query socket has the same exposure with more code |
| N5 | Header licensing (SA-7) | `GPL-2.0-only OR BSD-2-Clause` for `events.h` and `maps.h` | Common libbpf practice; lets Apache-2.0 userspace include them. The owner is the sole author, so relicensing is the owner's call. I will not change headers without approval |
| N6 | Sensor size budgets | Userspace about 1200, BPF about 1400, file split as in section 6 | See section 6 |
| N7 | IDE-embedded agents (NEW-18) | Out of scope for v0.1; say so in the README and in `doctor`/`status` output | Matching editor extension hosts would tag the whole editor and every terminal in it |
| N8 | Claude Code sandbox mode (NEW-6, NEW-13) | Supported and tested in M1a, since it is mainstream | If it breaks path matching or egress attribution, users will hit it first |
| N9 | Dev dependencies | Approve `hypothesis` (dev only) for decoder and redaction property tests. libFuzzer comes with clang; nothing new | CLAUDE.md requires approval for any added library |
| N10 | v0.1 scope | Adopt the cut line in section 6 | Keeps v0.1 near 50 days instead of 60 without dropping any one-liner evasion fix |

---

## 8. Proposed ADRs

| ADR | Title | Summary |
|---|---|---|
| 0001 | Group-exit-aware tag lifetime | Delete tags and emit EXIT only when the thread group is dead; fixes NEW-1, NEW-2 |
| 0002 | Process identity | `(pid, start_boottime)` everywhere; TAG carries the start time and the sensor checks it against `/proc` field 22 |
| 0003 | Session adoption and argv-tag race | `/proc` adoption at startup and after restart; `adopted=true`; options (a) and (b) for SE-3 recorded, neither adopted yet |
| 0004 | Blind spots and tamper signals | Map-full, drops, coverage gaps and sensor/engine death as session-attached signals; ring buffer split; map sizing |
| 0005 | File identity beyond paths | Rename and link coverage for AEDR-002/003, inode watchlist (directory inode + name for persistence), basis for future enforcement |
| 0006 | Network telemetry beyond connect | `sendmsg` for UDP and TCP Fast Open, AF_UNIX paths, DNS payload bytes parsed in Python |
| 0007 | Session taint model | Session-wide taint with decaying severity; 2-minute sequence kept as the critical fast path |
| 0008 | Trust model of the harness root | Root is not exempt by default; narrow per-path exemptions; root vs child as a rule field only |
| 0009 | Credential consumer model | Credential path to expected consumer exe mapping for AEDR-001; documented evasion and the compensating rule |
| 0010 | Workspace root resolution | `git_root` with fallback, `--add-dir`, degraded mode |
| 0011 | Install and execution integrity | Root-owned install, self-check of package and sensor writability, sensor SHA-256 |
| 0012 | Safe output paths | `O_NOFOLLOW`, owner and mode checks, `--dev` location outside the workspace |
| 0013 | Configuration trust boundary | Config, rules and suppressions only from root-owned, non-user-writable paths; enforced by test |
| 0014 | Protocol and schema versioning | `protocol_version` in READY, hard refusal on mismatch, `schema_version` on stored events |
| 0015 | Data access and notification | `agentedr` group read of redacted alerts; notifier off by default; same-uid exposure stated |
| 0016 | Privilege split (design only) | Sensor keeps capabilities, engine unprivileged; what breaks and how to fix it |
| 0017 | Shared header licensing | Dual license for `events.h` and `maps.h` |
| 0018 | Release supply chain | SHA-pinned actions, Dependabot, reproducible sensor builds, SBOM, provenance, Sigstore, trusted publishing |
| 0019 | Kernel test matrix | virtme-ng on 5.15, 6.8 and mainline, LSM and fentry modes |
| 0020 | Deception canaries | Planting, inode registration, content rules, scanner-safe format |
| 0021 | Redaction and raw recording policy | Pattern set, idempotence, stderr and raw stream handling, untagged EXEC privacy |
| 0022 | Output formats | OCSF mapping; Sigma deferred |
| 0023 | Sensor size budget and file layout | New budgets and file split |

---

## 9. Questions for the owner

1. Approve fixing NEW-1/NEW-2 as an M0.5 patch before M1a (N2)?
2. Which install method should replace G4's wording (N1)? This changes the README promise.
3. Approve the milestone re-cut, and the v0.1 cut line or the full scope (N10)?
4. Decisions 1 to 8 in 7.1: accept, change or defer each.
5. New decisions N3 to N9: accept, change or defer each.
6. Which ADRs to write in Phase B? I suggest 0001, 0002, 0005, 0008, 0009, 0011 and 0012
   first, since M1a depends on them; the rest can follow per milestone.
7. The real `claude` check still needs Claude Code installed and logged in inside the VM.
   Can you do that, so M0.5 can close M0 and test NEW-19?

---

## 10. Sources

Web sources were used for agent flags, competitor features and one kernel behaviour. Several
are secondary (blogs, vendor pages); official documentation should be rechecked before
anything ships in `docs/compatibility.md`.

1. Tetragon selectors (`matchBinaries`, `followChildren`): https://tetragon.netlify.app/docs/concepts/tracing-policy/selectors
2. Claude Code CLI flags, secondary: https://www.verdent.ai/guides/claude/code-cli
3. Claude Code flags and permission modes, secondary: https://dev.to/vpetreski/configure-claude-code-for-maximum-power-4coi
4. Codex `--yolo` / `--dangerously-bypass-approvals-and-sandbox`: https://github.com/openai/codex/issues/22546
5. Gemini CLI reference (`--approval-mode`, `--yolo` deprecated): https://geminicli.com/docs/cli/cli-reference.md
6. Permission modes across agents, secondary: https://flaviocopes.com/ai-glossary/permission-modes/
7. AgentSight README: https://docs.rs/crate/agentsight/0.2.42/source/README.md
8. AgentSight and Tetragon for Codex CLI, secondary: https://codex.danielvaughan.com/2026/06/09/ebpf-runtime-observability-codex-cli-agentsight-tetragon-kernel-level-agent-monitoring/
9. Landlock TCP Fast Open connect bypass (LSM list, June 2026): https://kernsec.org/pipermail/linux-security-module-archive/2026-June/058089.html
10. AppArmor TCP Fast Open connect bypass (LSM list, June 2026): https://kernsec.org/pipermail/linux-security-module-archive/2026-June/058126.html
11. Claude Code sandboxing (bubblewrap, network proxy): https://code.claude.com/docs/en/sandboxing

---

## 11. Owner decisions (2026-11-07)

The review was approved with these corrections and answers.

Corrections:
- The review was moved to `main` at `41c665d`. The "README is a one-line stub" correction
  was removed. README-dependent findings (NEW-8, NEW-9, NEW-17) were rechecked against the
  README and their evidence updated.
- ADR 0001 must remove the `pid != tgid` early return in `handle_exit` and act on whichever
  thread drops `signal->live` to 0. It must report `signal->group_exit_code` when set, and
  confirm the decrement ordering on 6.8 (done, section 5.1) and on 5.15 when available. It
  also needs a regression test where the main thread exits first and a worker last, asserting
  that EXIT and session end each fire exactly once.
- NEW-3 had to be reproduced in the VM before anything is built on it. Done on 6.8
  (section 5.2); 5.15 is unverified.

Answers to section 9:

| # | Decision |
|---|---|
| 1 | Fix NEW-1/NEW-2 as an M0.5 patch before M1a |
| 2 | N1: root-owned venv at `/opt/agentedr`, created by a documented install script, plus a startup self-check that refuses to run as root if any path in the package, the interpreter or the sensor is writable by a non-root user. Rewrite G4 as proposed |
| 3 | Re-cut approved with the v0.1 cut line |
| 4 | Open decisions 1 to 8 accepted as recommended in 7.1 |
| 5 | N3 to N9 accepted. N4: the `agentedr` group stays opt-in and off by default; the docs state that a same-uid agent can then read alerts |
| 6 | Write now: ADRs 0001, 0002, 0003, 0005 (rename part only), 0008, 0009, 0010, 0011, 0012, 0013, 0014, 0017, 0021, 0023. Write the rest at the start of the milestone that needs them |
| 7 | The owner installs and logs in to Claude Code in the VM and reports when done |
