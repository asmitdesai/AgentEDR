# AgentEDR

[![ci](https://github.com/asmitdesai/AgentEDR/actions/workflows/ci.yml/badge.svg)](https://github.com/asmitdesai/AgentEDR/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![eBPF: GPL-2.0](https://img.shields.io/badge/eBPF-GPL--2.0-blue.svg)](sensor/bpf/LICENSE)

Kernel-level detection for hijacked AI coding agents on Linux.

AgentEDR attributes every exec, file, network and ptrace action to the AI coding agent
session that caused it (Claude Code, Codex CLI, Gemini CLI, Cursor agent), including all
descendant processes, and runs a small set of high-signal rules that separate a hijacked
agent from a busy one.

> **Status: early development (M0 complete, M0.5 next).** Session tracking for process
> exec/fork/exit works end to end, with a known tagging gap that M0.5 fixes (see
> [Known limitations](#known-limitations)). File, network and ptrace telemetry, detection
> rules and the benchmark are not built yet. See [Roadmap](#roadmap). Do not rely on this
> for protection today.

---

## Why

Coding agents run with the developer's full privileges. They execute shell commands, read
and write files, install packages and make network requests, often driven by text they did
not write: READMEs, issues, dependency docs, web pages, MCP tool output. A single indirect
prompt injection can turn the agent into a tool for the attacker.

Visibility already exists (harness hooks, OpenTelemetry, generic eBPF tracers). Detection
does not. In existing telemetry, a hijacked agent and a hard-working agent look almost
the same.

AgentEDR's approach:

1. **Attribute** every kernel-level action to a specific agent session, in the kernel,
   before it reaches userspace.
2. **Detect** with a few deterministic, high-signal rules aimed at what an attacker actually
   wants from a developer machine.
3. **Prove it** with a public, reproducible benchmark of attack and benign sessions.

## Threat model in one table

The adversary can place text the agent will read, but cannot run code directly.

| Attacker objective | Planned rule |
|---|---|
| Read credentials (`~/.ssh`, `~/.aws`, `~/.kube`, `.env` outside the workspace, ...) | AEDR-001 |
| Install persistence (shell rc, systemd user units, crontab, `authorized_keys`, git and ssh config, ...) | AEDR-002 |
| Weaken the agent's own guardrails (permission, hooks, sandbox, MCP config) | AEDR-003 |
| Make an injection persistent through global agent instructions or memory (`~/.claude/CLAUDE.md`, `AGENTS.md`, commands, skills) | AEDR-013 |
| Download and execute a second stage | AEDR-004, AEDR-006 |
| Exfiltrate credentials | AEDR-005 |
| Escalate to root (sudo, setuid) | AEDR-009 |

The agent process itself is not trusted: agents perform many file reads, writes and web
fetches inside their own process, so rules apply to the agent and to everything it runs.

Out of scope:
- a root attacker. If the agent's user has passwordless or cached `sudo`, the agent can
  become root, and AgentEDR cannot protect itself on that machine;
- kernel exploits;
- malicious edits that stay inside the workspace and look like normal code changes;
- agents running on remote machines or inside containers;
- agents embedded in an IDE (editor extension hosts) rather than run as a CLI.

Full details in [SPEC.md, section 2](SPEC.md#2-threat-model).

## Architecture

Two processes with a strict split:

```
 Linux kernel
   tp_btf: sched_process_exec / fork / exit
   lsm (or fentry fallback): file_open, bprm_check_security, socket_connect,
                             inode_unlink, inode_rename, ptrace_access_check
        |
        |  agent_pids map: set on agent exec, inherited on fork, cleared on exit
        |  every hook returns early for untagged processes
        v
   BPF ring buffer
        |
 agentedr-sensor (C, libbpf CO-RE, static binary)
   ring buffer -> one JSON line per event on stdout
   control commands on stdin
        |
 agentedr engine (Python, asyncio)
   supervisor -> decoder -> tagger -> enrichment -> sessions -> rules
   -> redaction -> alerts.jsonl / events.jsonl / SQLite
```

| Component | Language | Does | Never does |
|---|---|---|---|
| `agentedr-sensor` | C | Loads eBPF programs, tags agent process trees in-kernel, streams events | Detection logic, enrichment, config parsing |
| `agentedr` engine | Python | Supervises the sensor, sessions, rules, redaction, storage, CLI | Kernel interaction other than through the sensor and `/proc` |

Design choices worth knowing:

- **In-kernel filtering.** Only processes descended from a known agent produce events, so
  non-agent workloads see near-zero overhead and Python throughput is never the bottleneck.
- **CO-RE, not BCC.** The sensor compiles once and runs on supported kernels without a
  compiler or kernel headers on the target. The planned install is one documented command
  that creates a root-owned environment in `/opt/agentedr`. AgentEDR runs as root, so it
  will refuse to run from a location your user (or a hijacked agent running as your user)
  can modify.
- **Monitor only.** LSM programs always return 0. Nothing is blocked in v1.
- **Behaviour, not conversations.** AgentEDR never inspects prompts or model output.

## What works today (M0)

- In-kernel session tagging: an exec of a matching agent binary (`claude`, `codex`,
  `cursor-agent`, ...) starts a session; children inherit the session on fork (threads are
  skipped); exits clean up and report the exit code. Known gap until M0.5: a process that
  calls `exec` from a worker thread, or whose main thread exits before its other threads,
  loses its session tag.
- Candidate interpreter EXECs (`node`, `bun`, `deno`, `python3`, `env`) are emitted untagged,
  ready for argv-based tagging of agents launched through an interpreter (M1).
- Static sensor binary with ring buffer streaming, `READY` / `STATS` / `BYE` control lines,
  `SET_MATCHERS` and `PING`, and drop counters.
- Python engine: layered config (packaged defaults plus a deep-merged user file), strict
  decoder that counts and never crashes on malformed lines, sensor supervisor with
  handshake, stderr forwarding, drop warnings and clean shutdown.
- `agentedr run` prints session start and end, and every tagged event with
  `--show-events`.
- Tests: unit, protocol (against a fake sensor) and an integration test with a fake agent in
  a BPF-LSM VM. CI runs lint, tests on Python 3.11 to 3.13 and a static x86_64 sensor build.

Verified in an Ubuntu 24.04 VM (kernel 6.8, aarch64, BPF LSM active): a fake agent starts a
session, its `git`, `cat` and `ls` children carry the same session id, the root exit is
reported with the right exit code, and processes outside the tree produce no events.

Example event line from the sensor:

```json
{"type":"EXEC","ts_ns":81234567890,"pid":4121,"tid":4121,"ppid":4100,"uid":1000,"session_id":3,"agent_kind":0,"comm":"cat","filename":"/usr/bin/cat","argv":["cat","/home/dev/.aws/credentials"],"argv_truncated":false,"session_start":false,"untagged":false}
```

## Requirements

| Requirement | Why | Check |
|---|---|---|
| Linux 5.8+ (targets: Ubuntu 22.04 and 24.04) | BPF ring buffer | `uname -r` |
| BTF enabled | CO-RE, `tp_btf`, fentry | `test -f /sys/kernel/btf/vmlinux` |
| BPF LSM active (optional) | LSM mode; otherwise fentry fallback (M1) | `cat /sys/kernel/security/lsm` contains `bpf` |
| Root | Loading eBPF programs | |

To enable BPF LSM on Ubuntu, add `bpf` to the `lsm=` kernel parameter, for example with a
file in `/etc/default/grub.d/`, then run `update-grub` and reboot. `lsm=` replaces the whole
list, so keep every LSM that is already active and append `bpf`:

```sh
echo "GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX lsm=$(cat /sys/kernel/security/lsm),bpf\"" \
  | sudo tee /etc/default/grub.d/99-bpf-lsm.cfg
sudo update-grub   # then reboot
```

Setting `lsm=bpf` on its own would turn off AppArmor and the other active LSMs. The dev VM
below does this for you. Without BPF LSM, AgentEDR will use fentry mode (from M1a), which
loses nothing in monitor mode.

Build dependencies: clang/llvm, make, libelf, zlib, zstd, libcap, binutils-dev, git,
Python 3.11+ and [uv](https://docs.astral.sh/uv/).

## Build and run from source

There is no packaged release yet. A `pip install agentedr` wheel with bundled sensor
binaries is planned for v0.1.0.

```sh
git clone --recursive https://github.com/asmitdesai/AgentEDR.git
cd AgentEDR

make sensor     # builds libbpf, bpftool, the BPF object, skeleton and static sensor
make dev        # uv sync

sudo .venv/bin/agentedr run --dev --show-events
```

In another terminal, start an agent (for example `claude`). You should see a
`SESSION START`, the agent's children under the same session id, and a `SESSION END` when it
exits. Processes started elsewhere produce nothing.

`--dev` keeps all writable paths under `./.agentedr/` instead of `/var/lib` and `/var/log`.

This development setup runs code from your own checkout as root, and `./.agentedr/` sits in
your working directory. Do not use it on a machine where an agent you do not trust can write
to the checkout or to that directory. From M1a, `--dev` writes to a root-only directory in
`/var/tmp/agentedr-dev/`, and running as root from a user-writable install will need an
explicit development flag, `--allow-unsafe-install`, which is accepted only together with
`--dev` and marks every session and alert `integrity: "unverified"`.

### On macOS (dev VM)

The sensor needs Linux. On macOS the top-level Makefile runs `sensor` and `vm-test` inside a
[Lima](https://lima-vm.io/) VM (Ubuntu 24.04, BPF LSM enabled):

```sh
brew install lima uv
limactl start --name=agentedr --mount-only "$PWD:w" bench/vm/lima-dev.yaml
limactl restart agentedr        # activates BPF LSM
make sensor                     # runs inside the VM
make vm-test                    # integration tests inside the VM
```

## Development

| Command | What it does |
|---|---|
| `make sensor` | Build the eBPF object, skeleton and static sensor; copy it to `src/agentedr/_bin/` |
| `make dev` | `uv sync` |
| `make test` | `pytest` (unit and protocol; integration tests skip without root and a sensor) |
| `make lint` | `ruff check`, `ruff format --check`, `mypy --strict src` |
| `make vm-test` | Integration tests with a real sensor (needs root and BTF) |
| `make clean` | Remove sensor build output |

Repository layout:

```
sensor/
  bpf/            eBPF programs, event and map definitions, per-arch vmlinux.h (GPL-2.0)
  src/            libbpf loader, JSON writer, control protocol
  libbpf/         submodule, pinned v1.5.0
  bpftool/        submodule, pinned v7.5.0 (build time only)
src/agentedr/     Python engine and CLI
tests/            unit, protocol (fake sensor), integration (fake agent)
bench/vm/         Lima dev VM
docs/             adr/ (decision records)
SPEC.md           full technical specification
```

[SPEC.md](SPEC.md) is the source of truth for scope, protocol, event schema, rules and
milestones. Architectural decisions and their reasoning are recorded as
[ADRs](docs/adr/).

## Roadmap

The plan was re-cut after a product and security review in November 2026; the resulting
decisions are recorded as [ADRs](docs/adr/).

| Milestone | Scope | Status |
|---|---|---|
| **M0 - Skeleton** | Repo, build, exec/fork/exit tagging, sensor protocol, supervisor, CI | Done (real-`claude` check pending) |
| **M0.5 - Fix and close M0** | Thread-group-aware exit handling (fixes the tagging gap), protocol version, header licensing, SHA-pinned CI actions, real-`claude` check | Next |
| **M1a - Vertical slice** | File, exec-check, connect and rename hooks (LSM and fentry); process identity; adoption of already-running agents; sessions, enrichment, workspace detection; redaction; safe outputs; install self-check; SQLite; AEDR-001, 002, 003, 013; `doctor`, `status`, `sessions`, `replay`, `demo` | Planned |
| **M1b - Telemetry breadth** | Unlink, ptrace, UDP and TCP Fast Open egress, tamper hooks, split ring buffers, fuzzing, aarch64 CI, kernel test matrix | Planned |
| **M2 - Detections** | Sequence rules and session taint, egress allowlist, AEDR-004, 005, 006, 009, process-tree escape rules, incidents with likely injection source, `explain`, `suppress`, `alerts`, `analyze`, `rules` | Planned |
| **M3 - Benchmark and release** | Attack, benign and evasion corpora, overhead numbers, root-owned install script, signed release with SBOM and provenance, systemd unit, v0.1.0 | Planned |

Moved to v0.2: inode-based file identity (catches hardlinks), DNS query name capture,
in-kernel rate limiting, deception canaries, OCSF output, desktop notifications.

Planned v0.1 rules:

| Rule | Severity | Detects |
|---|---|---|
| AEDR-001 | High | Agent read a credential file outside the workspace, and the reader is not the file's expected consumer |
| AEDR-002 | Critical | Agent wrote (or renamed a file onto) a persistence location |
| AEDR-003 | High | Agent modified its own permission, hook or MCP configuration |
| AEDR-004 | High | Agent executed a file it recently wrote to a staging location |
| AEDR-005 | Critical | Credential read followed by egress to a non-allowlisted destination |
| AEDR-006 | High | Pipe-to-shell or decode-and-run |
| AEDR-009 | High | sudo or setuid execution from an agent session |
| AEDR-013 | High | Agent wrote a global agent instruction or memory file |

Benchmark targets for v0.1.0: at least 90% detection rate, at most 1 false positive per
agent-hour, under 5% overhead on agent workloads, no measurable overhead elsewhere, under
1 s p95 event-to-alert latency, zero ring buffer drops. Results will be published here
whether or not they meet the targets.

Later: harness hook bridge, more rules, opt-in enforcement for AEDR-002 and AEDR-003 (BPF
LSM only), ECS output, container-aware sessions, unprivileged engine.

## Known limitations

Today (M0):
- A process in an agent session that calls `exec` from a worker thread, or whose main thread
  exits while other threads keep running, drops out of the session. Verified on kernel 6.8;
  fixed in M0.5.
- An agent that was already running when AgentEDR started is not tracked (adoption arrives
  in M1a).
- Only process exec and exit are observed; there is no file, network or ptrace telemetry
  and no detection yet.

By design, also after v0.1:
- Public rules can be evaded by an attacker who reads them. Known evasions are kept in an
  evasion corpus and reported as caught or missed.
- A root attacker can disable the sensor. That includes an agent whose user has
  passwordless or cached `sudo`.
- Agent matchers, flags and config paths depend on vendor packaging and need updates as
  agents change.
- Agents embedded in an IDE are not observed; only CLI agents are.
- Network attribution is IP-level; domain allowlisting is resolution-based. Egress that
  skips `connect()` (unconnected UDP, TCP Fast Open) is invisible until M1b.
- File identity is path-based in v0.1, so a hardlink to a credential file is not recognised.
- Credential access that reads no file is not detected as a credential read (environment
  variables, desktop keyrings over D-Bus, ssh-agent).
- Malicious edits inside the workspace are invisible by design.
- Very long paths and argv are truncated in the kernel.
- If you opt in to letting your user read alerts without `sudo`, a hijacked agent running as
  you can read them too.
- Linux only. No macOS, Windows, containers or remote agents in v1.

## License

- eBPF programs under [`sensor/bpf/`](sensor/bpf/): [GPL-2.0](sensor/bpf/LICENSE)
- Everything else: [Apache-2.0](LICENSE)

## Author

Asmit Desai - [asmitdesai.dev](https://asmitdesai.dev) -
[GitHub](https://github.com/asmitdesai) -
[LinkedIn](https://www.linkedin.com/in/asmit-desai-858668230)
