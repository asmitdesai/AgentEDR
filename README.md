# AgentEDR

[![ci](https://github.com/asmitdesai/AgentEDR/actions/workflows/ci.yml/badge.svg)](https://github.com/asmitdesai/AgentEDR/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![eBPF: GPL-2.0](https://img.shields.io/badge/eBPF-GPL--2.0-blue.svg)](sensor/bpf/LICENSE)

Kernel-level detection for hijacked AI coding agents on Linux.

AgentEDR attributes every exec, file, network and ptrace action to the AI coding agent
session that caused it (Claude Code, Codex CLI, Gemini CLI, Cursor agent), including all
descendant processes, and runs a small set of high-signal rules that separate a hijacked
agent from a busy one.

> **Status: early development (M0 of 4 complete).** Session tracking for process
> exec/fork/exit works end to end. File, network and ptrace telemetry, detection rules and
> the benchmark are not built yet. See [Roadmap](#roadmap). Do not rely on this for
> protection today.

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
| Install persistence (shell rc, systemd user units, crontab, `authorized_keys`, ...) | AEDR-002 |
| Weaken the agent's own guardrails (permission, sandbox, MCP config) | AEDR-003 |
| Download and execute a second stage | AEDR-004 |
| Exfiltrate credentials | AEDR-005 |

Out of scope: a root attacker, kernel exploits, malicious edits that stay inside the
workspace and look like normal code changes, and agents running on remote machines.
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
  compiler or kernel headers on the target, so the goal is a plain `pip install`.
- **Monitor only.** LSM programs always return 0. Nothing is blocked in v1.
- **Behaviour, not conversations.** AgentEDR never inspects prompts or model output.

## What works today (M0)

- In-kernel session tagging: an exec of a matching agent binary (`claude`, `codex`,
  `cursor-agent`, ...) starts a session; children inherit the session on fork (threads are
  skipped); exits clean up and report the exit code.
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

To enable BPF LSM on Ubuntu, append `bpf` to the `lsm=` kernel parameter, for example
with a file in `/etc/default/grub.d/`, then run `update-grub` and reboot. The dev VM below
does this for you.

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
docs/             progress.md, worklog.md
SPEC.md           full technical specification
```

[SPEC.md](SPEC.md) is the source of truth for scope, protocol, event schema, rules and
milestones. [docs/progress.md](docs/progress.md) and [docs/worklog.md](docs/worklog.md)
track what has been built and the decisions behind it.

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| **M0 - Skeleton** | Repo, build, exec/fork/exit tagging, sensor protocol, supervisor, CI | Done (real-`claude` check pending) |
| **M1 - Telemetry** | File, exec-check, connect, unlink, rename, ptrace hooks (LSM and fentry); path filter; argv tagging with `/proc` walk; enrichment; redaction; SQLite; `doctor`, `status`, `sessions`, `replay` | Next |
| **M2 - Detections** | Rule engine (single and sequence), egress allowlist, alerts with dedup, AEDR-001 to AEDR-005 with golden tests, `alerts`, `analyze`, `rules` | Planned |
| **M3 - Benchmark and release** | Attack and benign corpora, one-command benchmark, overhead numbers, wheel with bundled sensors, PyPI v0.1.0 | Planned |

Planned v1 rules:

| Rule | Severity | Detects |
|---|---|---|
| AEDR-001 | High | Agent read a credential file outside the workspace |
| AEDR-002 | Critical | Agent wrote to a persistence location |
| AEDR-003 | High | Agent modified its own permission or MCP configuration |
| AEDR-004 | High | Agent executed a file it recently wrote to a staging location |
| AEDR-005 | Critical | Credential read followed by egress to a non-allowlisted destination |

Benchmark targets for v0.1.0: at least 90% detection rate, at most 1 false positive per
agent-hour, under 5% overhead on agent workloads, no measurable overhead elsewhere, under
1 s p95 event-to-alert latency, zero ring buffer drops. Results will be published here
whether or not they meet the targets.

Later: harness hook bridge, more rules, opt-in enforcement for AEDR-002 and AEDR-003 (BPF
LSM only), OCSF/ECS output, container-aware sessions, unprivileged engine.

## Known limitations

- Public rules can be evaded by an attacker who reads them.
- A root attacker can disable the sensor.
- Agent matchers depend on vendor packaging and will need updates as agents change.
- Network attribution is IP-level; domain allowlisting is resolution-based.
- Malicious edits inside the workspace are invisible by design.
- Very long paths and argv are truncated in the kernel.
- Linux only. No macOS, Windows, containers or remote agents in v1.

## License

- eBPF programs under [`sensor/bpf/`](sensor/bpf/): [GPL-2.0](sensor/bpf/LICENSE)
- Everything else: [Apache-2.0](LICENSE)

## Author

Asmit Desai - [asmitdesai.dev](https://asmitdesai.dev) -
[GitHub](https://github.com/asmitdesai) -
[LinkedIn](https://www.linkedin.com/in/asmit-desai-858668230)
