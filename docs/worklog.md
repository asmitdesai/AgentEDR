# Work log

Chronological record of work done on AgentEDR, including decisions, problems
and how they were resolved. Newest session at the bottom.

---

## 2026-10-13 - M0 Skeleton

Branch: `m0-skeleton` (nothing committed yet).

### 1. Planning

- Read `SPEC.md` and `CLAUDE.md`. Wrote the M0 plan (files, tests, CI) and waited for approval
  as CLAUDE.md requires.
- Checked the host: Apple Silicon Mac (arm64), no Linux VM, no Docker, no `uv`. The sensor
  cannot be built or run on macOS, so a Linux VM is required.
- Raised spec issues before starting:
  - A single `vmlinux.h` cannot cover both x86_64 and aarch64 (the file is arch-specific).
  - The spec does not say where `bpftool` comes from.
  - CLAUDE.md refers to "SPEC section 11 (Open decisions)"; the open decisions are in
    section 22. None of them block M0.

Owner decisions:

| Question | Decision |
|---|---|
| Linux environment | Lima VM, Ubuntu 24.04 |
| bpftool source | Vendored git submodule, pinned |
| vmlinux.h | One per architecture (spec change approved) |
| M0 plan | Approved |

### 2. Development environment

- Installed `lima` (2.2.1) and `uv` (0.13.0) on the host via Homebrew.
- Created `bench/vm/lima-dev.yaml`. Provisioning:
  1. Toolchain: clang/llvm 18, libelf, zlib, zstd, libcap, binutils-dev, python3, uv 0.9.5.
  2. Enables BPF LSM by appending `bpf` to the `lsm=` kernel parameter
     (`/etc/default/grub.d/99-agentedr-bpf-lsm.cfg`).
  3. Creates `/opt/agentedr-venv` for the VM's Python venv.
- Started the VM: `limactl start --name=agentedr --mount-only "$PWD:w" bench/vm/lima-dev.yaml`,
  then `limactl restart agentedr` to activate BPF LSM.
- Verified in the VM: kernel `6.8.0-142-generic` aarch64, active LSMs
  `lockdown,capability,landlock,yama,apparmor,bpf`, `/sys/kernel/btf/vmlinux` present.
- Problem: the first mount config used `{{.Dir}}`, which is Lima's instance dir, not the
  YAML's dir. Fixed by passing the mount on the command line (`--mount-only "$PWD:w"`).
- Problem: the VM shares the repo with macOS, so a Linux `.venv` in the tree would clash with
  the macOS one. `/etc/environment` was not picked up by `limactl shell` (persistent SSH
  connection). Fixed by having the top-level Makefile pass
  `UV_PROJECT_ENVIRONMENT=/opt/agentedr-venv` when it delegates to the VM.

### 3. Submodules and vmlinux.h

- Added `sensor/libbpf` at `v1.5.0` and `sensor/bpftool` at `v7.5.0` (with its own nested
  libbpf submodule).
- `sensor/bpf/vmlinux/arm64/vmlinux.h`: dumped from `/sys/kernel/btf/vmlinux` in the VM
  (`make -C sensor vmlinux`).
- `sensor/bpf/vmlinux/x86/vmlinux.h`: downloaded
  `linux-image-unsigned-6.8.0-142-generic_6.8.0-142.142_amd64.deb` from archive.ubuntu.com,
  extracted the zstd-compressed vmlinux ELF from the bzImage, dumped its BTF with bpftool.
  Same kernel version as the VM. Download removed afterwards.
- Documented the provenance in `sensor/bpf/vmlinux/README.md`.
- Updated SPEC 4.1, 18 and the M0 checklist for per-arch `vmlinux.h` and the bpftool submodule.

### 4. Sensor (C)

Files: `sensor/Makefile`, `sensor/bpf/{events.h,maps.h,agentedr.bpf.c,LICENSE}`,
`sensor/src/{main.c,json.c,json.h,protocol.c,protocol.h}`.

- `sensor/Makefile`: builds static libbpf, bootstrap bpftool, the BPF object (clang
  `-target bpf`, CO-RE), the skeleton, then a static `build/agentedr-sensor-<uname -m>`.
- `events.h`, `maps.h`: as in SPEC 8.3 and 6.2. `maps.h` has an `AGENTEDR_MAP_TYPES_ONLY`
  guard so userspace can use the value structs without the map definitions.
- `agentedr.bpf.c` (M0 scope):
  - `handle_exec` (`tp_btf/sched_process_exec`): tagged process -> emit EXEC; untagged ->
    match exe basename against `agent_matchers`, start a session (id from `counters[0]`, +1
    so 0 means "no session"); else emit untagged EXEC for candidate interpreters
    (`node`, `bun`, `deno`, `python3`, `env`).
  - `handle_fork`: copy the tag to new processes only (skip threads).
  - `handle_exit`: leader exits only; emit EXIT with exit code in shell convention
    (status, or 128 + signal) and `is_root`; delete the tag.
  - Ring buffer reserve failure increments `counters[1]`; tag insert failure `counters[2]`.
- `json.c`: JSON line writer. Escapes `"`, `\`, control chars; passes valid UTF-8 through;
  writes bytes of invalid UTF-8 as `\u00XX` so output is always valid JSON.
- `protocol.c`: `PING` -> `PONG`; `SET_MATCHERS` with a small fixed-shape parser (no JSON
  library); `TAG`, `UNTAG`, `SET_PATH_FILTER` -> `ACK ok:false "not implemented"` (M1);
  anything else -> `ACK ok:false "unknown command"`.
- `main.c`: args (`--ringbuf-kib`, `--mode`, `--stats-interval`), BTF check, memlock,
  mode detection from `/sys/kernel/security/lsm`, load/attach with SPEC exit codes, epoll
  over ring buffer + stdin + signalfd + stats timerfd, `READY`/`STATS`/`BYE` lines.

Problem: verifier rejected `handle_exec` with E2BIG ("Argument list too long" = program too
complex). Cause: the basename offset was used to index the stack copy of the path inside
per-character compare loops, so the verifier tracked it precisely and explored every possible
offset for each of 16 matchers. Fix: find the offset with one scan, then read the basename
from kernel memory at `filename + off` into a zero-padded 16-byte union and compare it to
matchers as two u64 words. The offset is then only a helper pointer offset, stays imprecise,
and the program loads.

Manual sensor test in the VM (fake `claude` = copy of `/bin/bash`):
- Session 1 started for the fake agent; `git`, `cat`, `echo` children had session id 1.
- Root EXIT: `is_root:true`, `exit_code:3` as scripted.
- Unrelated `ls` produced nothing; `python3` produced an untagged EXEC.
- Escaping checked with quotes, backslashes, `\x01`, `\xff` and `é`; all lines parsed as JSON.
- ACKs correct for valid/invalid `SET_MATCHERS`, `BOGUS`, `TAG`; `PING` -> `PONG`; `BYE` on EOF.

### 5. Engine (Python)

Files: `pyproject.toml`, `uv.lock`, `src/agentedr/{__init__,__main__,config,models,decoder,
supervisor,cli}.py`, `src/agentedr/data/default_config.yaml`.

- Runtime deps: pydantic, PyYAML, typer. Dev deps: pytest, pytest-asyncio, ruff, mypy,
  types-PyYAML (needed for `mypy --strict`).
- `config.py`: packaged `default_config.yaml` (SPEC 10, verbatim) is the single source of
  defaults; user file deep-merged on top (mappings merge, lists replace); pydantic models with
  `extra="forbid"`; kernel limits validated (basename <= 15 bytes, <= 16 matchers, path
  filters < 64 bytes, ring buffer power of two). `--dev` redirects writable paths to
  `./.agentedr/`. Matcher `kind` = agent's index in `agents`.
- `models.py`: READY/STATS/ACK/PONG/BYE and EXEC/EXIT, discriminated on `type`.
- `decoder.py`: rejects lines > 64 KiB, bad JSON, unknown types, schema mismatches; logs a
  reason (never the line, it may contain secrets) and counts. Never fatal.
- `supervisor.py`: root check (`--allow-nonroot` for dev), locate sensor (config or bundled
  `_bin/agentedr-sensor-<machine>`), start, wait 10 s for READY (error includes exit code and
  stderr tail), push `SET_MATCHERS` and await ACK, FIFO pairing of ACK/PONG, stderr forwarded
  at WARNING, warnings on ring buffer drops and tag map full, stop via stdin EOF then
  SIGTERM/SIGKILL. No restart yet (M1).
- `cli.py`: `agentedr run [--config] [--dev] [--mode] [--allow-nonroot] [--show-events]`.
  Prints SESSION START / SESSION END (and all tagged events with `--show-events`).

### 6. Tests, tooling, CI

- `tests/unit/test_config.py`, `tests/unit/test_decoder.py`.
- `tests/protocol/fake_sensor.py` + `test_supervisor.py`: handshake, event delivery,
  malformed lines counted, unknown command, rejected matchers, startup failure with stderr,
  READY timeout, stderr forwarding, drop warnings, stop escalation, root check.
- `tests/integration/test_fake_agent.py` (SPEC 16.2): root + BTF + built sensor, skips
  otherwise.
- Top-level `Makefile`: `sensor`, `dev`, `test`, `lint`, `vm-test`, `clean`. On macOS,
  `sensor` and `vm-test` run in the Lima VM. `make sensor` copies the binary to
  `src/agentedr/_bin/`.
- `.github/workflows/ci.yml`: lint, tests on Python 3.11/3.12/3.13, x86_64 static sensor build
  with artifact upload.
- `.gitignore`, `LICENSE` (Apache-2.0), `sensor/bpf/LICENSE` (GPL-2.0 text from the kernel
  tree, SPDX header stripped). A stray `sensor/LICENSE` created by a failed download was
  removed.
- Ruff fixes: `StrEnum` for `Mode`, line length. Mypy fixes: `reject()` returns None
  explicitly; typed list for pending futures.

### 7. Verification results

| Check | Result |
|---|---|
| `make sensor` | OK (aarch64 static binary in the VM) |
| BPF object + skeleton against x86 `vmlinux.h` | OK |
| `ruff check` | pass |
| `ruff format --check` | pass |
| `mypy src` (strict) | pass |
| `pytest` (host) | 45 passed, 1 skipped (integration) |
| `make vm-test` | 1 passed |
| `agentedr run --dev --show-events` with fake agent in VM | session start, children same session id, outsider invisible, session end |

### 8. Open items

- M0 "Done when" still needs: a real `claude` session in the VM, and a green CI run.
  Installing Claude Code in the VM with `curl | bash` was blocked by the permission
  classifier; owner to install and log in.
- Push branch / open PR when the owner approves.
- Licensing question: `events.h` and `maps.h` are under `sensor/bpf/` (GPL-2.0) but are
  included by the Apache-2.0 userspace. Proposed: dual-license those headers
  (e.g. `LGPL-2.1 OR BSD-2-Clause`) or move them. Awaiting decision.
- Size budget: userspace sensor is ~670 non-blank, non-comment lines (budget ~600). M1 will
  add more; proposed raising the budget to ~1000. Awaiting decision.
