# Progress

## M0 - Skeleton

Status: code complete; real-agent check and CI run pending (see below).

### Done

- Repo layout, `pyproject.toml` (hatchling, uv), top-level `Makefile` with `sensor`, `dev`,
  `test`, `lint`, `vm-test`. On macOS, `sensor` and `vm-test` run inside the Lima VM
  (`bench/vm/lima-dev.yaml`).
- Submodules: libbpf `v1.5.0`, bpftool `v7.5.0` (build-time only).
- Per-arch `vmlinux.h` from Ubuntu 24.04 kernel `6.8.0-142-generic` (x86 and arm64);
  SPEC 4.1 and 18 updated accordingly.
- `sensor/bpf/`: `events.h`, `maps.h` (SPEC 6.2, 8.3) and `handle_exec`, `handle_fork`,
  `handle_exit` with the tagging logic of SPEC 6.3, including untagged candidate EXECs.
- Sensor userspace: arg parsing, memlock, mode detection, load/attach, epoll loop over ring
  buffer, stdin, signalfd and stats timer; `READY`, `STATS`, `BYE`, `SET_MATCHERS`, `PING`.
  `TAG`, `UNTAG`, `SET_PATH_FILTER` answer `ACK ok:false "not implemented"` until M1.
- Engine: config loading (packaged defaults + deep-merged user file), models and decoder for
  control lines and EXEC/EXIT, supervisor (start, READY wait, matcher push, stderr forwarding,
  drop warnings, clean stop), `agentedr run [--dev] [--mode] [--show-events]`.
- Tests: unit (config, decoder), protocol (supervisor against `tests/protocol/fake_sensor.py`),
  integration (fake agent, SPEC 16.2) via `make vm-test`.
- CI: lint, tests on 3.11-3.13, x86_64 static sensor build.

### Verified

- In the Lima VM (Ubuntu 24.04, 6.8.0-142, aarch64, BPF LSM active): fake `claude` (copy of
  bash) starts a session; `git`, `cat`, `ls` children carry the same session id; root EXIT has
  `is_root=true` and the right exit code; processes outside the tree produce no events.
- BPF object also compiles and skeletonizes against the x86 `vmlinux.h`.

### Pending for "Done when"

- Real `claude` session in the VM (needs Claude Code installed and logged in inside the VM).
- CI green on GitHub (needs the branch pushed).

### Notes for M1

- Userspace sensor is ~670 non-blank, non-comment lines already, above the ~600 budget, and
  M1 adds five event types, `/proc` walk, `TAG`/`UNTAG`/`SET_PATH_FILTER`.
- Verifier lesson: indexing a stack buffer with a data-dependent offset inside a loop made
  `handle_exec` too complex to load (E2BIG). Using the offset only as a helper pointer offset
  keeps it imprecise and the program small. Apply the same pattern in M1 path handling.
