# CLAUDE.md - working instructions for AgentEDR

Read `SPEC.md` before doing anything. It is the source of truth for scope, architecture, stack and milestones.

## Project shape

- `sensor/` is C: eBPF programs plus a small libbpf loader that streams JSON lines. It contains no detection logic.
- `src/agentedr/` is Python: supervisor, enrichment, sessions, rules, outputs, CLI. All detection logic lives here.
- The owner is strong in Python and new to eBPF. Keep the C side small, heavily commented, and explain any non-obvious verifier or libbpf detail in comments.

## How to work

- Work one milestone at a time (M0 -> M1 -> M2 -> M3). Do not start the next milestone until the current one's "Done when" criteria pass.
- At the start of each milestone, write a short plan (files to create, tests to add) and wait for approval.
- Do not add features, dependencies or components that are not in SPEC.md. If something seems necessary, propose it and explain why; do not just add it.
- When you hit an item in SPEC.md section 11 (Open decisions), stop and ask. Do not pick an answer silently.
- If the spec is wrong or impossible (e.g. a verifier limitation, a kernel API that doesn't exist on 5.15), say so clearly and propose the smallest change to the spec.

## Sensor rules (C)

- CO-RE with `vmlinux.h`, loaded via a `bpftool gen skeleton` skeleton. No BCC.
- Every hook checks `agent_pids` first and returns early for untagged processes.
- LSM programs return 0 (monitor mode only). Never deny in v1.
- Must work in both BPF LSM mode and fentry fallback mode.
- Userspace sensor stays under ~600 lines. If logic is needed, it belongs in Python.
- Escape all strings correctly when writing JSON.

## Engine rules (Python)

- Python 3.11+, fully type-hinted, passes `mypy`.
- Use only the libraries listed in SPEC.md section 4; ask before adding others.
- `yaml.safe_load` only. Never use `eval`, `exec` or pickle on rule or config data.
- Malformed sensor lines are logged and counted, never fatal.

## Code quality

- Every detection rule needs a golden-file pytest with one true positive and at least one benign near-miss.
- Before declaring any task done, run: `make sensor`, `ruff check`, `ruff format --check`, `mypy src`, `pytest`.
- Never write real secrets anywhere, including tests and benchmark fixtures. Use obviously fake canary values.
- Output files are created with mode 0600. Redact secrets before writing any event.
- No emojis in code, comments, commit messages or docs.
- When changing a file, show the entire updated file rather than a partial diff when reporting back.

## Commands

```
make sensor       # build eBPF objects, skeleton and static sensor binary
make dev          # uv sync, install engine in editable mode
make test         # pytest (unit + golden-file rule tests)
make lint         # ruff + mypy
make vm-test      # integration tests in a VM with BPF LSM enabled
```

(Create these Make targets during M0.)

## Licensing

- Files under `sensor/bpf/` are GPL-2.0 and must declare `char LICENSE[] SEC("license") = "GPL";`.
- Everything else is Apache-2.0.
