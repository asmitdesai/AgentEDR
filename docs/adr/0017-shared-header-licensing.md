# ADR 0017: Licensing of shared BPF headers

Status: Accepted (2026-11-07)
Milestone: M0.5
Related: review SA-7, decision N5; M0 open items

## Context

Files under `sensor/bpf/` are GPL-2.0. `events.h` and `maps.h` live there and are included
by the Apache-2.0 userspace sensor (`sensor/src/main.c`, `sensor/src/protocol.c`). They
contain only struct, enum and constant definitions shared between the BPF programs and the
loader. Including GPL-2.0-only headers in Apache-2.0 code makes the userspace binary's
licensing unclear: Apache-2.0 and GPL-2.0-only are generally considered incompatible.

## Decision

1. Relicense `sensor/bpf/events.h` and `sensor/bpf/maps.h` as
   `SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause`. This dual license is common
   libbpf practice; libbpf itself is `LGPL-2.1 OR BSD-2-Clause`.
2. Add the BSD-2-Clause text as `sensor/bpf/LICENSE.BSD-2-Clause`. `sensor/bpf/LICENSE`
   keeps the GPL-2.0 text.
3. `sensor/bpf/agentedr.bpf.c`, and any future BPF program or hook header, stays GPL-2.0
   and keeps `char LICENSE[] SEC("license") = "GPL";`. Only headers included by userspace
   are dual-licensed.
4. Update the contributor instructions and the README license section to state the exception.
5. The owner is the sole copyright holder of these files (written in this repository by the
   owner with an AI assistant; no outside contributions), so relicensing needs no other
   consent. Future contributions to these two headers are accepted under the dual license
   (CONTRIBUTING.md, M3).

## Alternatives considered

- **Move the headers out of `sensor/bpf/` under Apache-2.0.** The BPF programs, which must
  be GPL-compatible to use GPL-only helpers, would then include Apache-2.0 headers. That
  combination is equally unclear. Rejected.
- **`LGPL-2.1 OR BSD-2-Clause`** (the first proposal during M0). Also fine. Rejected only
  because the BPF side's license is GPL-2.0, so `GPL-2.0-only` is the natural first option.

## Consequences

- The userspace binary is clearly Apache-2.0 plus BSD-2-Clause headers plus statically linked
  libbpf (LGPL-2.1 OR BSD-2-Clause, used under BSD-2-Clause).
- `make sensor` output is unchanged.

## Kernel-version notes

None. The kernel checks only the BPF object's `license` section, which is unchanged.

## Tests

None. Review the SPDX lines in the M0.5 diff.
