# Architecture decision records

Each ADR records one decision: context, decision, alternatives, consequences, kernel-version
notes and tests. ADRs are numbered in the order proposed by the November 2026 product and
security review. Planned ADRs are written at the
start of the milestone that needs them.

| ADR | Title | Status | Milestone |
|---|---|---|---|
| [0001](0001-group-exit-aware-tag-lifetime.md) | Group-exit-aware tag lifetime | Accepted | M0.5 |
| [0002](0002-process-identity.md) | Process identity is (pid, start time) | Accepted | M1a |
| [0003](0003-session-adoption-and-argv-tag-race.md) | Session adoption and the argv-tag race | Accepted | M1a |
| 0004 | Blind spots and tamper signals | Planned | M1b |
| [0005](0005-file-identity-beyond-paths.md) | File identity beyond open-for-write (rename part) | Accepted (rename only) | M1a |
| 0006 | Network telemetry beyond connect | Planned | M1b |
| 0007 | Session taint model | Planned | M2 |
| [0008](0008-harness-root-trust-model.md) | The harness root process is not trusted | Accepted | M1a |
| [0009](0009-credential-consumer-model.md) | Expected consumers of credential files | Accepted | M1a |
| [0010](0010-workspace-root-resolution.md) | Workspace root resolution and degraded mode | Accepted | M1a |
| [0011](0011-install-and-execution-integrity.md) | Install and execution integrity | Accepted | M1a |
| [0012](0012-safe-output-paths.md) | Safe output paths | Accepted | M1a |
| [0013](0013-configuration-trust-boundary.md) | Configuration trust boundary | Accepted | M1a |
| [0014](0014-protocol-and-schema-versioning.md) | Protocol and schema versioning | Accepted | M0.5 |
| 0015 | Data access and notification | Planned | M2 |
| 0016 | Privilege split (design only) | Planned | M3 |
| [0017](0017-shared-header-licensing.md) | Licensing of shared BPF headers | Accepted | M0.5 |
| 0018 | Release supply chain | Planned | M3 |
| 0019 | Kernel test matrix | Planned | M1b |
| 0020 | Deception canaries | Planned | v0.2 |
| [0021](0021-redaction-and-raw-recording-policy.md) | Redaction and raw recording policy | Accepted | M1a |
| 0022 | Output formats | Planned | v0.2 |
| [0023](0023-sensor-size-budget-and-layout.md) | Sensor size budget and file layout | Accepted | M0.5 |
| [0024](0024-kernel-session-identity-without-fetch-atomics.md) | Kernel session identity without fetch atomics | Accepted | M0.5 |
