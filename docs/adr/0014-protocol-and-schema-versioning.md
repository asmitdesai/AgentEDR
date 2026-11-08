# ADR 0014: Protocol and schema versioning

Status: Accepted (2026-11-07)
Milestone: M0.5 (protocol field), M1a (schema versions, mismatch detection)
Related: review SA-4a, SA-4b, NEW-14; SPEC 7, 8, 12, 13

## Context

The sensor reports `version` in READY, and the engine logs it and carries on. The engine's
models reject unknown fields (`extra="forbid"`). If the sensor and engine are out of step,
for example a new event field, every event is counted as malformed with one WARNING per
line, and the engine keeps running with zero detections. That is a silent failure of the
whole product.

Stored events and alerts have no schema version, so `analyze`, `replay` and integrations
cannot tell what shape a stored record has. The SQLite `meta.schema_version` covers DB
migrations only.

## Decision

1. **Protocol version.** READY gains `"protocol": <int>`. It is incremented on any change to
   event fields, event semantics, control lines or commands.
   - Protocol 1 is what M0.5 ships (M0 plus the ADR 0001 EXIT semantics).
   - M1a ships protocol 2 (`start_ns`, new event types, new `TAG`/`UNTAG` arguments).
   - The sensor `version` string stays informational.
2. **Engine check.** The engine parses READY with a lenient model (`type`, `protocol`, rest
   ignored) before strict parsing, and compares `protocol` with its supported set (exactly
   one version in v1).
   - A missing or unsupported value stops the engine with a message naming both versions and
     the fix (reinstall so that sensor and engine come from the same release).
   - Exit code 3 (environment unsupported).
3. **Mismatch detection after READY.** If 20 consecutive event lines, or more than 5% of
   lines in any 10-second window with at least 100 lines, are malformed, the engine logs one
   ERROR ("protocol mismatch or sensor bug suspected"), records a blind-spot entry on every
   open session, and keeps counting. Per-line warnings are rate-limited to one per 10 s with
   a count.
4. **Schema versions for stored data.**
   - Each event record written to `events.jsonl` and to SQLite `events.data` carries
     `"schema_version": <int>` for the enriched event shape.
   - Each alert carries `"schema_version"` for the alert shape (SPEC 12.1).
   - Both start at 1 in M1a and increase independently of the protocol.
   - `meta.schema_version` remains the DB migration version.
5. Readers (`replay`, `analyze`, the integrations) reject records with a newer
   `schema_version` than they understand, with a clear message, and accept older ones.

## Alternatives considered

- **Lenient event models (ignore unknown fields).** Hides real bugs and lets semantics drift
  silently. Rejected; the strict decoder stays, and the explicit version check makes skew
  loud.
- **Use the sensor semver as the protocol version.** Ties the protocol to unrelated release
  numbering. Rejected.

## Consequences

- A mismatched install fails at startup instead of running blind.
- Every protocol change needs a version bump and a test update; a test asserts that
  `protocol.h` and the engine's supported version match.

## Kernel-version notes

None.

## Tests

- Protocol tests against the fake sensor: a missing `protocol` is refused; an unsupported
  `protocol` is refused with exit code 3; a burst of malformed lines raises the ERROR and
  the blind-spot record once; the per-line warning is rate-limited.
- Unit: stored events and alerts carry `schema_version`; readers reject newer versions.
