# ADR 0021: Redaction and raw recording policy

Status: Accepted (2026-11-07)
Milestone: M1a
Related: common token formats missing from redaction, and raw recordings written unredacted; decision N9; SPEC 9.7, 10 (`record_raw`), 15, 17.5, gotcha 15

## Context

AgentEDR records argv, paths and environment-like strings from agent sessions. Secrets
appear in argv (`curl -H "Authorization: ..."`, `mysql -pSECRET`), in URLs and in
environment assignments. SPEC 9.7 defines eight patterns and applies them to events and
alerts. Gaps:

- Common token formats are missing: Stripe `sk_live_` and `rk_live_`, Slack `xox?-`, Google
  `AIza...`, JWTs, npm `npm_`, GitLab `glpat-`, Vault `hvs.`. Password argv forms
  (`-pSECRET`, `--password=`) and API key headers other than Bearer (`x-api-key:`,
  `api-key:`) are missing too.
- Raw recordings (`--record`) are written unredacted, with no stated file policy.
- Untagged candidate EXECs carry the argv of every `node`, `python3` and `env` on the host,
  for every user including root, into the engine. They are not part of any agent session.
- The `/proc` adoption scan (ADR 0003) reads every process's cmdline.
- Sensor stderr and the daemon log could carry event content.

## Decision

1. **Pattern set.** SPEC 9.7 is extended with the formats above, each as a named kind. All
   patterns:
   - are linear-time (no nested quantifiers);
   - are applied to strings of at most 64 KiB (the line limit);
   - replace only the secret part, keeping context such as the header name or flag;
   - use the placeholder `[REDACTED:<kind>]`, which no pattern can match.

   `--password=`, `--passwd=` and all token patterns apply globally. The short form
   `-p<value>` does not: globally it would destroy port numbers that egress rules use as
   evidence (`ssh -p2222`) and corrupt ordinary flags (`mkdir -p`, `cp -p`, `git log -p`). It
   is a separate kind, `password_short_flag`, applied only to argv arrays whose `argv[0]`
   basename is `mysql`, `mysqldump`, `mariadb`, `mariadb-dump` or `sshpass`, and only to an
   argv element that starts with `-p` followed by a value.

   The separate-argument form is a second argv-scoped kind, `sshpass_password_arg`: when
   the basename of `argv[0]` is `sshpass`, the element after a lone `-p` is redacted
   (`sshpass -p VALUE ssh host`). It applies to `sshpass` only. For `mysql` and `mariadb` a
   lone `-p` means "prompt for the password", and the next element is a database name, not
   a secret. Added in M1a with the rest of redaction.
2. **Never redacted:** rule ids, IP addresses, and paths of credential files (the path is
   evidence). Tests assert that no pattern matches representative credential paths.
3. **Coverage.** Redaction applies to:
   - every string field of events, alerts, session `root_argv`, and stored and exported
     records;
   - daemon log records, through a `logging.Filter` on all handlers;
   - forwarded sensor stderr lines.
   CLI output reads already-redacted stored data.
4. **High-entropy detector.** Optional, off by default (`redaction.entropy: false`). It
   flags tokens of at least 24 base64url or hex characters with Shannon entropy above 4.0,
   excluding exactly 40- or 64-character hex strings (git SHAs, SHA-256 digests). The FP
   trade-off (hashes, IDs and file names get redacted) is documented in `docs/rules.md`.
5. **Raw recordings are redacted by default.** The redactor is applied to every string value
   of each raw JSON line with the structure preserved, so `analyze` replays keep working.
   - `--record-unredacted` exists for local debugging only: it prints a warning on start and
     writes with mode 0600 under ADR 0012 rules. It is never a config option.
   - Benchmark recordings committed to the repository must be redacted recordings.
6. **Untagged EXEC privacy.** Untagged candidate EXECs are used only for argv matching and
   then dropped. They are never stored in events, SQLite or the daemon log, and are excluded
   from raw recordings unless `--record-untagged` is given (still redacted). Tagger log lines
   carry the pid and the matched pattern, never argv.
7. **Adoption scan privacy.** Cmdlines read by the scan are used only for matching; nothing
   is kept for non-matching processes.

## Alternatives considered

- **Unredacted raw recordings with a warning.** Raw recordings are exactly what people share
  in bug reports and benchmark contributions. Rejected as the default.
- **Entropy detection on by default.** Too many false redactions of hashes and identifiers,
  which hurts replay readability. Rejected as the default.

## Consequences

- `analyze` on a redacted recording cannot see secret values. No rule needs them.
- A redaction bug can still leak. This is why the coverage tests below are part of the
  quality bar, and why integrations (OCSF, Wazuh) only ship already-redacted records.

## Kernel-version notes

None.

## Tests

- Unit, per kind: positive, negative and boundary cases (token too short, adjacent
  punctuation, embedded in a URL or JSON).
- Unit, `password_short_flag`: redacted for `mysql -pSECRET`, `/usr/bin/mysqldump -pSECRET`,
  `mariadb -pSECRET`, `mariadb-dump -pSECRET` and `sshpass -pSECRET`; unchanged for
  `ssh -p2222 host`, `mkdir -p dir`, `cp -p a b` and `git log -p`; unchanged when the same
  text appears in a free-text field rather than an argv array.
- Unit, `sshpass_password_arg`: `sshpass -p VALUE ssh host` has `VALUE` redacted and the
  rest unchanged; `mysql -p dbname` and `ssh -p 2222 host` are unchanged.
- Property tests (Hypothesis, approved as a dev dependency in decision N9):
  - idempotence: `redact(redact(x)) == redact(x)`;
  - placeholders never re-match;
  - a random credential path is unchanged;
  - redaction of a 64 KiB adversarial string finishes within a time budget.
- Unit: the logging filter redacts formatted messages; untagged EXECs never reach storage;
  `--record` output contains no planted fake canary token.
