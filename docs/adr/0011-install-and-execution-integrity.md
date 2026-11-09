# ADR 0011: Install and execution integrity

Status: Accepted (2026-11-07); dev escape hatch amended 2026-11-08 (SPEC 22 decision 9)
Milestone: M1a (self-check, sensor hash); M3 (install script, release)
Related: a user-writable install run as root is a privilege escalation; sensor binary integrity; decision N1; SPEC 1.1 G4, 5, 9.3, 14, 15

## Context

AgentEDR runs as root. SPEC G4 promised `pip install agentedr` or `uv tool install agentedr`.
Both put the engine and the bundled sensor in locations owned by the user. The agent runs as
that user, so a hijacked agent can edit the installed Python code or replace the sensor
binary, and the next `sudo agentedr run` executes the modified code as root.

That is both a local privilege escalation and a trivial way to blind AgentEDR. A SHA-256
check of the sensor does not help on its own: the Python code that performs the check is
equally writable. `sudo` also hides `~/.local/bin` (`secure_path`), so users would type
`sudo $(which agentedr)`, which is exactly the unsafe path. The README quickstart today runs
`sudo .venv/bin/agentedr run --dev` from a user-owned checkout.

## Decision

### Supported install

1. The supported install is a root-owned virtual environment at `/opt/agentedr`, created by
   a documented install script (`deploy/install.sh`, M3) run as root. The script:
   1. provides Python 3.11+. Ubuntu 24.04's system Python (3.12) is used as is. Ubuntu
      22.04 ships Python 3.10, which is below the engine's minimum, so on 22.04 the script
      installs a root-owned Python 3.11+ under `/opt/agentedr` (for example a pinned,
      hash-verified standalone CPython build) and creates the venv from it. It never
      upgrades or replaces the system Python. The interpreter it provides is covered by
      the self-check in step 3 like any other;
   2. creates `/opt/agentedr` (root:root, 0755) and a venv in `/opt/agentedr/venv`;
   3. installs a pinned AgentEDR version from PyPI with `pip install --require-hashes`
      against a published, hash-pinned requirements file;
   4. installs a root-owned launcher at `/usr/local/bin/agentedr`:
      `exec /opt/agentedr/venv/bin/python -I -m agentedr "$@"`. `-I` (isolated mode)
      ignores `PYTHON*` environment variables and the user site directory.
2. G4 is rewritten:

   > Install with one documented command into a root-owned location, on Ubuntu 22.04 and
   > 24.04, without compilers or kernel headers. User-writable installs (`pip install
   > --user`, `uv tool install`, a project venv) are not supported for running as root and
   > are refused at startup.

### Startup self-check

3. When the engine runs with euid 0, before loading config or starting the sensor, it
   refuses to start unless all of the following are owned by root and not writable by group
   or other:
   - the interpreter: `sys.executable`, its resolved real path, and every parent directory
     up to `/`;
   - the package: every directory and file under the directory containing the `agentedr`
     package, and every existing `sys.path` entry with all their files (`.pth` files
     included);
   - the sensor: the binary, its directory and parents.

   The error message names the first offending path and points to the supported install.
4. When running as root, the engine also requires `sys.flags.isolated` to be set, or
   `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP` and `PYTHONINSPECT` to be absent.
5. **Dev escape hatch (SPEC 22 decision 9, approved 2026-11-08).** A flag
   `--allow-unsafe-install` turns the refusals in steps 3 and 4 into a warning. Constraints:
   1. It is a command-line flag only. It is never a config key, and the config loader
      rejects any key with that name.
   2. It is rejected (usage error, exit code 2) unless `--dev` is also set.
   3. The checks in steps 3 and 4 still run. The engine logs one WARNING at startup naming
      every user-writable path it found, not only the first.
   4. Every session and every alert produced by that engine run carries
      `integrity: "unverified"` (otherwise `"verified"`), stored in SQLite and shown by
      `status`, `sessions` and `replay`.
   5. `deploy/install.sh` and `deploy/agentedr.service` never pass it. A unit test fails if
      any file under `deploy/` contains the string `allow-unsafe-install`.

### Sensor integrity

6. The wheel ships `_bin/SHA256SUMS`, generated at build time (`make sensor` writes it for
   dev builds).
7. Before starting the sensor, the supervisor:
   1. opens the binary with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`;
   2. `fstat`s it: regular file, owner root, no group or other write;
   3. hashes the open fd and compares the hash with `SHA256SUMS`;
   4. execs `/proc/self/fd/<n>` with the fd passed to the child, so that the binary that
      was checked is the binary that runs (no path TOCTOU).
8. A `sensor.binary` override must pass the same ownership checks. It has no checksum file,
   so the hash step is skipped and a WARNING is logged.

## Alternatives considered

- **Keep user-level installs and drop privileges.** The engine needs root (or the sensor
  capabilities) to start the sensor. A privilege split (ADR 0016, later) reduces what runs
  privileged but still needs a root-owned privileged half. Rejected for v1.
- **Distro packages (.deb).** The strongest option long-term, but more release work.
  Deferred; the venv layout is compatible with a later package.
- **`sudo uv tool install` with root-owned tool directories.** Works, but depends on uv
  being installed for root. Allowed as an alternative documented path as long as it passes
  the self-check.

## Consequences

- An agent running as the user cannot modify code that later runs as root.
- The dev workflow (`sudo .venv/bin/agentedr run --dev`, `make vm-test`) needs
  `--dev --allow-unsafe-install`, or the `Supervisor(allow_unsafe_install=True)` parameter
  in tests. The README quickstart is updated to say so.
- Data from a dev run is always distinguishable from a verified install by the `integrity`
  field, so a dev recording cannot be mistaken for production evidence.
- The self-check walks a few thousand files at startup (tens of ms; measured in M1a).

## Kernel-version notes

None.

## Tests

- Unit, with an injected `stat` function: every refusal condition (group- or world-writable
  file, non-root owner, writable parent directory, `.pth` file in a writable `sys.path`
  entry, missing isolation); `SHA256SUMS` mismatch; the override path.
- Unit, CLI: `--allow-unsafe-install` without `--dev` exits 2; `allow_unsafe_install` as a
  config key is rejected; with both flags the startup WARNING lists every offending path
  (test with two); sessions and alerts carry `integrity: "unverified"`, and `"verified"`
  without the flag.
- Unit, repo lint: no file under `deploy/` contains `allow-unsafe-install` (passes vacuously
  until `deploy/` exists in M3).
- Integration (VM): a root-owned install passes; a user-owned venv is refused with the
  offending path named; `--dev --allow-unsafe-install` starts with a warning naming every
  offending path.
