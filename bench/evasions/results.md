# Evasion corpus results

Each `EVA-NNN/` directory holds a script (`eva.py`) and its expected result
(`expected`: `caught`, or `xfail` with the limitation it documents). The
scripts are driven from `tests/integration/` and run in the VMs. Known misses
stay listed as `xfail`; entries are never removed.

| ID | Evasion | Expected | Ubuntu 24.04 (6.8) | Ubuntu 22.04 (5.15) |
|---|---|---|---|---|
| EVA-001 | exec from a worker thread (ADR 0001) | caught | see below | see below |
| EVA-002 | main thread exits first, worker continues (ADR 0001) | caught | see below | see below |
