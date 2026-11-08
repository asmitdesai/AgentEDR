"""Thread-group-aware EXIT (ADR 0001) and the EVA-001/EVA-002 evasions.

The fake agent is a copy of the system python3 named after the `claude`
matcher, so the kernel exec hook tags it as a new session root and it can be
multi-threaded itself. Cases 1 to 3 run the threaded program as a child of the
root (as in the original reproduction); cases 4, (f) and (g) make the root
itself multi-threaded.

Every case asserts that EXIT fires exactly once per process. After the
expected EXIT arrives, the tests wait a short grace period so that a duplicate
EXIT, if the sensor emitted one, would also have arrived.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import textwrap
from pathlib import Path

import pytest

from agentedr.cli import _SessionPrinter
from agentedr.models import Event, ExecEvent, ExitEvent

from ._harness import EVASIONS, make_config, running_sensor, wait_for

pytestmark = pytest.mark.integration

SYSTEM_PYTHON = Path(os.path.realpath("/usr/bin/python3"))
GRACE_S = 0.5

# Guard used by the multi-threaded root scripts: prove (from the kernel's
# point of view) that the main thread and at least two workers are alive.
THREADS_GUARD = textwrap.dedent("""
    import os, sys, threading
    stop = threading.Event()
    for _ in range(2):
        threading.Thread(target=stop.wait, daemon=True).start()
    if len(os.listdir("/proc/self/task")) < 3:
        os._exit(99)
""")


@pytest.fixture
def fake_agent(tmp_path: Path) -> Path:
    agent = tmp_path / "claude"
    shutil.copy(SYSTEM_PYTHON, agent)
    return agent


def _exits(events: list[Event], pid: int) -> list[ExitEvent]:
    return [e for e in events if isinstance(e, ExitEvent) and e.pid == pid]


def _root_session(events: list[Event], root_pid: int) -> int:
    starts = [e for e in events if isinstance(e, ExecEvent) and e.session_start]
    root = [e for e in starts if e.pid == root_pid]
    assert len(root) == 1, starts
    return root[0].session_id


def _marker_execs(events: list[Event], marker: str) -> list[ExecEvent]:
    return [e for e in events if isinstance(e, ExecEvent) and marker in e.argv[1:2]]


async def _run_agent(
    tmp_path: Path, fake_agent: Path, *args: str
) -> tuple[list[Event], int, int | None]:
    """Run the fake agent to completion under the sensor.

    Returns the events, the root pid, and the root's exit status as seen by
    the parent (negative for a signal).
    """
    events: list[Event] = []
    async with running_sensor(make_config(tmp_path), events.append):
        agent = await asyncio.create_subprocess_exec(str(fake_agent), *args)
        status = await agent.wait()
        await wait_for(lambda evs: bool(_exits(evs, agent.pid)), events)
        await asyncio.sleep(GRACE_S)
    return events, agent.pid, status


def _child_runner(script: Path, *script_args: str) -> list[str]:
    """Agent arguments that run `script` in a child python3 and wait for it."""
    argv = [str(SYSTEM_PYTHON), str(script), *script_args]
    return ["-c", f"import subprocess; subprocess.run({argv!r}, check=False)"]


# ------------------------------------------------- cases 1 to 3 (child process)


async def _run_child_case(
    tmp_path: Path, fake_agent: Path, script: Path, *script_args: str
) -> tuple[list[Event], int, ExecEvent]:
    events, root_pid, _ = await _run_agent(
        tmp_path, fake_agent, *_child_runner(script, *script_args)
    )
    session = _root_session(events, root_pid)
    child = [
        e
        for e in events
        if isinstance(e, ExecEvent) and e.ppid == root_pid and str(script) in e.argv
    ]
    assert len(child) == 1, child
    assert child[0].session_id == session
    return events, session, child[0]


async def test_case1_exec_from_worker_thread(tmp_path: Path, fake_agent: Path) -> None:
    """EVA-001: the new image and its child keep the session."""
    script = EVASIONS / "EVA-001" / "eva.py"
    events, session, child = await _run_child_case(tmp_path, fake_agent, script)

    new_image = [
        e for e in events if isinstance(e, ExecEvent) and e.pid == child.pid and e.comm == "sh"
    ]
    assert len(new_image) == 1 and new_image[0].session_id == session
    for marker in ("eva001_exec_marker", "eva001_child_marker"):
        hits = _marker_execs(events, marker)
        assert hits and all(e.session_id == session for e in hits), marker

    # The old main thread's death during exec is not a process exit.
    exits = _exits(events, child.pid)
    assert len(exits) == 1
    assert exits[0].exit_code == 0 and not exits[0].is_root


async def test_case2_main_thread_exits_first(tmp_path: Path, fake_agent: Path) -> None:
    """EVA-002: the worker's activity is tagged; one EXIT, after it."""
    script = EVASIONS / "EVA-002" / "eva.py"
    events, session, child = await _run_child_case(tmp_path, fake_agent, script)

    markers = _marker_execs(events, "eva002_marker")
    assert markers and all(e.session_id == session for e in markers)
    exits = _exits(events, child.pid)
    assert len(exits) == 1
    assert exits[0].pid == child.pid  # pid is the tgid even if a worker died last
    assert exits[0].ts_ns > max(e.ts_ns for e in markers)
    assert exits[0].exit_code == 0 and not exits[0].is_root


async def test_case3_worker_exit_group_code(tmp_path: Path, fake_agent: Path) -> None:
    script = EVASIONS / "EVA-002" / "eva.py"
    events, _, child = await _run_child_case(tmp_path, fake_agent, script, "5")

    exits = _exits(events, child.pid)
    assert len(exits) == 1
    assert exits[0].exit_code == 5


# -------------------------------------------- cases 4, 5, (f), (g) (the root)


async def test_case4_root_main_first_session_ends_once(
    tmp_path: Path, fake_agent: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Root exits main-thread-first: one is_root EXIT and one session end."""
    events: list[Event] = []
    config = make_config(tmp_path)
    printer = _SessionPrinter(config, show_events=False)

    def on_event(ev: Event) -> None:
        events.append(ev)
        printer(ev)

    script = EVASIONS / "EVA-002" / "eva.py"
    async with running_sensor(config, on_event):
        agent = await asyncio.create_subprocess_exec(str(fake_agent), str(script))
        await agent.wait()
        await wait_for(lambda evs: bool(_exits(evs, agent.pid)), events)
        await asyncio.sleep(GRACE_S)

    session = _root_session(events, agent.pid)
    markers = _marker_execs(events, "eva002_marker")
    assert markers and all(e.session_id == session for e in markers)
    exits = _exits(events, agent.pid)
    assert len(exits) == 1 and exits[0].is_root and exits[0].exit_code == 0
    out = capsys.readouterr().out
    assert out.count("SESSION START") == 1
    assert out.count("SESSION END") == 1


async def test_case5_single_threaded_exit_unchanged(tmp_path: Path, fake_agent: Path) -> None:
    events, root_pid, status = await _run_agent(
        tmp_path, fake_agent, "-c", "import sys; sys.exit(4)"
    )
    assert status == 4
    exits = _exits(events, root_pid)
    assert len(exits) == 1
    assert exits[0].is_root and exits[0].exit_code == 4
    assert exits[0].tid == root_pid
    assert exits[0].session_id == _root_session(events, root_pid)


@pytest.mark.parametrize("exit_call", ["sys.exit(3)", "os._exit(3)"])
async def test_case_f_multithreaded_normal_exit(
    tmp_path: Path, fake_agent: Path, exit_call: str
) -> None:
    """Main thread exits with 3 while two workers are alive: one EXIT, code 3.

    The workers are torn down by the group exit. The status must be the
    group's (3), not the SIGKILL-style 137 a dying worker could report.
    """
    events, root_pid, status = await _run_agent(
        tmp_path, fake_agent, "-c", THREADS_GUARD + exit_call + "\n"
    )
    assert status == 3, "the guard failed or the script did not run"
    exits = _exits(events, root_pid)
    assert len(exits) == 1
    assert exits[0].is_root and exits[0].exit_code == 3


async def test_case_g_multithreaded_root_sigkill(tmp_path: Path, fake_agent: Path) -> None:
    """Session root with two workers is killed from outside: one EXIT, 137."""
    events: list[Event] = []
    script = THREADS_GUARD + "print('ready', flush=True)\nstop.wait()\n"
    async with running_sensor(make_config(tmp_path), events.append):
        agent = await asyncio.create_subprocess_exec(
            str(fake_agent), "-c", script, stdout=asyncio.subprocess.PIPE
        )
        assert agent.stdout is not None
        line = await asyncio.wait_for(agent.stdout.readline(), 5.0)
        assert line.strip() == b"ready"
        os.kill(agent.pid, signal.SIGKILL)
        assert await agent.wait() == -signal.SIGKILL
        await wait_for(lambda evs: bool(_exits(evs, agent.pid)), events)
        await asyncio.sleep(GRACE_S)

    exits = _exits(events, agent.pid)
    assert len(exits) == 1
    assert exits[0].is_root and exits[0].exit_code == 137
