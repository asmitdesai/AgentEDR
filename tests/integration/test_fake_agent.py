"""Sensor integration test with a fake agent (SPEC 16.2).

Needs root, Linux with BTF, and a built sensor (`make sensor`). Skips cleanly
otherwise. Run with `make vm-test`.

The fake agent is a copy (not a symlink) of /bin/bash named after the
`claude` matcher, so the kernel exec hook tags it as a new session.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from agentedr.config import load_config
from agentedr.models import Event, ExecEvent, ExitEvent
from agentedr.supervisor import Supervisor, bundled_sensor_path

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]


def _sensor_binary() -> Path | None:
    for p in (bundled_sensor_path(), REPO / f"sensor/build/agentedr-sensor-{platform.machine()}"):
        if p.is_file():
            return p
    return None


SENSOR = _sensor_binary()

if not sys.platform.startswith("linux"):
    pytest.skip("Linux only", allow_module_level=True)
if os.geteuid() != 0:
    pytest.skip("needs root to load BPF programs", allow_module_level=True)
if not Path("/sys/kernel/btf/vmlinux").exists():
    pytest.skip("kernel BTF not available", allow_module_level=True)
if SENSOR is None:
    pytest.skip("sensor not built (make sensor)", allow_module_level=True)


async def _wait_for(
    pred: Callable[[list[Event]], bool], events: list[Event], timeout: float = 5.0
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not pred(events):
        if asyncio.get_running_loop().time() > deadline:
            pytest.fail(f"timed out; got {len(events)} events: {events!r}")
        await asyncio.sleep(0.05)


async def test_fake_agent_session(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"sensor:\n  binary: {SENSOR}\n  stats_interval_s: 1\n")
    config = load_config(cfg_file)
    events: list[Event] = []
    sup = Supervisor(config, events.append)
    await sup.start()
    try:
        fake = tmp_path / "claude"
        shutil.copy("/bin/bash", fake)

        # A process outside any agent tree, started by the test itself.
        outsider = await asyncio.create_subprocess_exec("/bin/sleep", "0.2")

        agent = await asyncio.create_subprocess_exec(
            str(fake), "-c", "git --version >/dev/null; cat /etc/hostname >/dev/null; exit 7"
        )
        await agent.wait()
        await outsider.wait()

        root_pid = agent.pid
        await _wait_for(
            lambda evs: any(isinstance(e, ExitEvent) and e.pid == root_pid for e in evs), events
        )
    finally:
        assert await sup.stop() == 0

    starts = [e for e in events if isinstance(e, ExecEvent) and e.session_start]
    root_start = [e for e in starts if e.pid == root_pid]
    assert len(root_start) == 1, starts
    session = root_start[0].session_id
    assert session > 0
    assert config.agent_kind_name(root_start[0].agent_kind) == "claude-code"

    child_execs = {
        e.comm: e for e in events if isinstance(e, ExecEvent) and e.session_id == session
    }
    assert "git" in child_execs and child_execs["git"].argv == ["git", "--version"]
    assert "cat" in child_execs and child_execs["cat"].ppid == root_pid

    root_exit = [e for e in events if isinstance(e, ExitEvent) and e.pid == root_pid]
    assert root_exit[0].is_root and root_exit[0].exit_code == 7
    assert root_exit[0].session_id == session

    assert not [e for e in events if e.pid == outsider.pid], "outsider produced events"
    assert sup.decoder.malformed == 0
