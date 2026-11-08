"""Sensor integration test with a fake agent (SPEC 16.2).

Needs root, Linux with BTF, and a built sensor (`make sensor`). Skips cleanly
otherwise. Run with `make vm-test`.

The fake agent is a copy (not a symlink) of /bin/bash named after the
`claude` matcher, so the kernel exec hook tags it as a new session.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from agentedr.models import Event, ExecEvent, ExitEvent

from ._harness import make_config, running_sensor, wait_for

pytestmark = pytest.mark.integration


async def test_fake_agent_session(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    events: list[Event] = []
    async with running_sensor(config, events.append):
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
        await wait_for(
            lambda evs: any(isinstance(e, ExitEvent) and e.pid == root_pid for e in evs), events
        )

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
