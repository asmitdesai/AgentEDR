"""Supervisor <-> sensor protocol tests against tests/protocol/fake_sensor.py."""

from __future__ import annotations

import logging
import os
import shlex
import stat
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from agentedr.config import Config, load_config
from agentedr.models import Event, ExecEvent, ExitEvent
from agentedr.supervisor import SensorError, Supervisor

FAKE_SENSOR = Path(__file__).with_name("fake_sensor.py")

MakeSupervisor = Callable[..., tuple[Supervisor, list[Event]]]


@pytest.fixture
def make_supervisor(tmp_path: Path) -> MakeSupervisor:
    """Build a Supervisor whose sensor binary is the fake sensor with extra flags."""

    def _make(*flags: str, ready_timeout: float = 5.0) -> tuple[Supervisor, list[Event]]:
        wrapper = tmp_path / "agentedr-sensor-fake"
        cmd = shlex.join([sys.executable, str(FAKE_SENSOR), *flags])
        wrapper.write_text(f'#!/bin/sh\nexec {cmd} "$@"\n')
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(f"sensor:\n  binary: {wrapper}\n")
        config: Config = load_config(cfg_file)
        events: list[Event] = []
        sup = Supervisor(
            config, events.append, allow_nonroot=True, ready_timeout=ready_timeout, ack_timeout=5.0
        )
        return sup, events

    return _make


async def test_ready_handshake_and_matchers(make_supervisor: MakeSupervisor) -> None:
    sup, _ = make_supervisor()
    ready = await sup.start()
    assert ready.mode == "fentry"
    assert ready.kernel == "6.8.0-fake"
    await sup.ping()
    assert await sup.stop() == 0


async def test_events_are_decoded_and_delivered(make_supervisor: MakeSupervisor) -> None:
    sup, events = make_supervisor("--events")
    await sup.start()
    await sup.ping()  # PONG arrives after the events, so they have been dispatched
    await sup.stop()

    assert [e.type for e in events] == ["EXEC", "EXEC", "EXIT"]
    start, child, end = events
    assert isinstance(start, ExecEvent) and start.session_start
    assert isinstance(child, ExecEvent) and child.session_id == start.session_id
    assert child.argv == ["git", "status"]
    assert isinstance(end, ExitEvent) and end.is_root


async def test_malformed_lines_are_counted_not_fatal(make_supervisor: MakeSupervisor) -> None:
    sup, events = make_supervisor("--garbage", "--events")
    await sup.start()
    await sup.ping()
    await sup.stop()

    assert sup.decoder.malformed == 4
    assert len(events) == 3


async def test_unknown_command_gets_negative_ack(make_supervisor: MakeSupervisor) -> None:
    sup, _ = make_supervisor()
    await sup.start()
    ack = await sup.send("FROBNICATE 1")
    assert not ack.ok
    assert ack.cmd == "FROBNICATE"
    await sup.stop()


async def test_rejected_matchers_fail_start(make_supervisor: MakeSupervisor) -> None:
    sup, _ = make_supervisor("--reject-matchers")
    with pytest.raises(SensorError, match="SET_MATCHERS"):
        await sup.start()


async def test_sensor_failure_reports_stderr_and_exit_code(
    make_supervisor: MakeSupervisor,
) -> None:
    sup, _ = make_supervisor("--fail", "4")
    with pytest.raises(SensorError) as info:
        await sup.start()
    msg = str(info.value)
    assert "exit code 4" in msg
    assert "BPF program load failed" in msg


async def test_ready_timeout(make_supervisor: MakeSupervisor) -> None:
    sup, _ = make_supervisor("--no-ready", ready_timeout=0.5)
    with pytest.raises(SensorError, match="timed out waiting for READY"):
        await sup.start()
    assert sup.returncode is not None


async def test_stderr_is_forwarded_to_log(
    make_supervisor: MakeSupervisor, caplog: pytest.LogCaptureFixture
) -> None:
    sup, _ = make_supervisor()
    with caplog.at_level(logging.WARNING, logger="agentedr.sensor"):
        await sup.start()
        await sup.stop()
    assert any("fake-sensor: starting" in r.getMessage() for r in caplog.records)


async def test_ringbuf_drops_are_logged(
    make_supervisor: MakeSupervisor, caplog: pytest.LogCaptureFixture
) -> None:
    sup, _ = make_supervisor("--drops")
    with caplog.at_level(logging.WARNING):
        await sup.start()
        await sup.ping()
        await sup.stop()
    assert sup.stats is not None and sup.stats.ringbuf_drops == 5
    assert any("dropped 5 event(s)" in r.getMessage() for r in caplog.records)


async def test_stop_escalates_when_sensor_ignores_eof(
    make_supervisor: MakeSupervisor, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentedr.supervisor.STOP_TIMEOUT_S", 0.5)
    sup, _ = make_supervisor("--ignore-eof")
    await sup.start()
    code = await sup.stop()
    assert code is not None and code != 0


async def test_requires_root_unless_allowed(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("running as root")
    sup = Supervisor(load_config(None), lambda e: None)
    with pytest.raises(SensorError, match="root"):
        await sup.start()
