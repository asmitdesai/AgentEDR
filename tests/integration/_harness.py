"""Shared helpers for the sensor integration tests (SPEC 16.2).

Importing this module skips the importing test module unless the tests can
really load BPF: Linux, root, kernel BTF and a built sensor. Run the tests with
`make vm-test`, optionally with `MODE=lsm` or `MODE=fentry`.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from agentedr.config import Config, load_config
from agentedr.models import Event
from agentedr.supervisor import Supervisor, bundled_sensor_path

REPO = Path(__file__).resolve().parents[2]
EVASIONS = REPO / "bench" / "evasions"

# Sensor mode for this run: auto | lsm | fentry (Makefile MODE=...).
MODE = os.environ.get("AGENTEDR_TEST_MODE", "auto")


# `make vm-test` installs this machine's own build here right before the tests.
_BUNDLED = bundled_sensor_path()
SENSOR = _BUNDLED if _BUNDLED.is_file() else None

if not sys.platform.startswith("linux"):
    pytest.skip("Linux only", allow_module_level=True)
if os.geteuid() != 0:
    pytest.skip("needs root to load BPF programs", allow_module_level=True)
if not Path("/sys/kernel/btf/vmlinux").exists():
    pytest.skip("kernel BTF not available", allow_module_level=True)
if SENSOR is None:
    pytest.skip("sensor not built (make sensor)", allow_module_level=True)


def make_config(tmp_path: Path) -> Config:
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"sensor:\n  binary: {SENSOR}\n  stats_interval_s: 1\n")
    return load_config(cfg_file)


@asynccontextmanager
async def running_sensor(
    config: Config, on_event: Callable[[Event], None]
) -> AsyncIterator[Supervisor]:
    """Start the sensor in MODE, yield the supervisor, and stop it cleanly."""
    sup = Supervisor(config, on_event, mode=MODE)
    ready = await sup.start()
    if MODE != "auto":
        assert ready.mode == MODE, f"requested {MODE}, sensor runs in {ready.mode}"
    try:
        yield sup
    finally:
        assert await sup.stop() == 0
    assert sup.decoder.malformed == 0


async def wait_for(
    pred: Callable[[list[Event]], bool], events: list[Event], timeout: float = 5.0
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not pred(events):
        if asyncio.get_running_loop().time() > deadline:
            pytest.fail(f"timed out; got {len(events)} events: {events!r}")
        await asyncio.sleep(0.05)
