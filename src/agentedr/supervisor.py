"""Sensor process supervision and protocol I/O (SPEC 9.3).

M0 scope: start the sensor, wait for READY, push agent matchers, stream
decoded events to a callback, forward stderr to the log, stop cleanly.
Restart with backoff arrives in M1.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import logging
import os
import platform
from collections.abc import Callable
from importlib import resources
from pathlib import Path

from agentedr.config import Config
from agentedr.decoder import MAX_LINE_BYTES, Decoder
from agentedr.models import (
    AckLine,
    ByeLine,
    Event,
    PongLine,
    ReadyLine,
    StatsLine,
)

log = logging.getLogger(__name__)
sensor_log = logging.getLogger("agentedr.sensor")

READY_TIMEOUT_S = 10.0
ACK_TIMEOUT_S = 5.0
STOP_TIMEOUT_S = 5.0
STDERR_TAIL_LINES = 50

EventHandler = Callable[[Event], None]


class SensorError(Exception):
    """The sensor could not be started or stopped responding."""


def bundled_sensor_path() -> Path:
    """Path of the sensor binary shipped inside the package for this machine."""
    name = f"agentedr-sensor-{platform.machine()}"
    return Path(str(resources.files("agentedr").joinpath("_bin", name)))


def locate_sensor(config: Config) -> Path:
    path = config.sensor.binary or bundled_sensor_path()
    if not path.is_file():
        raise SensorError(f"sensor binary not found: {path} (run `make sensor`)")
    if not os.access(path, os.X_OK):
        raise SensorError(f"sensor binary is not executable: {path}")
    return path


class Supervisor:
    def __init__(
        self,
        config: Config,
        on_event: EventHandler,
        *,
        mode: str | None = None,
        allow_nonroot: bool = False,
        ready_timeout: float = READY_TIMEOUT_S,
        ack_timeout: float = ACK_TIMEOUT_S,
    ) -> None:
        self.config = config
        self.on_event = on_event
        self.mode = mode or config.sensor.mode
        self.allow_nonroot = allow_nonroot
        self.ready_timeout = ready_timeout
        self.ack_timeout = ack_timeout

        self.decoder = Decoder()
        self.ready: ReadyLine | None = None
        self.stats: StatsLine | None = None
        self.stderr_tail: collections.deque[str] = collections.deque(maxlen=STDERR_TAIL_LINES)

        self._proc: asyncio.subprocess.Process | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._ready_fut: asyncio.Future[ReadyLine] | None = None
        # The sensor answers commands strictly in order, so a FIFO is enough
        # to pair each ACK / PONG with the command that caused it.
        self._pending_acks: collections.deque[asyncio.Future[AckLine]] = collections.deque()
        self._pending_pongs: collections.deque[asyncio.Future[None]] = collections.deque()
        self._exited = asyncio.Event()

    @property
    def returncode(self) -> int | None:
        """Sensor exit code, or None while it is running (or never started)."""
        return self._proc.returncode if self._proc else None

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> ReadyLine:
        if os.geteuid() != 0 and not self.allow_nonroot:
            raise SensorError("agentedr must run as root (or pass --allow-nonroot)")
        binary = locate_sensor(self.config)
        args = [
            str(binary),
            "--mode", self.mode,
            "--ringbuf-kib", str(self.config.sensor.ringbuf_kib),
            "--stats-interval", str(self.config.sensor.stats_interval_s),
        ]  # fmt: skip
        log.info("starting sensor: %s", " ".join(args))
        self._ready_fut = asyncio.get_running_loop().create_future()
        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # Allow lines somewhat over the decoder limit so they reach the
            # decoder and are counted as malformed instead of aborting reads.
            limit=MAX_LINE_BYTES * 2,
        )
        self._tasks = [
            asyncio.create_task(self._read_stdout(), name="sensor-stdout"),
            asyncio.create_task(self._read_stderr(), name="sensor-stderr"),
        ]

        try:
            self.ready = await asyncio.wait_for(self._ready_fut, self.ready_timeout)
        except (TimeoutError, SensorError) as exc:
            code = await self._kill()
            tail = "\n".join(self.stderr_tail) or "(no stderr output)"
            reason = "timed out waiting for READY" if isinstance(exc, TimeoutError) else str(exc)
            msg = f"sensor failed to start ({reason}, exit code {code}):\n{tail}"
            raise SensorError(msg) from exc
        log.info(
            "sensor ready: version=%s mode=%s kernel=%s",
            self.ready.version, self.ready.mode, self.ready.kernel,
        )  # fmt: skip

        ack = await self.send("SET_MATCHERS " + json.dumps(self.config.kernel_matchers()))
        if not ack.ok:
            await self.stop()
            raise SensorError(f"sensor rejected SET_MATCHERS: {ack.error}")
        return self.ready

    async def wait(self) -> int | None:
        """Wait until the sensor process exits and return its exit code."""
        await self._exited.wait()
        return self.returncode

    async def stop(self) -> int | None:
        """Ask the sensor to exit (stdin EOF), escalating to SIGTERM/SIGKILL."""
        proc = self._proc
        if proc is None:
            return None
        if proc.returncode is None and proc.stdin is not None:
            with contextlib.suppress(ConnectionError, RuntimeError):
                proc.stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), STOP_TIMEOUT_S)
            except TimeoutError:
                log.warning("sensor did not exit on stdin EOF; sending SIGTERM")
                return await self._kill()
        await self._join_tasks()
        return proc.returncode

    async def _kill(self) -> int | None:
        proc = self._proc
        if proc is None:
            return None
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 2.0)
            except TimeoutError:
                proc.kill()
                await proc.wait()
        await self._join_tasks()
        return proc.returncode

    async def _join_tasks(self) -> None:
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(task, 2.0)

    # ------------------------------------------------------------- commands

    async def send(self, command: str) -> AckLine:
        """Send one command and wait for its ACK."""
        fut: asyncio.Future[AckLine] = asyncio.get_running_loop().create_future()
        self._pending_acks.append(fut)
        await self._write(command)
        try:
            return await asyncio.wait_for(fut, self.ack_timeout)
        except TimeoutError as exc:
            raise SensorError(f"no ACK for {command.split(' ', 1)[0]}") from exc

    async def ping(self) -> None:
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._pending_pongs.append(fut)
        await self._write("PING")
        try:
            await asyncio.wait_for(fut, self.ack_timeout)
        except TimeoutError as exc:
            raise SensorError("no PONG") from exc

    async def _write(self, command: str) -> None:
        if self._proc is None or self._proc.stdin is None or self._proc.returncode is not None:
            raise SensorError("sensor is not running")
        self._proc.stdin.write(command.encode() + b"\n")
        try:
            await self._proc.stdin.drain()
        except ConnectionError as exc:
            raise SensorError("sensor stdin closed") from exc

    # -------------------------------------------------------------- readers

    async def _read_stdout(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        stdout = self._proc.stdout
        try:
            while True:
                try:
                    line = await stdout.readline()
                except ValueError:
                    # Over the StreamReader limit; asyncio already dropped it.
                    self.decoder.reject("line exceeds reader limit")
                    continue
                if not line:
                    break
                self._dispatch(line)
        finally:
            await self._proc.wait()
            self._fail_pending(SensorError(f"sensor exited with code {self._proc.returncode}"))
            self._exited.set()

    def _dispatch(self, line: bytes) -> None:
        msg = self.decoder.parse(line)
        if msg is None:
            return
        if isinstance(msg, ReadyLine):
            if self._ready_fut is not None and not self._ready_fut.done():
                self._ready_fut.set_result(msg)
        elif isinstance(msg, AckLine):
            if self._pending_acks:
                fut = self._pending_acks.popleft()
                if not fut.done():
                    fut.set_result(msg)
            else:
                log.warning("unexpected ACK for %s", msg.cmd)
        elif isinstance(msg, PongLine):
            if self._pending_pongs:
                pong = self._pending_pongs.popleft()
                if not pong.done():
                    pong.set_result(None)
        elif isinstance(msg, StatsLine):
            self._on_stats(msg)
        elif isinstance(msg, ByeLine):
            log.info("sensor said BYE")
        else:
            try:
                self.on_event(msg)
            except Exception:
                # A handler bug must not stop the event stream.
                log.exception("event handler failed")

    def _on_stats(self, stats: StatsLine) -> None:
        prev = self.stats
        if prev is not None and stats.ringbuf_drops > prev.ringbuf_drops:
            log.warning(
                "sensor ring buffer dropped %d event(s) (total %d)",
                stats.ringbuf_drops - prev.ringbuf_drops, stats.ringbuf_drops,
            )  # fmt: skip
        if prev is not None and stats.tag_map_full > prev.tag_map_full:
            log.warning("sensor agent_pids map full; %d tag(s) lost", stats.tag_map_full)
        self.stats = stats

    async def _read_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        stderr = self._proc.stderr
        while True:
            try:
                raw = await stderr.readline()
            except ValueError:
                continue
            if not raw:
                return
            text = raw.decode("utf-8", "replace").rstrip()
            self.stderr_tail.append(text)
            sensor_log.warning("%s", text)

    def _fail_pending(self, exc: Exception) -> None:
        if self._ready_fut is not None and not self._ready_fut.done():
            self._ready_fut.set_exception(exc)
        pending: list[asyncio.Future[AckLine] | asyncio.Future[None]] = [
            *self._pending_acks,
            *self._pending_pongs,
        ]
        for fut in pending:
            if not fut.done():
                fut.set_exception(exc)
        self._pending_acks.clear()
        self._pending_pongs.clear()
