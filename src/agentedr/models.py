"""Pydantic models for sensor protocol lines (SPEC sections 7 and 8).

M0 covers the control lines and the EXEC / EXIT events. The remaining event
types are added in M1.
"""

from __future__ import annotations

import os
from typing import Annotated, Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class _Line(BaseModel):
    # The sensor is ours: unexpected fields mean a protocol mismatch, so reject.
    model_config = ConfigDict(extra="forbid", frozen=True)


# ----------------------------------------------------------- control lines


class ReadyLine(_Line):
    type: Literal["READY"]
    version: str
    protocol: int  # checked leniently before this model is used (ADR 0014)
    mode: Literal["lsm", "fentry"]
    kernel: str
    ringbuf_kib: int


class StatsLine(_Line):
    type: Literal["STATS"]
    ts_ns: int
    ringbuf_drops: int
    tag_map_full: int
    tagged_pids: int
    events_emitted: int


class AckLine(_Line):
    type: Literal["ACK"]
    cmd: str
    ok: bool
    error: str | None = None


class PongLine(_Line):
    type: Literal["PONG"]


class ByeLine(_Line):
    type: Literal["BYE"]


# --------------------------------------------------------- session identity

# Length of one clock tick in ns. /proc/<pid>/stat field 22 (process start
# time) has tick resolution, so a session key rebuilt from /proc can only be
# compared with a key from the kernel at that resolution.
TICK_NS = 1_000_000_000 // os.sysconf("SC_CLK_TCK")


class SessionKey(NamedTuple):
    """Kernel identity of a session: its root process (ADR 0024).

    ``root_start_ns`` is the root's start time on the boot clock, truncated to
    a whole clock tick. The kernel reports nanoseconds; truncating with the
    same division the kernel uses for /proc field 22 means a key rebuilt from
    /proc (adoption after a sensor restart) equals the original key exactly.
    """

    root_tgid: int
    root_start_ns: int


def make_session_key(root_tgid: int, root_start_ns: int) -> SessionKey:
    return SessionKey(root_tgid, root_start_ns // TICK_NS * TICK_NS)


# ------------------------------------------------------------------ events


class EventBase(_Line):
    ts_ns: int = Field(ge=0)
    pid: int = Field(ge=0)
    tid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    uid: int = Field(ge=0)
    session_root_tgid: int = Field(ge=0)  # 0 with start 0: not tagged
    session_root_start_ns: int = Field(ge=0)
    agent_kind: int = Field(ge=0)
    comm: str

    @property
    def session_key(self) -> SessionKey | None:
        """The session this event belongs to, or None if untagged."""
        if self.session_root_tgid == 0:
            return None
        return make_session_key(self.session_root_tgid, self.session_root_start_ns)


class ExecEvent(EventBase):
    type: Literal["EXEC"]
    filename: str
    argv: list[str]
    argv_truncated: bool
    session_start: bool
    untagged: bool


class ExitEvent(EventBase):
    type: Literal["EXIT"]
    exit_code: int
    is_root: bool


Event = ExecEvent | ExitEvent
ControlLine = ReadyLine | StatsLine | AckLine | PongLine | ByeLine
SensorLine = Annotated[Event | ControlLine, Field(discriminator="type")]

SENSOR_LINE_ADAPTER: TypeAdapter[SensorLine] = TypeAdapter(SensorLine)
