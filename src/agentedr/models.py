"""Pydantic models for sensor protocol lines (SPEC sections 7 and 8).

M0 covers the control lines and the EXEC / EXIT events. The remaining event
types are added in M1.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class _Line(BaseModel):
    # The sensor is ours: unexpected fields mean a protocol mismatch, so reject.
    model_config = ConfigDict(extra="forbid", frozen=True)


# ----------------------------------------------------------- control lines


class ReadyLine(_Line):
    type: Literal["READY"]
    version: str
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


# ------------------------------------------------------------------ events


class EventBase(_Line):
    ts_ns: int = Field(ge=0)
    pid: int = Field(ge=0)
    tid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    uid: int = Field(ge=0)
    session_id: int = Field(ge=0)
    agent_kind: int = Field(ge=0)
    comm: str


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
