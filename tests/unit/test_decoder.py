from __future__ import annotations

import json

import pytest

from agentedr.decoder import MAX_LINE_BYTES, Decoder
from agentedr.models import AckLine, ExecEvent, ExitEvent, ReadyLine, StatsLine

# Example lines from SPEC 7.1 and 8.4.
EXEC_LINE = (
    '{"type":"EXEC","ts_ns":81234567890,"pid":4121,"tid":4121,"ppid":4100,"uid":1000,'
    '"session_id":3,"agent_kind":0,"comm":"cat","filename":"/usr/bin/cat",'
    '"argv":["cat","/home/dev/.aws/credentials"],"argv_truncated":false,'
    '"session_start":false,"untagged":false}'
)
EXIT_LINE = (
    '{"type":"EXIT","ts_ns":81300000000,"pid":4100,"tid":4100,"ppid":1,"uid":1000,'
    '"session_id":3,"agent_kind":0,"comm":"claude","exit_code":0,"is_root":true}'
)


def test_exec() -> None:
    d = Decoder()
    ev = d.parse(EXEC_LINE + "\n")
    assert isinstance(ev, ExecEvent)
    assert ev.argv == ["cat", "/home/dev/.aws/credentials"]
    assert ev.session_id == 3
    assert d.decoded == 1 and d.malformed == 0


def test_exit_from_bytes() -> None:
    ev = Decoder().parse(EXIT_LINE.encode() + b"\n")
    assert isinstance(ev, ExitEvent)
    assert ev.is_root and ev.exit_code == 0


@pytest.mark.parametrize(
    ("line", "cls"),
    [
        ('{"type":"READY","version":"0.1.0","mode":"lsm","kernel":"6.8.0-45-generic",'
         '"ringbuf_kib":256}', ReadyLine),
        ('{"type":"STATS","ts_ns":0,"ringbuf_drops":0,"tag_map_full":0,"tagged_pids":12,'
         '"events_emitted":4031}', StatsLine),
        ('{"type":"ACK","cmd":"TAG","ok":true}', AckLine),
        ('{"type":"ACK","cmd":"TAG","ok":false,"error":"no such process"}', AckLine),
    ],
)  # fmt: skip
def test_control_lines(line: str, cls: type) -> None:
    assert isinstance(Decoder().parse(line), cls)


def test_escaped_and_unicode_strings() -> None:
    obj = json.loads(EXEC_LINE)
    obj["argv"] = ["echo", 'a"b\\c', "\u0001ÿé"]
    ev = Decoder().parse(json.dumps(obj))
    assert isinstance(ev, ExecEvent)
    assert ev.argv[1] == 'a"b\\c'
    assert ev.argv[2] == "\x01\xff\xe9"


@pytest.mark.parametrize(
    "line",
    [
        "not json",
        "[1, 2]",
        '{"type":"NOPE"}',
        '{"type":"EXEC","pid":"x"}',
        EXEC_LINE.replace('"comm":"cat"', '"comm":"cat","extra":1'),
        EXEC_LINE.replace('"pid":4121', '"pid":-1'),
        b'{"type":"PONG"\xff}',
    ],
)
def test_malformed_lines_are_counted(line: str | bytes) -> None:
    d = Decoder()
    assert d.parse(line) is None
    assert d.malformed == 1


def test_oversized_line_rejected() -> None:
    d = Decoder()
    obj = json.loads(EXEC_LINE)
    obj["argv"] = ["x" * (MAX_LINE_BYTES + 1)]
    assert d.parse(json.dumps(obj)) is None
    assert d.malformed == 1


def test_blank_line_ignored_not_counted() -> None:
    d = Decoder()
    assert d.parse("\n") is None
    assert d.malformed == 0
