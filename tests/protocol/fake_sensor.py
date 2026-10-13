#!/usr/bin/env python3
"""Fake agentedr-sensor for protocol tests.

Speaks the sensor protocol (SPEC 7) on stdin/stdout without touching the
kernel. Behaviour is selected with flags so each test can provoke one case.
It accepts and ignores the real sensor's --mode/--ringbuf-kib/--stats-interval.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

EXEC_START = {
    "type": "EXEC", "ts_ns": 1000, "pid": 4100, "tid": 4100, "ppid": 1, "uid": 1000,
    "session_id": 1, "agent_kind": 0, "comm": "claude", "filename": "/usr/bin/claude",
    "argv": ["claude"], "argv_truncated": False, "session_start": True, "untagged": False,
}  # fmt: skip
EXEC_CHILD = {
    **EXEC_START, "ts_ns": 2000, "pid": 4121, "tid": 4121, "ppid": 4100, "comm": "git",
    "filename": "/usr/bin/git", "argv": ["git", "status"], "session_start": False,
}  # fmt: skip
EXIT_ROOT = {
    "type": "EXIT", "ts_ns": 3000, "pid": 4100, "tid": 4100, "ppid": 1, "uid": 1000,
    "session_id": 1, "agent_kind": 0, "comm": "claude", "exit_code": 0, "is_root": True,
}  # fmt: skip


def emit(obj: object) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def emit_raw(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default="auto")
    p.add_argument("--ringbuf-kib", default="256")
    p.add_argument("--stats-interval", default="10")
    p.add_argument("--no-ready", action="store_true", help="never print READY")
    p.add_argument("--fail", type=int, help="print to stderr and exit with this code")
    p.add_argument("--reject-matchers", action="store_true")
    p.add_argument("--garbage", action="store_true", help="emit malformed lines before events")
    p.add_argument("--events", action="store_true", help="emit a session after SET_MATCHERS")
    p.add_argument("--drops", action="store_true", help="emit STATS lines with increasing drops")
    p.add_argument("--ignore-eof", action="store_true", help="keep running after stdin EOF")
    args = p.parse_args()

    print("fake-sensor: starting", file=sys.stderr, flush=True)
    if args.fail is not None:
        print("libbpf: prog 'handle_exec': BPF program load failed", file=sys.stderr)
        return args.fail
    if args.no_ready:
        time.sleep(60)
        return 0

    emit({"type": "READY", "version": "0.1.0", "mode": "fentry",
          "kernel": "6.8.0-fake", "ringbuf_kib": 256})  # fmt: skip

    for line in sys.stdin:
        cmd, _, rest = line.strip().partition(" ")
        if cmd == "PING":
            emit({"type": "PONG"})
        elif cmd == "SET_MATCHERS":
            json.loads(rest)  # must be valid JSON
            if args.reject_matchers:
                emit({"type": "ACK", "cmd": cmd, "ok": False, "error": "bad matcher object"})
                continue
            emit({"type": "ACK", "cmd": cmd, "ok": True})
            if args.drops:
                for drops in (0, 0, 5):
                    emit({"type": "STATS", "ts_ns": 1, "ringbuf_drops": drops,
                          "tag_map_full": 0, "tagged_pids": 1, "events_emitted": 3})  # fmt: skip
            if args.garbage:
                emit_raw("this is not json")
                emit_raw('{"type":"EXEC","pid":"not-an-int"}')
                emit_raw('{"type":"NOPE"}')
                emit_raw("x" * (70 * 1024))
            if args.events:
                for ev in (EXEC_START, EXEC_CHILD, EXIT_ROOT):
                    emit(ev)
        else:
            emit({"type": "ACK", "cmd": cmd, "ok": False, "error": "unknown command"})

    if args.ignore_eof:
        time.sleep(60)
    emit({"type": "BYE"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
