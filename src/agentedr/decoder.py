"""Sensor line decoder: one JSON line -> one validated model.

Sensor output is untrusted input (SPEC 15): lines over 64 KiB, invalid JSON,
unknown types and schema mismatches are logged and counted, never fatal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from pydantic import ValidationError

from agentedr.models import SENSOR_LINE_ADAPTER, SensorLine

log = logging.getLogger(__name__)

MAX_LINE_BYTES = 64 * 1024


@dataclass
class Decoder:
    malformed: int = 0
    decoded: int = 0

    def parse(self, line: bytes | str) -> SensorLine | None:
        """Return the decoded line, or None (and count it) if it is malformed."""
        raw = line.encode("utf-8", "replace") if isinstance(line, str) else line
        raw = raw.rstrip(b"\r\n")
        if not raw:
            return None
        if len(raw) > MAX_LINE_BYTES:
            self.reject(f"line too long ({len(raw)} bytes)")
            return None
        try:
            parsed = SENSOR_LINE_ADAPTER.validate_json(raw)
        except ValidationError as exc:
            # Do not log the line itself: it may contain secrets (gotcha 15).
            self.reject(f"{exc.error_count()} validation error(s): {exc.errors()[0]['msg']}")
            return None
        self.decoded += 1
        return parsed

    def reject(self, reason: str) -> None:
        """Count and log a malformed line."""
        self.malformed += 1
        log.warning(
            "malformed sensor line dropped (%s); total malformed: %d", reason, self.malformed
        )
