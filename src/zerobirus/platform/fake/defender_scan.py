"""Scripted Defender scanner for tests and ``--demo``: advances one step per status call."""

from __future__ import annotations

from zerobirus.core.defender_scan import ScanEvent as _Event
from zerobirus.core.defender_scan import ScanState, ScanStatus, interpret


class FakeDefenderScanner:
    def __init__(self, end: ScanState = ScanState.COMPLETED, polls_until_end: int = 2) -> None:
        self._end = end
        self._left = polls_until_end
        self.started = False
        self.start_calls = 0

    def start(self) -> tuple[int, str]:
        self.started = True
        self.start_calls += 1
        return 4242, "2026-01-01T12:00:00+00:00"

    def status(self, pid: int | None, started_at: str | None) -> ScanStatus:
        if not started_at:
            return interpret((), started=False, process_alive=None)
        start = _Event(1000, "2026-01-01T12:00:01")
        if self._left > 0:
            self._left -= 1
            return interpret([start], started=True, process_alive=True)
        end_id = {
            ScanState.COMPLETED: 1001,
            ScanState.STOPPED: 1002,
            ScanState.FAILED: 1005,
        }.get(self._end)
        if end_id is None:
            return interpret([start], started=True, process_alive=False)
        return interpret(
            [start, _Event(end_id, "2026-01-01T13:00:00")], started=True, process_alive=False
        )
