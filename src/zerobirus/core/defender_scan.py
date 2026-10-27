"""State of a Microsoft Defender full scan, decided only from facts (BRIEF section 5, stage 5).

Never by elapsed time and never by output text. The facts are the Defender Operational log
events since the scan was started and whether the process we started is still alive.

Microsoft documents 1000 (scan started), 1001 (completed) and 1002 (stopped before finishing)
at learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus. Event 1005
(scan failed) is only confirmed by a community answer, so it is treated as a failure but is
listed as not confirmed in docs/DETECTION.md.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

EVENT_STARTED = 1000
EVENT_COMPLETED = 1001
EVENT_STOPPED = 1002
EVENT_FAILED = 1005
SCAN_EVENT_IDS = (EVENT_STARTED, EVENT_COMPLETED, EVENT_STOPPED, EVENT_FAILED)


class ScanState(StrEnum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"
    UNKNOWN = "unknown"  # the log could not be read, or the process vanished with no end event


@dataclass(frozen=True, slots=True)
class ScanEvent:
    event_id: int
    time: str  # ISO 8601, only used for ordering


@dataclass(frozen=True, slots=True)
class ScanStatus:
    state: ScanState
    text: str


TEXT = {
    ScanState.NOT_STARTED: "A análise ainda não começou.",
    ScanState.RUNNING: "A análise do Microsoft Defender está a decorrer. Pode demorar horas.",
    ScanState.COMPLETED: "O Microsoft Defender concluiu a análise.",
    ScanState.STOPPED: "A análise foi interrompida antes de terminar. Volta a iniciá-la.",
    ScanState.FAILED: "A análise falhou. Volta a iniciá-la; se repetir, usa a Análise offline.",
    ScanState.UNKNOWN: "Não foi possível saber como terminou a análise (o registo do Defender "
    "não foi lido ou não tem o fim). Não a dês como concluída.",
}


def interpret(
    events: Iterable[ScanEvent], *, started: bool, process_alive: bool | None
) -> ScanStatus:
    """``events`` are the scan events since our scan was started (any order)."""
    ordered = sorted(
        (e for e in events if e.event_id in SCAN_EVENT_IDS), key=lambda e: (e.time, e.event_id)
    )
    if not started:
        return ScanStatus(ScanState.NOT_STARTED, TEXT[ScanState.NOT_STARTED])
    last_end = next((e for e in reversed(ordered) if e.event_id != EVENT_STARTED), None)
    last_start = next((e for e in reversed(ordered) if e.event_id == EVENT_STARTED), None)
    if last_end is not None and (last_start is None or last_end.time >= last_start.time):
        state = {
            EVENT_COMPLETED: ScanState.COMPLETED,
            EVENT_STOPPED: ScanState.STOPPED,
            EVENT_FAILED: ScanState.FAILED,
        }[last_end.event_id]
        return ScanStatus(state, TEXT[state])
    if process_alive:
        return ScanStatus(ScanState.RUNNING, TEXT[ScanState.RUNNING])
    return ScanStatus(ScanState.UNKNOWN, TEXT[ScanState.UNKNOWN])
