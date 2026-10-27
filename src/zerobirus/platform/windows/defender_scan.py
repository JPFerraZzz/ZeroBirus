"""Starts a Microsoft Defender full scan that outlives this window, and reads how it ended.

The scan runs in its own detached PowerShell (absolute path, fixed command, no user data).
How it ended comes from the Defender Operational log events since it started, never from time
or text (see ``core/defender_scan.py``). Nothing here changes Defender settings.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from datetime import UTC, datetime
from typing import Any, cast

import psutil

from zerobirus.core.defender_scan import ScanEvent, ScanState, ScanStatus, interpret
from zerobirus.platform.windows import ps

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_COMMAND = "Start-MpScan -ScanType FullScan"
_DETACHED = 0x00000008
_NEW_GROUP = 0x00000200
_NO_WINDOW = 0x08000000


class WindowsDefenderScanner:
    def __init__(self, system_root: str) -> None:
        self._root = system_root

    def start(self) -> tuple[int, str]:
        """Start the scan. Returns the process id and the UTC start time (ISO 8601)."""
        encoded = base64.b64encode(_COMMAND.encode("utf-16-le")).decode("ascii")
        started = datetime.now(UTC).isoformat()
        proc = subprocess.Popen(  # noqa: S603 - absolute path, fixed command, no shell
            [
                ps.powershell_path(self._root),
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ],
            cwd=os.path.join(self._root, "System32"),
            env=ps.child_environment(self._root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=_DETACHED | _NEW_GROUP | _NO_WINDOW,
            close_fds=True,
        )
        return proc.pid, started

    def status(self, pid: int | None, started_at: str | None) -> ScanStatus:
        if not started_at:
            return interpret((), started=False, process_alive=None)
        try:
            out = ps.run_json("defender_events", {"since": started_at}, system_root=self._root)
        except ps.PowerShellError:
            return ScanStatus(ScanState.UNKNOWN, "Não foi possível ler o registo do Defender.")
        if out.errors:
            return ScanStatus(ScanState.UNKNOWN, "Não foi possível ler o registo do Defender.")
        items: Any = out.items
        rows: list[Any] = list(items) if isinstance(items, list) else [items]  # pyright: ignore[reportUnknownArgumentType]
        events: list[ScanEvent] = []
        for r in rows:
            if isinstance(r, dict) and "id" in r and "time" in r:
                row = cast("dict[str, Any]", r)
                events.append(ScanEvent(int(row["id"]), str(row["time"])))
        alive = psutil.pid_exists(pid) if pid else None
        return interpret(events, started=True, process_alive=alive)
