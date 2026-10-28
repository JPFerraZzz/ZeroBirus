"""Backend interfaces. Read-only inspection and state-changing remediation are separate."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from zerobirus.core.defender_scan import ScanStatus
from zerobirus.core.models import (
    AutorunEntry,
    ConnectionInfo,
    DefenderState,
    FileCandidate,
    FileHash,
    Observed,
    ProcessInfo,
    ServiceInfo,
    Signature,
    TaskInfo,
    TempEntry,
    WmiBinding,
)
from zerobirus.core.safety import SystemContext


class Inspector(Protocol):
    """Read-only view of the machine. Scanner code receives only this.

    Every collection method returns ``Observed``: what was seen plus, in ``gaps``, what
    could not be read. A method never raises for missing permissions and never reports
    "nothing found" when it simply could not look.

    Paths handed back (process images, autorun targets, files) must be canonical, resolved
    with GetFinalPathNameByHandle where they exist, because ``core.safety`` only compares
    strings. Command lines are returned exactly as the system holds them.
    """

    def is_elevated(self) -> bool: ...

    def system_context(self) -> SystemContext: ...

    def desktop_folder(self) -> str:
        """The user's Desktop as SHGetKnownFolderPath resolves it, or an empty string."""
        ...

    def processes(self) -> Observed[ProcessInfo]: ...

    def autoruns(self) -> Observed[AutorunEntry]: ...

    def scheduled_tasks(self) -> Observed[TaskInfo]: ...

    def services(self) -> Observed[ServiceInfo]: ...

    def connections(self) -> Observed[ConnectionInfo]: ...

    def defender(self) -> Observed[DefenderState]: ...

    def hosts_lines(self) -> Observed[str]: ...

    def wmi_bindings(self) -> Observed[WmiBinding]: ...

    def candidate_files(self) -> Observed[FileCandidate]:
        """Executables found by a bounded search of user-writable places (depth, size, time)."""
        ...

    def temp_entries(self) -> Observed[TempEntry]:
        """Top-level entries of the current user's Temp folder, for the optional cleaning."""
        ...

    def signatures(self, paths: Sequence[str]) -> Observed[Signature]:
        """Authenticode for the requested paths only (candidates, never the whole disk)."""
        ...

    def file_hashes(self, paths: Sequence[str]) -> Observed[FileHash]: ...


class DefenderScanner(Protocol):
    """Starts a Microsoft Defender full scan and reports how it is going, from facts only."""

    def start(self) -> tuple[int, str]:
        """Start it. Returns (process id, UTC start time as ISO 8601)."""
        ...

    def status(self, pid: int | None, started_at: str | None) -> ScanStatus: ...
