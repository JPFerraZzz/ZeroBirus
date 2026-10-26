"""Backend interfaces. Read-only inspection and state-changing remediation are separate."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from zerobirus.core.models import (
    ActionResult,
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

    def signatures(self, paths: Sequence[str]) -> Observed[Signature]:
        """Authenticode for the requested paths only (candidates, never the whole disk)."""
        ...

    def file_hashes(self, paths: Sequence[str]) -> Observed[FileHash]: ...


class Remediator(Protocol):
    """Changes the system. Must reject anything not in the authorised plan (Phase 3)."""

    def quarantine_file(self, path: str, *, plan_item_id: str) -> ActionResult: ...
