"""Backend interfaces. Read-only inspection and state-changing remediation are separate."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from zerobirus.core.models import ActionResult, ProcessInfo
from zerobirus.core.safety import SystemContext


class Inspector(Protocol):
    """Read-only view of the machine. Scanner code receives only this."""

    def is_elevated(self) -> bool: ...

    def system_context(self) -> SystemContext: ...

    def list_processes(self) -> Sequence[ProcessInfo]: ...


class Remediator(Protocol):
    """Changes the system. Must reject anything not in the authorised plan (Phase 3)."""

    def quarantine_file(self, path: str, *, plan_item_id: str) -> ActionResult: ...
