"""Fake backend: synthetic fixtures only. Used by tests and ``--demo``.

A fixture is a snapshot in JSON (the same schema a real scan report carries), so a report
from a real machine can be replayed here once it is cleaned of personal data.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from importlib import resources
from pathlib import Path

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
from zerobirus.core.safety import SystemContext, normalize_windows_path
from zerobirus.core.snapshot import Snapshot, snapshot_from_dict


def load_snapshot_file(path: Path) -> Snapshot:
    """Load a snapshot from a snapshot file or from a scan report that carries one."""
    data = json.loads(path.read_text("utf-8"))
    return snapshot_from_dict(data.get("snapshot", data))


def load_fixture(name: str) -> Snapshot:
    text = resources.files(__package__).joinpath(f"{name}.json").read_text("utf-8")
    return snapshot_from_dict(json.loads(text))


def fixture_names() -> list[str]:
    return sorted(
        p.name.removesuffix(".json")
        for p in resources.files(__package__).iterdir()
        if p.name.endswith(".json")
    )


class FakeInspector:
    """Inspector that replays a snapshot. Missing sections behave as "seen, empty"."""

    def __init__(self, fixture: str | Snapshot = "clean_pc") -> None:
        self._snap = load_fixture(fixture) if isinstance(fixture, str) else fixture

    def _observed[T](self, section: str, items: tuple[T, ...]) -> Observed[T]:
        return Observed(items, self._snap.gaps.get(section, ()))

    def is_elevated(self) -> bool:
        return self._snap.elevated

    def system_context(self) -> SystemContext:
        return self._snap.system

    def desktop_folder(self) -> str:
        return self._snap.desktop

    def processes(self) -> Observed[ProcessInfo]:
        return self._observed("processes", self._snap.processes)

    def autoruns(self) -> Observed[AutorunEntry]:
        return self._observed("autoruns", self._snap.autoruns)

    def scheduled_tasks(self) -> Observed[TaskInfo]:
        return self._observed("tasks", self._snap.tasks)

    def services(self) -> Observed[ServiceInfo]:
        return self._observed("services", self._snap.services)

    def connections(self) -> Observed[ConnectionInfo]:
        return self._observed("connections", self._snap.connections)

    def defender(self) -> Observed[DefenderState]:
        return self._observed("defender", self._snap.defender)

    def hosts_lines(self) -> Observed[str]:
        return self._observed("hosts", self._snap.hosts)

    def wmi_bindings(self) -> Observed[WmiBinding]:
        return self._observed("wmi_bindings", self._snap.wmi_bindings)

    def candidate_files(self) -> Observed[FileCandidate]:
        return self._observed("files", self._snap.files)

    def temp_entries(self) -> Observed[TempEntry]:
        """A few synthetic Temp entries under the first profile, so the demo has something."""
        base = self._snap.system.profile_roots[0] + "\\AppData\\Local\\Temp\\"
        return Observed(
            (
                TempEntry(base + "installer-cache.tmp", False, 48_000_000, 12),
                TempEntry(base + "old-setup", True, 120_000_000, 30),
                TempEntry(base + "~DF3A91.tmp", False, 16_000, 5),
                TempEntry(base + "in-use.tmp", False, 1_000, 0),
            )
        )

    def signatures(self, paths: Sequence[str]) -> Observed[Signature]:
        known = {normalize_windows_path(s.path): s for s in self._snap.signatures}
        found = tuple(s for p in paths if (s := known.get(normalize_windows_path(p))) is not None)
        return Observed(found, self._snap.gaps.get("signatures", ()))

    def file_hashes(self, paths: Sequence[str]) -> Observed[FileHash]:
        known = {normalize_windows_path(h.path): h for h in self._snap.hashes}
        found = tuple(h for p in paths if (h := known.get(normalize_windows_path(p))) is not None)
        return Observed(found, self._snap.gaps.get("hashes", ()))
