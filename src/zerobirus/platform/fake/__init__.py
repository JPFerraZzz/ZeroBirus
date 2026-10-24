"""Fake backend: synthetic fixtures only. Used by tests and ``--demo``."""

from __future__ import annotations

import json
from collections.abc import Sequence
from importlib import resources
from typing import Any

from zerobirus.core.models import ProcessInfo
from zerobirus.core.safety import SystemContext


class FakeInspector:
    """Inspector backed by a JSON fixture shipped inside the package."""

    def __init__(self, fixture: str = "clean_pc") -> None:
        text = resources.files(__package__).joinpath(f"{fixture}.json").read_text("utf-8")
        data: dict[str, Any] = json.loads(text)
        self._elevated = bool(data["elevated"])
        system = data["system"]
        self._context = SystemContext(
            system_root=system["system_root"],
            program_files=tuple(system["program_files"]),
            program_data=system["program_data"],
            users_dir=system["users_dir"],
            profile_roots=tuple(system["profile_roots"]),
            personal_folders=tuple(system["personal_folders"]),
        )
        self._processes = tuple(ProcessInfo(**p) for p in data["processes"])

    def is_elevated(self) -> bool:
        return self._elevated

    def system_context(self) -> SystemContext:
        return self._context

    def list_processes(self) -> Sequence[ProcessInfo]:
        return self._processes
