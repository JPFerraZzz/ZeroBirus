"""RAM and per-program memory through psutil. Anything unreadable is left out, never invented."""

from __future__ import annotations

import sys

import psutil

from zerobirus.core.ram import MemoryProcess, MemorySnapshot
from zerobirus.platform.windows.paths import canonical_path

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")


class WindowsMemoryProbe:
    def snapshot(self) -> MemorySnapshot:
        vm = psutil.virtual_memory()
        found: list[MemoryProcess] = []
        for proc in psutil.process_iter(["pid", "name", "memory_info"]):
            info = proc.info
            mem = info.get("memory_info")
            if mem is None:
                continue
            try:
                path: str | None = canonical_path(proc.exe()) or None
            except (psutil.Error, OSError):
                path = None
            found.append(
                MemoryProcess(int(info["pid"]), str(info.get("name") or ""), path, int(mem.rss))
            )
        return MemorySnapshot(int(vm.total), int(vm.available), tuple(found))
