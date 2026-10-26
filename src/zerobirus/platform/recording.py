"""Memoising wrapper around an Inspector that remembers everything it was asked.

Scanners run in parallel and several of them need the same data (processes, signatures).
This wrapper asks the backend once per question, and at the end turns everything that was
observed into a ``Snapshot`` for the report.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from typing import Any

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
    WmiBinding,
)
from zerobirus.core.safety import SystemContext, normalize_windows_path
from zerobirus.core.snapshot import Snapshot
from zerobirus.platform.base import Inspector


def _key(path: str) -> str:
    return normalize_windows_path(path)


class RecordingInspector:
    def __init__(self, inner: Inspector) -> None:
        self._inner = inner
        self._lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._cache: dict[str, Any] = {}
        self._signatures: dict[str, Signature] = {}
        self._asked_signatures: set[str] = set()
        self._hashes: dict[str, FileHash] = {}
        self._asked_hashes: set[str] = set()
        self._gaps: dict[str, tuple[str, ...]] = {}

    def _once[T](self, name: str, fn: Callable[[], Observed[T]]) -> Observed[T]:
        with self._lock:
            lock = self._locks.setdefault(name, threading.Lock())
        with lock:
            if name not in self._cache:
                result = fn()
                self._cache[name] = result
                if result.gaps:
                    self._gaps[name] = result.gaps
            cached: Observed[T] = self._cache[name]
            return cached

    def is_elevated(self) -> bool:
        return bool(self._once("elevated", lambda: Observed((self._inner.is_elevated(),))).items[0])

    def system_context(self) -> SystemContext:
        ctx: SystemContext = self._once(
            "system", lambda: Observed((self._inner.system_context(),))
        ).items[0]
        return ctx

    def desktop_folder(self) -> str:
        value: str = self._once("desktop", lambda: Observed((self._inner.desktop_folder(),))).items[
            0
        ]
        return value

    def processes(self) -> Observed[ProcessInfo]:
        return self._once("processes", self._inner.processes)

    def autoruns(self) -> Observed[AutorunEntry]:
        return self._once("autoruns", self._inner.autoruns)

    def scheduled_tasks(self) -> Observed[TaskInfo]:
        return self._once("tasks", self._inner.scheduled_tasks)

    def services(self) -> Observed[ServiceInfo]:
        return self._once("services", self._inner.services)

    def connections(self) -> Observed[ConnectionInfo]:
        return self._once("connections", self._inner.connections)

    def defender(self) -> Observed[DefenderState]:
        return self._once("defender", self._inner.defender)

    def hosts_lines(self) -> Observed[str]:
        return self._once("hosts", self._inner.hosts_lines)

    def wmi_bindings(self) -> Observed[WmiBinding]:
        return self._once("wmi_bindings", self._inner.wmi_bindings)

    def candidate_files(self) -> Observed[FileCandidate]:
        return self._once("files", self._inner.candidate_files)

    def signatures(self, paths: Sequence[str]) -> Observed[Signature]:
        with self._lock:
            wanted = list(dict.fromkeys(p for p in paths if _key(p) not in self._asked_signatures))
            self._asked_signatures.update(_key(p) for p in wanted)
        if wanted:
            result = self._inner.signatures(wanted)
            with self._lock:
                for sig in result.items:
                    self._signatures[_key(sig.path)] = sig
                if result.gaps:
                    self._gaps["signatures"] = tuple(
                        dict.fromkeys((*self._gaps.get("signatures", ()), *result.gaps))
                    )
        with self._lock:
            have = tuple(s for p in paths if (s := self._signatures.get(_key(p))) is not None)
            gaps = self._gaps.get("signatures", ())
        return Observed(have, gaps)

    def file_hashes(self, paths: Sequence[str]) -> Observed[FileHash]:
        with self._lock:
            wanted = list(dict.fromkeys(p for p in paths if _key(p) not in self._asked_hashes))
            self._asked_hashes.update(_key(p) for p in wanted)
        if wanted:
            result = self._inner.file_hashes(wanted)
            with self._lock:
                for h in result.items:
                    self._hashes[_key(h.path)] = h
                if result.gaps:
                    self._gaps["hashes"] = tuple(
                        dict.fromkeys((*self._gaps.get("hashes", ()), *result.gaps))
                    )
        with self._lock:
            have = tuple(f for p in paths if (f := self._hashes.get(_key(p))) is not None)
            gaps = self._gaps.get("hashes", ())
        return Observed(have, gaps)

    def snapshot(self) -> Snapshot:
        """Everything observed so far. Sections never requested stay empty."""

        def items(name: str) -> tuple[Any, ...]:
            cached = self._cache.get(name)
            return () if cached is None else tuple(cached.items)

        return Snapshot(
            elevated=self.is_elevated(),
            system=self.system_context(),
            desktop=self.desktop_folder(),
            processes=items("processes"),
            autoruns=items("autoruns"),
            tasks=items("tasks"),
            services=items("services"),
            connections=items("connections"),
            defender=items("defender"),
            hosts=items("hosts"),
            wmi_bindings=items("wmi_bindings"),
            files=items("files"),
            signatures=tuple(self._signatures.values()),
            hashes=tuple(self._hashes.values()),
            gaps=dict(self._gaps),
        )
