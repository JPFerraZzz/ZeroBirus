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
    TempEntry,
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
        self._signatures_in_flight: dict[str, threading.Event] = {}
        self._hashes_in_flight: dict[str, threading.Event] = {}
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

    def temp_entries(self) -> Observed[TempEntry]:
        return self._inner.temp_entries()  # optional cleaning: not part of a scan snapshot

    def _fetch_shared[T](
        self,
        paths: Sequence[str],
        asked: set[str],
        in_flight: dict[str, threading.Event],
        fetch: Callable[[list[str]], Observed[T]],
        store: Callable[[T], None],
        gap_key: str,
    ) -> None:
        """Ask the backend about each path once, even when several checks ask at the same time.

        A caller that wants a path someone else is already fetching waits for that fetch instead
        of getting an empty answer (which would be read as "unknown").
        """
        with self._lock:
            wanted = list(dict.fromkeys(p for p in paths if _key(p) not in asked))
            asked.update(_key(p) for p in wanted)
            mine = threading.Event()
            for p in wanted:
                in_flight[_key(p)] = mine
            waiting = [in_flight[k] for p in paths if (k := _key(p)) in in_flight]
        if wanted:
            try:
                result = fetch(wanted)
                with self._lock:
                    for item in result.items:
                        store(item)
                    if result.gaps:
                        self._gaps[gap_key] = tuple(
                            dict.fromkeys((*self._gaps.get(gap_key, ()), *result.gaps))
                        )
            finally:
                with self._lock:
                    for p in wanted:
                        in_flight.pop(_key(p), None)
                mine.set()
        for event in waiting:
            event.wait(300)

    def signatures(self, paths: Sequence[str]) -> Observed[Signature]:
        def store(sig: Signature) -> None:
            self._signatures[_key(sig.path)] = sig

        self._fetch_shared(
            paths,
            self._asked_signatures,
            self._signatures_in_flight,
            self._inner.signatures,
            store,
            "signatures",
        )
        with self._lock:
            have = tuple(s for p in paths if (s := self._signatures.get(_key(p))) is not None)
            gaps = self._gaps.get("signatures", ())
        return Observed(have, gaps)

    def file_hashes(self, paths: Sequence[str]) -> Observed[FileHash]:
        def store(h: FileHash) -> None:
            self._hashes[_key(h.path)] = h

        self._fetch_shared(
            paths,
            self._asked_hashes,
            self._hashes_in_flight,
            self._inner.file_hashes,
            store,
            "hashes",
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
