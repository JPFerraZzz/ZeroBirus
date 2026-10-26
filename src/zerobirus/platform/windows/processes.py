"""Process listing through psutil, mapped to ``ProcessInfo``.

Everything psutil returns is data. Fields that cannot be read (``AccessDenied`` is normal
for protected system processes, even as administrator) become ``None`` or empty, never an
invented value: ``core/safety`` relies on "no path" meaning "unknown".

CPU is measured over a short window (several readings), not at one instant, and reported as
a share of the whole machine.
"""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Callable

import psutil

from zerobirus.core.models import Observed, ProcessInfo
from zerobirus.platform.windows.paths import canonical_path

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_READ_ERRORS = (psutil.AccessDenied, psutil.ZombieProcess, OSError)
SAMPLES = 3
SAMPLE_INTERVAL = 0.7


def _quote(arg: str) -> str:
    return f'"{arg}"' if not arg or " " in arg or "\t" in arg else arg


def _safe[T](read: Callable[[], T], default: T) -> T:
    try:
        return read()
    except _READ_ERRORS:
        return default


def own_tree_pids() -> set[int]:
    """This process and its descendants (the PowerShell bridge children among them)."""
    me = psutil.Process()
    pids = {me.pid}
    with contextlib.suppress(psutil.Error):
        pids.update(c.pid for c in me.children(recursive=True))
    return pids


def own_and_parent_pids() -> frozenset[int]:
    """Own process, its parent and its children: what ``SystemContext.own_pids`` needs."""
    pids = own_tree_pids()
    with contextlib.suppress(psutil.Error):
        parent = psutil.Process().parent()
        if parent is not None:
            pids.add(parent.pid)
    return frozenset(pids)


def _canonical(exe: str) -> str | None:
    if not exe:
        return None
    if "\\" not in exe and "/" not in exe:
        return exe  # not a path (psutil reports "Registry"); safety judges it
    try:
        return canonical_path(exe)
    except OSError:
        return exe


def to_process_info(proc: psutil.Process, cpu_percent: float | None = None) -> ProcessInfo | None:
    """Map one process, or None if it disappeared or its identity cannot be read."""
    try:
        pid = proc.pid
        name = proc.name()
        args: list[str] = _safe(proc.cmdline, [])
        exe = _safe(proc.exe, "")
        user = _safe(proc.username, "")
        parent: int | None
        try:
            parent = proc.ppid()
        except _READ_ERRORS:
            parent = None
    except psutil.NoSuchProcess:
        return None  # it ended while we were reading it
    except _READ_ERRORS:
        return None
    return ProcessInfo(
        pid=pid,
        name=name,
        path=_canonical(exe),
        cmdline=" ".join(_quote(a) for a in args),
        user=user,
        parent_pid=parent,
        cpu_percent=cpu_percent,
    )


def _sample_cpu(procs: list[psutil.Process]) -> dict[int, float]:
    """Average CPU share of the whole machine over several readings."""
    for p in procs:
        with contextlib.suppress(psutil.NoSuchProcess, *_READ_ERRORS):
            p.cpu_percent(None)
    totals: dict[int, list[float]] = {}
    for _ in range(SAMPLES):
        time.sleep(SAMPLE_INTERVAL)
        for p in procs:
            try:
                totals.setdefault(p.pid, []).append(p.cpu_percent(None))
            except (psutil.NoSuchProcess, *_READ_ERRORS):
                continue
    cores = psutil.cpu_count(logical=True) or 1
    return {
        pid: max(0.0, min(100.0, sum(vals) / len(vals) / cores))
        for pid, vals in totals.items()
        if vals
    }


def list_processes(*, sample_cpu: bool = True) -> Observed[ProcessInfo]:
    exclude = own_tree_pids()
    procs = [p for p in psutil.process_iter() if p.pid not in exclude]
    cpu = _sample_cpu(procs) if sample_cpu else {}
    out = [i for p in procs if (i := to_process_info(p, cpu.get(p.pid))) is not None]
    return Observed(tuple(out))
