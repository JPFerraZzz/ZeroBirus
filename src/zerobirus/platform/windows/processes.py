"""Process listing through psutil, mapped to ``ProcessInfo``.

Everything psutil returns is data. Fields that cannot be read (``AccessDenied`` is normal
for protected system processes, even as administrator) become ``None`` or empty, never an
invented value: ``core/safety`` relies on "no path" meaning "unknown", and protects the
kernel pseudo-processes by name in that case.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator

import psutil

from zerobirus.core.models import ProcessInfo

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_READ_ERRORS = (psutil.AccessDenied, psutil.ZombieProcess, OSError)


def _quote(arg: str) -> str:
    return f'"{arg}"' if not arg or " " in arg or "\t" in arg else arg


def _safe[T](read: Callable[[], T], default: T) -> T:
    try:
        return read()
    except _READ_ERRORS:
        return default


def to_process_info(proc: psutil.Process) -> ProcessInfo | None:
    """Map one process, or None if it disappeared while being read."""
    try:
        pid = proc.pid
        name = proc.name()
    except psutil.NoSuchProcess:
        return None
    except _READ_ERRORS:
        return None
    exe = _safe(proc.exe, "")
    args: list[str] = _safe(proc.cmdline, [])
    try:
        parent: int | None = proc.ppid()
    except (psutil.NoSuchProcess, *_READ_ERRORS):
        parent = None
    return ProcessInfo(
        pid=pid,
        name=name,
        path=exe or None,
        cmdline=" ".join(_quote(a) for a in args),
        user=_safe(proc.username, ""),
        parent_pid=parent,
    )


def iter_processes() -> Iterator[ProcessInfo]:
    for proc in psutil.process_iter():
        info = to_process_info(proc)
        if info is not None:
            yield info
