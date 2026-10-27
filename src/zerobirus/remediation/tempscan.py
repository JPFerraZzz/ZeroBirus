"""Read-only listing of the top-level entries of a Temp folder, for the optional cleaning.

Bounded in time and in entries: a Temp folder can hold hundreds of thousands of files. Links
and junctions are skipped (never followed, never offered). Nothing is changed here.
"""

from __future__ import annotations

import os
import time

from zerobirus.core.models import Observed, TempEntry
from zerobirus.remediation.ops import is_link

MAX_ENTRIES = 2000
MAX_WALK_FILES = 20000
MAX_SECONDS = 8.0
_DAY = 86400.0


def scan_temp(root: str, *, now: float | None = None) -> Observed[TempEntry]:
    clock = time.time() if now is None else now
    deadline = time.monotonic() + MAX_SECONDS
    out: list[TempEntry] = []
    gaps: list[str] = []
    try:
        entries = list(os.scandir(root))
    except OSError as exc:
        return Observed((), (f"a pasta de temporários não foi lida ({exc.strerror or exc})",))
    for entry in entries[:MAX_ENTRIES]:
        if time.monotonic() > deadline:
            gaps.append("a leitura dos temporários foi cortada por tempo")
            break
        try:
            st = entry.stat(follow_symlinks=False)
            if is_link(st):
                continue
            if entry.is_dir(follow_symlinks=False):
                size, newest, complete = _tree(entry.path, st.st_mtime, deadline)
                if not complete:
                    continue  # cannot see all of it (links inside, unreadable): not offered
                out.append(TempEntry(entry.path, True, size, _age(clock, newest)))
            else:
                out.append(TempEntry(entry.path, False, st.st_size, _age(clock, st.st_mtime)))
        except OSError:
            continue
    if len(entries) > MAX_ENTRIES:
        gaps.append("há mais temporários do que os que são listados")
    return Observed(tuple(out), tuple(gaps))


def _age(now: float, mtime: float) -> int:
    return max(0, int((now - mtime) // _DAY))


def _tree(path: str, mtime: float, deadline: float) -> tuple[int, float, bool]:
    """Size, newest change and whether the whole tree could be seen without links."""
    size, newest, count = 0, mtime, 0
    stack = [path]
    while stack:
        if time.monotonic() > deadline:
            return size, newest, False
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    st = e.stat(follow_symlinks=False)
                    if is_link(st):
                        return size, newest, False
                    newest = max(newest, st.st_mtime)
                    count += 1
                    if count > MAX_WALK_FILES:
                        return size, newest, False
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    else:
                        size += st.st_size
        except OSError:
            return size, newest, False
    return size, newest, True
