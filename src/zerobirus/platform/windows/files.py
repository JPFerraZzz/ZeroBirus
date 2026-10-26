"""File system reads: startup folders, hosts, bounded search of writable places, hashes."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import time
from collections import deque
from collections.abc import Iterable, Sequence

from zerobirus.core.models import AutorunEntry, FileCandidate, FileHash, Observed

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".exe",
        ".dll",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".jar",
        ".msi",
        ".hta",
    }
)
MAX_DEPTH = 4
MAX_ENTRIES = 60_000
MAX_CANDIDATES = 5_000
MAX_SECONDS = 25.0
MAX_HASH_BYTES = 200 * 1024 * 1024
STARTUP_SUBPATH = r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
_REPARSE = 0x400  # junctions and symlinks: never followed
# Windows PowerShell drops this probe file in TEMP on start (our own bridge runs it).
_OWN_NOISE_PREFIXES = ("__psscriptpolicytest_",)


def _is_reparse(entry: os.DirEntry[str]) -> bool:
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError:
        return True
    return entry.is_symlink() or bool(getattr(st, "st_file_attributes", 0) & _REPARSE)


def startup_folder_files(
    folders: Iterable[tuple[str, str]],
) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Files in Startup folders as (label, user, path). ``folders`` is (label, folder)."""
    found: list[tuple[str, str, str]] = []
    gaps: list[str] = []
    for label, folder in folders:
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and entry.name.lower() != "desktop.ini":
                        found.append((label, "", entry.path))
        except FileNotFoundError:
            continue
        except OSError as exc:
            gaps.append(f"pasta de Arranque ({label}) não legível: {exc.strerror}")
    return found, gaps


def startup_entries(
    files: Sequence[tuple[str, str, str]], resolved: dict[str, str]
) -> list[AutorunEntry]:
    return [
        AutorunEntry(
            f"Pasta de Arranque ({label})",
            os.path.basename(path),
            resolved.get(path, path),
            user,
            "startup_folder",
        )
        for label, user, path in files
    ]


def read_hosts(path: str) -> Observed[str]:
    try:
        with open(path, "rb") as fh:
            text = fh.read(2_000_000).decode("utf-8-sig", errors="replace")
    except FileNotFoundError:
        return Observed()
    except OSError as exc:
        return Observed((), (f"o ficheiro hosts não é legível: {exc.strerror}",))
    return Observed(tuple(text.splitlines()))


def _search_one(
    root: str, max_entries: int, deadline: float
) -> tuple[list[FileCandidate], int, int, str]:
    """Breadth-first search of one root. Returns (found, visited, denied, why it stopped)."""
    found: list[FileCandidate] = []
    visited = 0
    denied = 0
    queue: deque[tuple[str, int]] = deque([(root, 0)])
    while queue:
        folder, depth = queue.popleft()
        if time.monotonic() > deadline:
            return found, visited, denied, "o tempo acabou"
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    visited += 1
                    if visited > max_entries:
                        return found, visited, denied, "o limite de entradas foi atingido"
                    if _is_reparse(entry):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if depth < MAX_DEPTH:
                                queue.append((entry.path, depth + 1))
                        elif os.path.splitext(entry.name)[
                            1
                        ].lower() in EXECUTABLE_EXTENSIONS and not entry.name.lower().startswith(
                            _OWN_NOISE_PREFIXES
                        ):
                            st = entry.stat(follow_symlinks=False)
                            if stat.S_ISREG(st.st_mode) and len(found) < MAX_CANDIDATES:
                                found.append(
                                    FileCandidate(entry.path, st.st_size, int(st.st_mtime))
                                )
                    except OSError:
                        denied += 1
        except FileNotFoundError:
            continue
        except OSError:
            denied += 1
    return found, visited, denied, ""


def search_roots(roots: Iterable[str]) -> Observed[FileCandidate]:
    """Bounded search for executables, root by root in the order given (most likely first).

    Every root gets a fair share of what is left of the time and entry budgets, so one huge
    folder cannot starve the ones after it. Never follows junctions or symlinks. Stopping at a
    limit, or being denied somewhere, is a gap: it is reported, never silent.
    """
    ordered = list(roots)
    started = time.monotonic()
    entries_left = MAX_ENTRIES
    found: list[FileCandidate] = []
    gaps: list[str] = []
    denied_total = 0
    for index, root in enumerate(ordered):
        roots_left = len(ordered) - index
        deadline = time.monotonic() + max(
            0.0, (MAX_SECONDS - (time.monotonic() - started)) / roots_left
        )
        got, visited, denied, why = _search_one(root, max(1, entries_left // roots_left), deadline)
        entries_left -= visited
        denied_total += denied
        found += got
        if why:
            gaps.append(f"a pesquisa em {root} parou: {why}; parte das pastas não foi vista")
    found = found[:MAX_CANDIDATES]
    if denied_total:
        gaps.append(f"sem acesso a {denied_total} pastas ou ficheiros durante a pesquisa dirigida")
    return Observed(tuple(found), tuple(gaps))


def sha256_of(paths: Sequence[str]) -> Observed[FileHash]:
    out: list[FileHash] = []
    gaps: list[str] = []
    for path in paths:
        try:
            if os.path.getsize(path) > MAX_HASH_BYTES:
                gaps.append(
                    f"ficheiro demasiado grande para calcular o SHA-256: {os.path.basename(path)}"
                )
                continue
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            out.append(FileHash(path, digest.hexdigest()))
        except OSError as exc:
            gaps.append(
                f"não foi possível calcular o SHA-256 de {os.path.basename(path)}: {exc.strerror}"
            )
    return Observed(tuple(out), tuple(gaps))
