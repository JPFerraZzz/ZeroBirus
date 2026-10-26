"""File system reads: startup folders, hosts, bounded search of writable places, hashes."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import time
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


def search_roots(roots: Iterable[str]) -> Observed[FileCandidate]:
    """Bounded search for executables: depth, entry count, candidate count and time limits.

    Never follows junctions or symlinks. Hitting a limit or being denied somewhere is a gap.
    """
    started = time.monotonic()
    found: list[FileCandidate] = []
    visited = 0
    denied = 0
    truncated = ""
    stack: list[tuple[str, int]] = [(r, 0) for r in roots]
    while stack:
        folder, depth = stack.pop()
        if time.monotonic() - started > MAX_SECONDS:
            truncated = "o tempo da pesquisa dirigida acabou"
            break
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    visited += 1
                    if visited > MAX_ENTRIES:
                        truncated = "a pesquisa dirigida atingiu o limite de entradas"
                        stack.clear()
                        break
                    if _is_reparse(entry):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if depth < MAX_DEPTH:
                                stack.append((entry.path, depth + 1))
                        elif os.path.splitext(entry.name)[1].lower() in EXECUTABLE_EXTENSIONS:
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
    gaps: list[str] = []
    if truncated:
        gaps.append(f"{truncated}; parte das pastas não foi vista")
    if denied:
        gaps.append(f"sem acesso a {denied} pastas ou ficheiros durante a pesquisa dirigida")
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
