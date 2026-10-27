"""The operations the removal engine may ask of the operating system.

The engine (``engine.py``) holds every rule: authorisation, safety re-checks, order, undo
records, independent verification. This interface is the thin, dumb layer underneath. A backend
only does what it is told with the exact parameters of an authorised plan item and reports the
state it re-reads; it never decides anything.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path
from typing import Any, Literal, Protocol

from zerobirus.core.plan import PlanItem

FileKind = Literal["missing", "file", "dir", "link", "other"]
_REPARSE_POINT = 0x400


class SystemOps(Protocol):
    """State-changing operations plus the re-reads used to verify them."""

    # restore point -------------------------------------------------------------------
    def create_restore_point(self, description: str) -> str | None:
        """Create a restore point and confirm it exists. Return None on success, else why not."""
        ...

    # processes -----------------------------------------------------------------------
    def process_image(self, pid: int) -> str | None:
        """Image path of a running process ("" if unreadable), or None if it is not running."""
        ...

    def terminate(self, pid: int) -> None: ...

    # files and folders (the engine decides; this moves) --------------------------------
    def file_kind(self, path: str) -> FileKind:
        """What ``path`` is, without following links. Junctions and symlinks are "link"."""
        ...

    def resolves_to_itself(self, path: str) -> bool:
        """False if any part of the path goes through a link, junction or alias."""
        ...

    def tree_has_link(self, path: str) -> bool: ...

    def fingerprint(self, path: str) -> str | None:
        """SHA-256 of a file, or of a folder's names and file hashes; None if unreadable."""
        ...

    def move(self, src: str, dest: str) -> None:
        """Move (never overwrite). Raises OSError with the real cause when it cannot."""
        ...

    def delete_tree(self, path: str) -> None:
        """Permanently delete a file or folder. Only for emptying the quarantine on request."""
        ...

    # everything else -------------------------------------------------------------------
    def capture(self, item: PlanItem) -> dict[str, Any]:
        """Read the exact current state that undo needs (JSON-able). Raises if unreadable."""
        ...

    def perform(self, item: PlanItem) -> None:
        """Do the change. Registry, tasks, services, WMI, Defender, hosts and firewall."""
        ...

    def verify(self, item: PlanItem) -> bool:
        """Re-read the real state: True only if the intended end state is there."""
        ...

    def restore(self, item: PlanItem, saved: dict[str, Any]) -> None:
        """Put back what ``capture`` saved."""
        ...


def is_link(st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    return stat.S_ISLNK(st.st_mode) or bool(attrs & _REPARSE_POINT)


class LocalFileOps:
    """File and folder operations on the real file system (used by the Windows backend)."""

    def file_kind(self, path: str) -> FileKind:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "other"
        if is_link(st):
            return "link"
        if stat.S_ISDIR(st.st_mode):
            return "dir"
        return "file" if stat.S_ISREG(st.st_mode) else "other"

    def resolves_to_itself(self, path: str) -> bool:
        return os.path.normcase(os.path.realpath(path)) == os.path.normcase(os.path.abspath(path))

    def tree_has_link(self, path: str) -> bool:
        stack = [path]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        if is_link(entry.stat(follow_symlinks=False)):
                            return True
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
            except OSError:
                return True  # cannot look inside: do not move what cannot be checked
        return False

    def fingerprint(self, path: str) -> str | None:
        try:
            if os.path.isdir(path):
                h = hashlib.sha256()
                for root, dirs, files in os.walk(path):
                    dirs.sort()
                    for name in sorted(files):
                        full = os.path.join(root, name)
                        h.update(os.path.relpath(full, path).encode("utf-8", "surrogateescape"))
                        h.update(self._file_hash(full).encode("ascii"))
                return h.hexdigest()
            return self._file_hash(path)
        except OSError:
            return None

    @staticmethod
    def _file_hash(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()

    def move(self, src: str, dest: str) -> None:
        if os.path.lexists(dest):
            raise FileExistsError(dest)
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        shutil.move(src, dest)

    def delete_tree(self, path: str) -> None:
        if self.file_kind(path) == "dir":
            shutil.rmtree(path)
        else:
            os.unlink(path)
