"""The on-disk record of one run: ``<base>\\Sessions\\<date-time>\\`` (BRIEF section 7).

Holds ``session.json`` (with a schema version), ``findings.json``, ``plan.json`` and later
``results.json``, ``undo/`` and ``log.txt``. Everything written here already went through the
redactor and the privacy filter, or is plan data that holds no secret.

Nothing in this module touches the system: it writes plain files under a folder chosen by the
caller (``%ProgramData%\\ZeroBirus`` on Windows, a temporary folder in tests and ``--demo``).
Writes are atomic (temporary file, then rename), so a crash never leaves half a JSON file.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

SESSION_SCHEMA_VERSION = 1
_ID = re.compile(r"^\d{8}-\d{6}(?:-\d+)?$")


def new_session_id(now: datetime, existing: set[str] | None = None) -> str:
    base = now.strftime("%Y%m%d-%H%M%S")
    taken: set[str] = existing or set()
    if base not in taken:
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    return f"{base}-{n}"


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


@dataclass(frozen=True, slots=True)
class Session:
    session_id: str
    folder: Path

    @property
    def undo_dir(self) -> Path:
        return self.folder / "undo"

    def write(self, name: str, data: Any) -> Path:
        path = self.folder / name
        write_json_atomic(path, data)
        return path

    def read(self, name: str) -> Any:
        return json.loads((self.folder / name).read_text("utf-8"))

    def log(self, line: str) -> None:
        """Append one line to ``log.txt``. The caller redacts before calling."""
        self.folder.mkdir(parents=True, exist_ok=True)
        with (self.folder / "log.txt").open("a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\n") + "\n")


def create_session(base: Path, now: datetime, *, tool_version: str, elevated: bool) -> Session:
    sessions = base / "Sessions"
    existing: set[str] = {p.name for p in sessions.iterdir()} if sessions.is_dir() else set()
    sid = new_session_id(now, existing)
    session = Session(sid, sessions / sid)
    session.folder.mkdir(parents=True, exist_ok=False)
    session.write(
        "session.json",
        {
            "schema_version": SESSION_SCHEMA_VERSION,
            "session_id": sid,
            "created_at": now.isoformat(timespec="seconds"),
            "tool_version": tool_version,
            "elevated": elevated,
            "stage": "context",
            "pending_restart_check": False,
        },
    )
    return session


def open_session(base: Path, session_id: str) -> Session:
    if not _ID.match(session_id):
        raise ValueError("not a session id")
    folder = base / "Sessions" / session_id
    data = json.loads((folder / "session.json").read_text("utf-8"))
    if data.get("schema_version") != SESSION_SCHEMA_VERSION:
        raise ValueError(f"unsupported session schema version {data.get('schema_version')}")
    return Session(session_id, folder)


def update_session(session: Session, **changes: Any) -> None:
    data = session.read("session.json")
    data.update(changes)
    session.write("session.json", data)


def list_sessions(base: Path) -> list[str]:
    sessions = base / "Sessions"
    if not sessions.is_dir():
        return []
    return sorted(p.name for p in sessions.iterdir() if _ID.match(p.name))


def find_pending_restart_check(base: Path) -> list[str]:
    """Sessions that asked for the post-restart check and did not finish it (newest first)."""
    found: list[str] = []
    for sid in reversed(list_sessions(base)):
        try:
            data: Any = json.loads((base / "Sessions" / sid / "session.json").read_text("utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get("pending_restart_check") is True:  # pyright: ignore[reportUnknownMemberType]
            found.append(sid)
    return found
