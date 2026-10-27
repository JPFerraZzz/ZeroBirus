"""Stage 6: free the work folder on request, keeping the reports.

Deletes only the two fixed sub-folders that hold the quarantine and the undo records of a
session, and nothing else. After this, that session can no longer be undone, so the caller
asks first.
"""

from __future__ import annotations

import os
import shutil

from zerobirus.core.session import Session
from zerobirus.remediation.engine import QUARANTINE_DIR
from zerobirus.remediation.ops import is_link

WORK_DIRS = (QUARANTINE_DIR, "undo")


def purge_session_work(session: Session) -> list[str]:
    """Remove the quarantine and undo folders of one session. Returns the names removed."""
    removed: list[str] = []
    for name in WORK_DIRS:
        target = session.folder / name
        try:
            st = os.lstat(target)
        except FileNotFoundError:
            continue
        if is_link(st):  # never follow a link out of the session folder
            continue
        shutil.rmtree(target)
        removed.append(name)
    return removed
