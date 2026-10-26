"""The only place outside ``platform/windows`` that may name the Windows backend.

The import happens inside the ``sys.platform == "win32"`` branch, so on Linux the Windows
backend is never imported. ``test_policy`` checks that this is the only file allowed and that
the import stays inside that branch.
"""

from __future__ import annotations

import importlib
import sys
from typing import Any

from zerobirus.platform.base import Inspector


class BackendUnavailable(RuntimeError):
    """The real backend cannot run on this system."""


def create_inspector() -> Inspector:
    """The Inspector for this machine. Windows only; use ``--demo`` elsewhere."""
    if sys.platform == "win32":
        module: Any = importlib.import_module("zerobirus.platform.windows")
        inspector: Inspector = module.create_inspector()
        return inspector
    raise BackendUnavailable(
        "A verificação real só funciona em Windows 10 e 11. Neste sistema usa --demo."
    )
