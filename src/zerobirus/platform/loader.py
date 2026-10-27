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
from zerobirus.remediation.ops import SystemOps


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


def create_remediation_ops() -> SystemOps:
    """The state-changing operations for this machine. Windows only."""
    if sys.platform == "win32":
        module: Any = importlib.import_module("zerobirus.platform.windows")
        ops: SystemOps = module.create_remediation_ops()
        return ops
    raise BackendUnavailable("A remoção real só funciona em Windows 10 e 11.")


def relaunch_elevated() -> bool:
    """Ask Windows to start this program again as administrator. True if it was launched."""
    if sys.platform == "win32":
        module: Any = importlib.import_module("zerobirus.platform.windows")
        return bool(module.relaunch_elevated())
    return False


def high_contrast_active() -> bool:
    """True when Windows high-contrast mode is on (the interface then uses the system palette)."""
    if sys.platform == "win32":
        module: Any = importlib.import_module("zerobirus.platform.windows")
        return bool(module.high_contrast_active())
    return False


def animations_enabled() -> bool:
    """False when the person asked Windows to reduce animations. Always True off Windows."""
    if sys.platform == "win32":
        module: Any = importlib.import_module("zerobirus.platform.windows")
        return bool(module.animations_enabled())
    return True
