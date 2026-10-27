"""Windows backend. The only place where Windows-specific code may live.

Imported only when ``sys.platform == "win32"`` (through ``platform/loader.py``).
"""

from __future__ import annotations

import sys

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

from zerobirus.platform.base import Inspector
from zerobirus.remediation.ops import SystemOps


def create_inspector() -> Inspector:
    """The read-only Windows Inspector."""
    from zerobirus.platform.windows.inspector import WindowsInspector

    return WindowsInspector()


def create_remediation_ops() -> SystemOps:
    """The state-changing Windows operations (stage 4)."""
    from zerobirus.platform.windows.inspector import windows_directory
    from zerobirus.platform.windows.remediator import WindowsOps

    return WindowsOps(windows_directory())


from zerobirus.platform.windows.uiprefs import (  # noqa: E402
    animations_enabled,
    high_contrast_active,
    relaunch_elevated,
)

__all__ = [
    "animations_enabled",
    "create_inspector",
    "create_remediation_ops",
    "high_contrast_active",
    "relaunch_elevated",
]
