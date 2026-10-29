"""Windows backend. The only place where Windows-specific code may live.

Imported only when ``sys.platform == "win32"`` (through ``platform/loader.py``).
"""

from __future__ import annotations

import sys

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

from zerobirus.platform.base import (
    DefenderScanner,
    DiagProbe,
    Inspector,
    MemoryProbe,
    PackageUpdater,
)
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


def create_memory_probe() -> MemoryProbe:
    """Reads the RAM and the memory of each program."""
    from zerobirus.platform.windows.memory import WindowsMemoryProbe

    return WindowsMemoryProbe()


def create_diag_probe() -> DiagProbe:
    """The read-only BigDiag reading."""
    from zerobirus.platform.windows.diag import WindowsDiagProbe
    from zerobirus.platform.windows.inspector import windows_directory

    return WindowsDiagProbe(windows_directory())


def create_package_updater() -> PackageUpdater:
    """winget, by absolute path."""
    from zerobirus.platform.windows.inspector import windows_directory
    from zerobirus.platform.windows.winget import WindowsPackageUpdater

    return WindowsPackageUpdater(windows_directory())


def restart_computer() -> None:
    """Restart in 30 seconds (the person can cancel with ``shutdown /a``)."""
    from zerobirus.platform.windows.inspector import windows_directory
    from zerobirus.platform.windows.power import restart_computer as restart

    restart(windows_directory())


def create_defender_scanner() -> DefenderScanner:
    """Starts and follows a Defender full scan."""
    from zerobirus.platform.windows.defender_scan import WindowsDefenderScanner
    from zerobirus.platform.windows.inspector import windows_directory

    return WindowsDefenderScanner(windows_directory())


from zerobirus.platform.windows.uiprefs import (  # noqa: E402
    animations_enabled,
    high_contrast_active,
    relaunch_elevated,
)

__all__ = [
    "animations_enabled",
    "create_defender_scanner",
    "create_diag_probe",
    "create_inspector",
    "create_memory_probe",
    "create_package_updater",
    "create_remediation_ops",
    "high_contrast_active",
    "relaunch_elevated",
    "restart_computer",
]
