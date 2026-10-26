"""Windows backend. The only place where Windows-specific code may live.

Imported only when ``sys.platform == "win32"`` (through ``platform/loader.py``).
"""

from __future__ import annotations

import sys

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

from zerobirus.platform.base import Inspector


def create_inspector() -> Inspector:
    """The read-only Windows Inspector."""
    from zerobirus.platform.windows.inspector import WindowsInspector

    return WindowsInspector()
