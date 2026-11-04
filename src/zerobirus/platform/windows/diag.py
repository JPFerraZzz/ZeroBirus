"""BigDiag and AllDrivers on Windows: CIM and storage cmdlets through the one PowerShell bridge,
read only."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any, cast

from zerobirus.platform.windows import ps

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_TIMEOUT = 180.0  # event logs and the Windows Update search can be slow


class WindowsDiagProbe:
    """Runs one read-only script (``bigdiag`` or ``drivers``) and returns its single object."""

    def __init__(self, system_root: str, script: str = "bigdiag") -> None:
        self._root = system_root
        self._script = script

    def read(self) -> Mapping[str, Any]:
        out = ps.run_json(self._script, {}, system_root=self._root, timeout=_TIMEOUT)
        items: Any = out.items
        head: Any = items[0] if isinstance(items, list) and items else items  # pyright: ignore[reportUnknownVariableType]
        return cast("dict[str, Any]", head) if isinstance(head, dict) else {}
