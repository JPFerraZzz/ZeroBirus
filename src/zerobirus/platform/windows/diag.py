"""BigDiag on Windows: CIM and storage cmdlets through the one PowerShell bridge, read only."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any, cast

from zerobirus.platform.windows import ps

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_TIMEOUT = 180.0  # event logs on a slow disk


class WindowsDiagProbe:
    def __init__(self, system_root: str) -> None:
        self._root = system_root

    def read(self) -> Mapping[str, Any]:
        out = ps.run_json("bigdiag", {}, system_root=self._root, timeout=_TIMEOUT)
        items: Any = out.items
        head: Any = items[0] if isinstance(items, list) and items else items  # pyright: ignore[reportUnknownVariableType]
        return cast("dict[str, Any]", head) if isinstance(head, dict) else {}
