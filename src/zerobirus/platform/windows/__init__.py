"""Windows backend. The only place where Windows-specific code may live.

Imported only when ``sys.platform == "win32"``. Empty in Phase 0; the Inspector comes in
Phase 1. It exists now so mypy and pyright cover the directory from the start.
"""

from __future__ import annotations

import sys

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")
