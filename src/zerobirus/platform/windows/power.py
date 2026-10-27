"""Asks Windows to restart. Only called after the person confirmed."""

from __future__ import annotations

import os
import subprocess
import sys

from zerobirus.platform.windows import ps

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_NO_WINDOW = 0x08000000


def restart_computer(system_root: str, seconds: int = 30) -> None:
    exe = os.path.join(system_root, "System32", "shutdown.exe")
    subprocess.run(  # noqa: S603 - absolute path, fixed arguments, no shell
        [exe, "/r", "/t", str(seconds), "/c", "ZeroBirus: reinicio para terminar a verificacao"],
        cwd=os.path.join(system_root, "System32"),
        env=ps.child_environment(system_root),
        creationflags=_NO_WINDOW,
        check=True,
        timeout=30,
    )
