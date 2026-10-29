"""winget on Windows, by absolute path (D-016): the Windows package manager downloads, not us.

The program is ``winget.exe`` in the current user's ``WindowsApps`` folder, as the shell
resolves that folder (SHGetKnownFolderPath), never from PATH. Package ids are validated before
they become an argument; arguments go as a list, never through a shell.
"""

from __future__ import annotations

import os
import sys

from zerobirus.core.allup import PACKAGE_ID, Upgrade, parse_upgrades
from zerobirus.core.redact import redact
from zerobirus.platform.subprocess_utils import OutputTooLarge, TimedOut, run_limited
from zerobirus.platform.windows import ps
from zerobirus.platform.windows.knownfolders import LOCAL_APP_DATA, known_folder

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_NO_WINDOW = 0x08000000
_LIST_TIMEOUT = 180.0
_UPDATE_TIMEOUT = 1800.0
_MAX_OUTPUT = 4 * 1024 * 1024
_COMMON = ("--accept-source-agreements", "--disable-interactivity")


def winget_path() -> str:
    return os.path.join(known_folder(LOCAL_APP_DATA), "Microsoft", "WindowsApps", "winget.exe")


class WindowsPackageUpdater:
    def __init__(self, system_root: str) -> None:
        self._root = system_root

    def _run(self, args: list[str], timeout: float) -> tuple[int, str]:
        exe = winget_path()
        if not os.path.isfile(exe):
            raise RuntimeError("o winget não está instalado neste PC (App Installer da Microsoft)")
        try:
            done = run_limited(
                [exe, *args],
                stdin=b"",
                timeout=timeout,
                max_stdout=_MAX_OUTPUT,
                max_stderr=64 * 1024,
                cwd=os.path.join(self._root, "System32"),
                env=ps.child_environment(self._root),
                creationflags=_NO_WINDOW,
            )
        except TimedOut as exc:
            raise RuntimeError("o winget demorou demasiado") from exc
        except OutputTooLarge as exc:
            raise RuntimeError("o winget devolveu demasiados dados") from exc
        return done.returncode, done.stdout.decode("utf-8", errors="replace")

    def list_upgrades(self) -> tuple[Upgrade, ...]:
        _code, text = self._run(["upgrade", *_COMMON], _LIST_TIMEOUT)
        return parse_upgrades(text)

    def upgrade(self, package_id: str) -> tuple[bool, str]:
        if not PACKAGE_ID.match(package_id):
            raise ValueError("identificador de pacote inválido")
        code, text = self._run(
            [
                "upgrade",
                "--id",
                package_id,
                "--exact",
                "--silent",
                "--accept-package-agreements",
                *_COMMON,
            ],
            _UPDATE_TIMEOUT,
        )
        last = next((ln.strip() for ln in reversed(text.splitlines()) if ln.strip()), "")
        return code == 0, redact(last)[:200]
