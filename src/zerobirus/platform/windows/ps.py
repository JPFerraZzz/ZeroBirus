"""The single bridge to PowerShell (BRIEF section 7).

Only used where there is no reasonable native alternative: scheduled tasks, Defender, WMI,
Authenticode and shortcut targets. Rules:

- ``powershell.exe`` by absolute path built from the system directory, never from PATH or
  the current directory (an infected PC may have a fake one there).
- ``-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand``; the script comes
  from a file shipped in this package, never from data.
- User data goes in as JSON on stdin (ASCII-escaped, so no code page can change it), never
  concatenated into the command.
- Output is forced to UTF-8 and is always JSON (``@()`` keeps single results as lists).
- A timeout on every call. Nothing the script prints is executed or evaluated.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from importlib import resources
from typing import Any

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

CREATE_NO_WINDOW = 0x08000000
DEFAULT_TIMEOUT = 60.0

_PREAMBLE = """\
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ParamsJson = [Console]::In.ReadToEnd()
$Params = $null
if ($ParamsJson) { $Params = $ParamsJson | ConvertFrom-Json }
$result = $null
"""
_EPILOGUE = """
ConvertTo-Json -InputObject @($result) -Depth 6 -Compress
"""


class PowerShellError(RuntimeError):
    """The script failed, timed out or returned something that is not JSON."""


def powershell_path(system_root: str) -> str:
    return os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def script_text(name: str) -> str:
    return resources.files(__package__).joinpath("scripts", f"{name}.ps1").read_text("utf-8")


def encode_command(script: str) -> str:
    return base64.b64encode((_PREAMBLE + script + _EPILOGUE).encode("utf-16-le")).decode("ascii")


def run_json(
    script: str,
    params: dict[str, Any] | None,
    *,
    system_root: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Any:
    """Run a packaged script and return its JSON result (always a list)."""
    exe = powershell_path(system_root)
    if not os.path.isfile(exe):
        raise PowerShellError("powershell.exe não foi encontrado na pasta do sistema")
    args = [
        exe,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encode_command(script_text(script)),
    ]
    stdin = json.dumps(params if params is not None else {}, ensure_ascii=True).encode("ascii")
    try:
        done = subprocess.run(  # noqa: S603 - absolute path, fixed arguments, no shell
            args,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            cwd=os.path.join(system_root, "System32"),
            creationflags=CREATE_NO_WINDOW,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PowerShellError(f"o PowerShell excedeu {timeout:.0f} s ({script})") from exc
    out = done.stdout.decode("utf-8-sig", errors="replace").strip()
    if done.returncode != 0:
        err = done.stderr.decode("utf-8", errors="replace").strip()[:300]
        raise PowerShellError(f"o PowerShell falhou ({script}): {err or done.returncode}")
    if not out:
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise PowerShellError(f"o PowerShell devolveu algo que não é JSON ({script})") from exc
