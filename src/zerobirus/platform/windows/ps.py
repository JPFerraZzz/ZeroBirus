"""The single bridge to PowerShell (BRIEF section 7).

Only used where there is no reasonable native alternative: scheduled tasks, Defender, WMI,
Authenticode and shortcut targets. Rules:

- ``powershell.exe`` by absolute path built from the system directory (which comes from
  ``GetSystemWindowsDirectoryW``, never from the environment), never from PATH or the
  current directory (an infected PC may have a fake one there).
- The child's environment is built from scratch from an allow list (``core.psenv``): no
  inherited ``PATH``, ``PATHEXT``, ``COMSPEC``, ``PSModulePath`` or ``PS*`` variables.
- ``-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand``; the script comes
  from a file shipped in this package, never from data.
- User data goes in as JSON on stdin (ASCII-escaped, so no code page can change it), never
  concatenated into the command.
- Output is forced to UTF-8 and is always JSON: ``{"items": [...], "errors": [...]}``. Each
  script handles errors per item, so a partial read comes back as items plus the list of what
  failed, not as an abort.
- A timeout, a 32 MB cap on the output (the child is killed above it), and stderr cut to a
  few KB and passed through the redactor before it can reach a message.
- Nothing the script prints is executed or evaluated.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from dataclasses import dataclass
from importlib import resources
from typing import Any

from zerobirus.core.parsing import parse_ps_envelope
from zerobirus.core.psenv import build_child_env
from zerobirus.core.redact import redact
from zerobirus.platform.subprocess_utils import OutputTooLarge, TimedOut, run_limited

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

CREATE_NO_WINDOW = 0x08000000
DEFAULT_TIMEOUT = 60.0
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_STDERR_BYTES = 8 * 1024
MAX_MESSAGE_CHARS = 300

_PREAMBLE = """\
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ParamsJson = [Console]::In.ReadToEnd()
$Params = $null
if ($ParamsJson) { $Params = $ParamsJson | ConvertFrom-Json }
$result = $null
$errors = @()
"""
_EPILOGUE = """
$out = [ordered]@{
    items = @($result | Where-Object { $_ -ne $null })
    errors = @($errors | Where-Object { $_ })
}
ConvertTo-Json -InputObject $out -Depth 6 -Compress
"""


class PowerShellError(RuntimeError):
    """The script failed, timed out or returned something that is not JSON."""


def powershell_path(system_root: str) -> str:
    return os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def script_text(name: str) -> str:
    return resources.files(__package__).joinpath("scripts", f"{name}.ps1").read_text("utf-8")


def child_environment(system_root: str) -> dict[str, str]:
    return build_child_env(system_root, os.environ)


def encode_command(script: str) -> str:
    return base64.b64encode((_PREAMBLE + script + _EPILOGUE).encode("utf-16-le")).decode("ascii")


@dataclass(frozen=True, slots=True)
class PsOutput:
    """What a script returned: the items it read and what it could not read."""

    items: Any
    errors: tuple[str, ...]


def _message(raw: bytes) -> str:
    return redact(raw.decode("utf-8", errors="replace").strip())[:MAX_MESSAGE_CHARS]


def run_json(
    script: str,
    params: dict[str, Any] | None,
    *,
    system_root: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> PsOutput:
    """Run a packaged script and return its items and per-item errors."""
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
        done = run_limited(
            args,
            stdin=stdin,
            timeout=timeout,
            max_stdout=MAX_OUTPUT_BYTES,
            max_stderr=MAX_STDERR_BYTES,
            cwd=os.path.join(system_root, "System32"),
            env=child_environment(system_root),
            creationflags=CREATE_NO_WINDOW,
        )
    except TimedOut as exc:
        raise PowerShellError(f"o PowerShell excedeu {timeout:.0f} s ({script})") from exc
    except OutputTooLarge as exc:
        raise PowerShellError(f"o PowerShell devolveu demasiados dados ({script})") from exc
    out = done.stdout.decode("utf-8-sig", errors="replace").strip()
    if done.returncode != 0:
        raise PowerShellError(
            f"o PowerShell falhou ({script}): {_message(done.stderr) or done.returncode}"
        )
    try:
        items, errors = parse_ps_envelope(out)
    except ValueError as exc:
        raise PowerShellError(f"o PowerShell devolveu algo inesperado ({script}): {exc}") from exc
    return PsOutput(items, tuple(_message(e.encode("utf-8")) for e in errors))
