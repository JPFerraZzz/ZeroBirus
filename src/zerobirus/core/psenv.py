"""The environment given to the PowerShell child, built from scratch.

Nothing that decides what runs or where it is found is inherited: ``PATH``, ``PATHEXT``,
``COMSPEC``, ``PSModulePath`` and every ``PS*`` variable are set here from the system
directory (which comes from ``GetSystemWindowsDirectoryW``, never from the environment) or
left out. A few plain per-user variables are copied from an allow list so cmdlets that need a
profile or a temp folder keep working.
"""

from __future__ import annotations

from collections.abc import Mapping

# Copied as they are, case-insensitively. None of these selects a program or a module.
ALLOWED_COPIES = frozenset(
    {
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMPUTERNAME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PUBLIC",
        "SESSIONNAME",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
    }
)
PATHEXT = ".COM;.EXE;.BAT;.CMD"


def build_child_env(system_root: str, source: Mapping[str, str]) -> dict[str, str]:
    root = system_root.rstrip("\\")
    system32 = root + "\\System32"
    env = {
        "SystemRoot": root,
        "windir": root,
        "SystemDrive": root[:2],
        "PATH": f"{system32};{root};{system32}\\Wbem;{system32}\\WindowsPowerShell\\v1.0",
        "PATHEXT": PATHEXT,
        "COMSPEC": system32 + "\\cmd.exe",
        "PSModulePath": system32 + "\\WindowsPowerShell\\v1.0\\Modules",
    }
    for key, value in source.items():
        if key.upper() in ALLOWED_COPIES:
            env[key] = value
    return env
