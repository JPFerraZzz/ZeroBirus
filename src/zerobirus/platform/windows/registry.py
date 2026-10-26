"""Registry reading with winreg: autoruns of all loaded users, services, profile list.

Read-only. A key that does not exist is normal (nothing there). A key that cannot be read
is a gap: it is reported, never treated as empty.
"""

from __future__ import annotations

import os
import sys
import winreg
from collections.abc import Iterator, Mapping
from typing import Any

from zerobirus.core.models import AutorunEntry, Observed, ServiceInfo
from zerobirus.core.parsing import expand_vars, profile_variables

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

RUN_KEYS = (
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "run"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "runonce"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "policies_run"),
)
WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
WINDOWS_NT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
PROFILE_LIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
SERVICES = r"SYSTEM\CurrentControlSet\Services"
VIEWS = ((winreg.KEY_WOW64_64KEY, "64"), (winreg.KEY_WOW64_32KEY, "32"))
USER_SID_PREFIX = "S-1-5-21-"
_STRING_TYPES = (winreg.REG_SZ, winreg.REG_EXPAND_SZ)
_START = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
_WIN32_SERVICE = 0x30  # own process (0x10) or shared process (0x20)


def _open(root: int, path: str, view: int) -> Any:
    return winreg.OpenKey(root, path, 0, winreg.KEY_READ | view)


def _values(root: int, path: str, view: int) -> Iterator[tuple[str, Any, int]]:
    with _open(root, path, view) as key:
        i = 0
        while True:
            try:
                yield winreg.EnumValue(key, i)
            except OSError:
                return
            i += 1


def _subkeys(root: int, path: str, view: int) -> list[str]:
    names: list[str] = []
    with _open(root, path, view) as key:
        i = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, i))
            except OSError:
                return names
            i += 1


def _value(root: int, path: str, view: int, name: str) -> tuple[Any, int] | None:
    try:
        with _open(root, path, view) as key:
            return winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return None


def machine_variables() -> dict[str, str]:
    return dict(os.environ)


def profile_list() -> dict[str, str]:
    """SID to profile folder for real user accounts (S-1-5-21-...)."""
    out: dict[str, str] = {}
    for sid in _subkeys(winreg.HKEY_LOCAL_MACHINE, PROFILE_LIST, winreg.KEY_WOW64_64KEY):
        if not sid.startswith(USER_SID_PREFIX):
            continue
        got = _value(
            winreg.HKEY_LOCAL_MACHINE,
            f"{PROFILE_LIST}\\{sid}",
            winreg.KEY_WOW64_64KEY,
            "ProfileImagePath",
        )
        if got is not None and isinstance(got[0], str):
            out[sid] = expand_vars(got[0], machine_variables())
    return out


def profiles_directory() -> str | None:
    got = _value(
        winreg.HKEY_LOCAL_MACHINE, PROFILE_LIST, winreg.KEY_WOW64_64KEY, "ProfilesDirectory"
    )
    return expand_vars(got[0], machine_variables()) if got and isinstance(got[0], str) else None


def _entries_under(
    root: int, prefix: str, label: str, user: str, variables: Mapping[str, str], gaps: list[str]
) -> list[AutorunEntry]:
    out: list[AutorunEntry] = []
    for path, kind in RUN_KEYS:
        for view, view_name in VIEWS:
            try:
                for name, data, vtype in _values(root, f"{prefix}{path}", view):
                    if vtype in _STRING_TYPES and isinstance(data, str):
                        out.append(
                            AutorunEntry(
                                f"{label}\\{path} ({view_name})",
                                name,
                                expand_vars(data, variables),
                                user,
                                kind,
                            )
                        )
            except FileNotFoundError:
                continue
            except OSError as exc:
                gaps.append(f"não foi possível ler {label}\\{path} ({view_name}): {exc.strerror}")
    return out


def _winlogon_entries(
    root: int,
    prefix: str,
    label: str,
    user: str,
    names: tuple[str, ...],
    variables: Mapping[str, str],
) -> list[AutorunEntry]:
    out: list[AutorunEntry] = []
    for name in names:
        got = _value(root, f"{prefix}{WINLOGON}", winreg.KEY_WOW64_64KEY, name)
        if got is not None and isinstance(got[0], str):
            out.append(
                AutorunEntry(
                    f"{label}\\{WINLOGON}", name, expand_vars(got[0], variables), user, "winlogon"
                )
            )
    return out


def collect_autoruns(profiles: Mapping[str, str]) -> Observed[AutorunEntry]:
    """Run/RunOnce/Policies Run for the machine and every loaded user, Winlogon, AppInit, IFEO."""
    entries: list[AutorunEntry] = []
    gaps: list[str] = []
    env = machine_variables()
    hklm = winreg.HKEY_LOCAL_MACHINE

    entries += _entries_under(hklm, "", "HKLM", "", env, gaps)
    entries += _winlogon_entries(hklm, "", "HKLM", "", ("Shell", "Userinit"), env)
    for view, view_name in VIEWS:
        got = _value(hklm, WINDOWS_NT, view, "AppInit_DLLs")
        if got is not None and isinstance(got[0], str):
            entries.append(
                AutorunEntry(
                    f"HKLM\\{WINDOWS_NT} ({view_name})",
                    "AppInit_DLLs",
                    expand_vars(got[0], env),
                    "",
                    "appinit",
                )
            )
        try:
            for image in _subkeys(hklm, IFEO, view):
                got = _value(hklm, f"{IFEO}\\{image}", view, "Debugger")
                if got is not None and isinstance(got[0], str) and got[0].strip():
                    entries.append(
                        AutorunEntry(
                            f"HKLM\\{IFEO} ({view_name})",
                            image,
                            expand_vars(got[0], env),
                            "",
                            "ifeo",
                        )
                    )
        except OSError as exc:
            gaps.append(
                f"não foi possível ler Image File Execution Options ({view_name}): {exc.strerror}"
            )

    loaded: set[str] = set()
    try:
        sids = _subkeys(winreg.HKEY_USERS, "", winreg.KEY_WOW64_64KEY)
    except OSError as exc:
        sids = []
        gaps.append(
            f"não foi possível listar os utilizadores com sessão (HKEY_USERS): {exc.strerror}"
        )
    for sid in sids:
        if not sid.startswith(USER_SID_PREFIX) or sid.endswith("_Classes"):
            continue
        loaded.add(sid)
        root_dir = profiles.get(sid)
        variables = profile_variables(root_dir) if root_dir else env
        who = os.path.basename(root_dir) if root_dir else sid
        prefix = sid + "\\"
        entries += _entries_under(winreg.HKEY_USERS, prefix, f"HKU\\{sid}", who, variables, gaps)
        entries += _winlogon_entries(
            winreg.HKEY_USERS, prefix, f"HKU\\{sid}", who, ("Shell",), variables
        )
    for sid, root_dir in profiles.items():
        if sid not in loaded:
            gaps.append(
                f"o registo do perfil '{os.path.basename(root_dir)}' não está carregado: "
                "o seu arranque pelo registo não foi lido"
            )
    return Observed(tuple(entries), tuple(dict.fromkeys(gaps)))


def collect_services(system_root: str) -> Observed[ServiceInfo]:
    """Win32 services from the registry (not drivers). Native read, no PowerShell."""
    services: list[ServiceInfo] = []
    gaps: list[str] = []
    env = machine_variables()
    hklm = winreg.HKEY_LOCAL_MACHINE
    try:
        names = _subkeys(hklm, SERVICES, winreg.KEY_WOW64_64KEY)
    except OSError as exc:
        return Observed((), (f"não foi possível listar os serviços: {exc.strerror}",))
    for name in names:
        try:
            values = {
                n.lower(): d
                for n, d, _ in _values(hklm, f"{SERVICES}\\{name}", winreg.KEY_WOW64_64KEY)
            }
        except OSError:
            gaps.append(f"serviço {name} não legível")
            continue
        stype, image = values.get("type"), values.get("imagepath")
        if not isinstance(stype, int) or not stype & _WIN32_SERVICE or not isinstance(image, str):
            continue
        command = expand_vars(image, env)
        if command.lower().startswith("\\systemroot\\"):
            command = system_root + command[len("\\SystemRoot") :]
        start = values.get("start")
        display = values.get("displayname")
        account = values.get("objectname")
        services.append(
            ServiceInfo(
                name=name,
                display_name=display if isinstance(display, str) else name,
                image_command=command,
                start=_START.get(start, "unknown") if isinstance(start, int) else "unknown",
                account=account if isinstance(account, str) else "",
            )
        )
    return Observed(
        tuple(services),
        tuple(gaps[:5]) + (("e mais serviços não legíveis",) if len(gaps) > 5 else ()),
    )
