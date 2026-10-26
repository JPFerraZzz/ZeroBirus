"""The Windows Inspector: read-only. Every method returns what it saw and what it could not.

Native APIs first (winreg, psutil, ctypes). PowerShell only for scheduled tasks, Defender,
WMI, Authenticode and shortcut targets, always through ``ps.run_json``.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import sys
from collections.abc import Sequence

import psutil

from zerobirus.core.models import (
    AutorunEntry,
    ConnectionInfo,
    DefenderState,
    FileCandidate,
    FileHash,
    Observed,
    ProcessInfo,
    ServiceInfo,
    Signature,
    TaskInfo,
    WmiBinding,
)
from zerobirus.core.parsing import (
    as_rows,
    parse_defender,
    parse_shortcuts,
    parse_signatures,
    parse_tasks,
    parse_wmi,
)
from zerobirus.core.safety import SystemContext
from zerobirus.platform.windows import files, knownfolders, ps, registry
from zerobirus.platform.windows.paths import canonical_path
from zerobirus.platform.windows.processes import list_processes, own_and_parent_pids

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("zerobirus.platform.windows only works on Windows")

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.GetSystemWindowsDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
_kernel32.GetSystemWindowsDirectoryW.restype = ctypes.c_uint
_shell32 = ctypes.WinDLL("shell32")
_shell32.IsUserAnAdmin.restype = ctypes.c_int

PERSONAL_FOLDERS = (
    knownfolders.DOCUMENTS,
    knownfolders.DESKTOP,
    knownfolders.PICTURES,
    knownfolders.VIDEOS,
    knownfolders.MUSIC,
)
SIGNATURE_BATCH = 200


def _canon(path: str) -> str:
    """The OS's own spelling of an existing path, or the path itself if it cannot be opened."""
    try:
        return canonical_path(path)
    except OSError:
        return path


def windows_directory() -> str:
    buf = ctypes.create_unicode_buffer(260)
    if _kernel32.GetSystemWindowsDirectoryW(buf, 260) == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    return _canon(buf.value)


class WindowsInspector:
    def __init__(self) -> None:
        self._system_root = windows_directory()

    # --- identity -----------------------------------------------------------------------

    def is_elevated(self) -> bool:
        return bool(_shell32.IsUserAnAdmin())

    def system_context(self) -> SystemContext:
        users_dir = registry.profiles_directory(self._system_root) or os.path.dirname(
            knownfolders.known_folder(knownfolders.PROFILE)
        )
        profiles = registry.profile_list(self._system_root)
        roots = [_canon(p) for p in profiles.values() if os.path.isdir(p)]
        current = _canon(knownfolders.known_folder(knownfolders.PROFILE))
        if current.lower() not in {r.lower() for r in roots}:
            roots.append(current)
        personal: list[str] = []
        for folder in PERSONAL_FOLDERS:
            try:
                personal.append(_canon(knownfolders.known_folder(folder)))
            except OSError:
                continue
        program_files = [_canon(knownfolders.known_folder(knownfolders.PROGRAM_FILES))]
        with contextlib.suppress(OSError):
            program_files.append(_canon(knownfolders.known_folder(knownfolders.PROGRAM_FILES_X86)))
        return SystemContext(
            system_root=self._system_root,
            program_files=tuple(dict.fromkeys(program_files)),
            program_data=_canon(knownfolders.known_folder(knownfolders.PROGRAM_DATA)),
            users_dir=_canon(users_dir),
            profile_roots=tuple(roots),
            personal_folders=tuple(dict.fromkeys(personal)),
            own_pids=own_and_parent_pids(),
        )

    # --- registry and file system -------------------------------------------------------

    def processes(self) -> Observed[ProcessInfo]:
        return list_processes()

    def autoruns(self) -> Observed[AutorunEntry]:
        profiles = registry.profile_list(self._system_root)
        observed = registry.collect_autoruns(profiles, self._system_root)
        gaps = list(observed.gaps)
        folders: list[tuple[str, str]] = [
            ("comum", knownfolders.known_folder(knownfolders.COMMON_STARTUP))
        ]
        folders += [
            (os.path.basename(root), os.path.join(root, files.STARTUP_SUBPATH))
            for root in profiles.values()
        ]
        startup, folder_gaps = files.startup_folder_files(folders)
        gaps += folder_gaps
        lnk = [p for _, _, p in startup if p.lower().endswith(".lnk")]
        resolved: dict[str, str] = {}
        if lnk:
            try:
                out = ps.run_json("shortcuts", {"paths": lnk}, system_root=self._system_root)
                resolved = parse_shortcuts(out.items)
                gaps += [f"atalhos de Arranque: {e}" for e in out.errors]
            except ps.PowerShellError as exc:
                gaps.append(f"os atalhos de Arranque não foram resolvidos: {exc}")
        return Observed(
            (*observed.items, *files.startup_entries(startup, resolved)), tuple(dict.fromkeys(gaps))
        )

    def services(self) -> Observed[ServiceInfo]:
        return registry.collect_services(self._system_root)

    def connections(self) -> Observed[ConnectionInfo]:
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return Observed((), ("sem administrador não é possível listar as ligações de rede",))
        out = [
            ConnectionInfo(c.pid, str(c.raddr.ip), int(c.raddr.port), str(c.status))
            for c in conns
            if c.raddr
        ]
        return Observed(tuple(out))

    def hosts_lines(self) -> Observed[str]:
        return files.read_hosts(
            os.path.join(self._system_root, "System32", "drivers", "etc", "hosts")
        )

    def candidate_files(self) -> Observed[FileCandidate]:
        ctx = self.system_context()
        # Most likely first: where droppers and persistence usually live.
        roots: list[str] = []
        for profile in ctx.profile_roots:
            roots += [
                os.path.join(profile, "AppData", "Roaming"),
                os.path.join(profile, "AppData", "Local", "Temp"),
                os.path.join(profile, "Downloads"),
            ]
        roots += [os.path.join(ctx.users_dir, "Public"), os.path.join(ctx.system_root, "Temp")]
        for profile in ctx.profile_roots:
            roots.append(os.path.join(profile, "AppData", "Local"))
        roots.append(ctx.program_data)
        return files.search_roots(r for r in roots if os.path.isdir(r))

    def file_hashes(self, paths: Sequence[str]) -> Observed[FileHash]:
        return files.sha256_of(paths)

    # --- PowerShell ---------------------------------------------------------------------

    def scheduled_tasks(self) -> Observed[TaskInfo]:
        try:
            out = ps.run_json("tasks", None, system_root=self._system_root)
        except ps.PowerShellError as exc:
            return Observed((), (f"as tarefas agendadas não foram lidas: {exc}",))
        parsed = parse_tasks(out.items, elevated=self.is_elevated())
        extra = tuple(f"tarefas agendadas: {e}" for e in out.errors)
        return Observed(parsed.items, (*parsed.gaps, *extra))

    def defender(self) -> Observed[DefenderState]:
        try:
            out = ps.run_json("defender", None, system_root=self._system_root)
        except ps.PowerShellError as exc:
            return Observed((), (f"o estado do Defender não foi lido: {exc}",))
        return parse_defender(out.items, elevated=self.is_elevated())

    def wmi_bindings(self) -> Observed[WmiBinding]:
        try:
            out = ps.run_json("wmi", None, system_root=self._system_root)
        except ps.PowerShellError as exc:
            return Observed((), (f"as assinaturas WMI não foram lidas: {exc}",))
        return Observed(parse_wmi(out.items), tuple(f"assinaturas WMI: {e}" for e in out.errors))

    def signatures(self, paths: Sequence[str]) -> Observed[Signature]:
        found: list[Signature] = []
        gaps: list[str] = []
        existing = [p for p in dict.fromkeys(paths) if os.path.isfile(p)]
        for start in range(0, len(existing), SIGNATURE_BATCH):
            batch = existing[start : start + SIGNATURE_BATCH]
            try:
                out = ps.run_json("signatures", {"paths": batch}, system_root=self._system_root)
            except ps.PowerShellError as exc:
                gaps.append(f"assinaturas não verificadas: {exc}")
                continue
            found += parse_signatures(out.items)
            failed = [r for r in as_rows(out.items) if r.get("status") == -1]
            if failed:
                detail = str(failed[0].get("detail", ""))[:160]
                gaps.append(
                    f"não foi possível verificar a assinatura de {len(failed)} ficheiros: {detail}"
                )
        return Observed(tuple(found), tuple(dict.fromkeys(gaps)))
