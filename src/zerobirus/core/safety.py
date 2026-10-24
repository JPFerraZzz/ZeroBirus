"""Safety rules: path normalisation, protected paths and protected processes.

This is the most heavily tested module of the project (BRIEF section 8). It is pure
string logic on Windows paths, with no OS access, so it runs and is tested on Linux.
The backend is responsible for expanding environment variables, resolving 8.3 short
names and resolving links or junctions *before* calling in here. Whatever this module
cannot judge with certainty is treated as protected (fail closed).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_SHORT_NAME_RE = re.compile(r"~\d")


class SignerKind(StrEnum):
    """Who signed a file, as established by the backend (Authenticode)."""

    UNSIGNED = "unsigned"
    MICROSOFT = "microsoft"
    ANTIVIRUS_VENDOR = "antivirus_vendor"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class SystemContext:
    """Machine-specific locations, supplied by the backend (never read from the OS here).

    Every location field is required on purpose: Windows may live on another drive, and an
    empty field would silently mean "nothing protected". ``personal_folders`` must hold the
    folders as resolved by SHGetKnownFolderPath (OneDrive redirection, localised names such
    as "Ambiente de Trabalho"); this module cannot guess them.
    """

    system_root: str
    program_files: tuple[str, ...]
    program_data: str
    users_dir: str
    profile_roots: tuple[str, ...]
    personal_folders: tuple[str, ...]
    own_pids: frozenset[int] = frozenset()


def normalize_windows_path(path: str) -> str:
    """Normalise a Windows path for comparison.

    Handles: case, forward slashes, ``\\\\?\\`` and ``\\\\.\\`` prefixes, ``\\\\?\\UNC\\``,
    ``.`` and ``..``, repeated separators, trailing dots and spaces per component, and
    alternate data streams (``file.txt:stream``). A segment made only of dots and spaces
    (other than ``.`` and ``..``) is dropped here, but how Windows resolves it is
    ambiguous, so ``has_ambiguous_component`` flags it and protection fails closed.

    Paths that are not absolute (relative, drive-relative, unexpanded ``%VAR%``) are
    returned lower-cased and otherwise untouched; ``is_absolute`` tells them apart.
    """
    p = path.replace("/", "\\")
    if p[:8].lower() == "\\\\?\\unc\\":
        p = "\\\\" + p[8:]
    elif p[:4] in ("\\\\?\\", "\\\\.\\"):
        p = p[4:]

    root: str
    rest: str
    if p.startswith("\\\\"):
        segs = [s for s in p.split("\\") if s]
        root = "\\\\" + "\\".join(segs[:2]).lower()
        rest = "\\".join(segs[2:])
    elif _DRIVE_RE.match(p) and p[2:3] == "\\":
        root = p[0].lower() + ":\\"
        rest = p[3:]
    else:
        return p.lower()

    stack: list[str] = []
    for seg in rest.split("\\"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if stack:
                stack.pop()
            continue
        seg = seg.split(":", 1)[0].rstrip(" .")
        if not seg:
            continue
        stack.append(seg.lower())

    if not stack:
        return root
    sep = "" if root.endswith("\\") else "\\"
    return root + sep + "\\".join(stack)


def is_absolute(normalized: str) -> bool:
    """True for a normalised drive-absolute or UNC path."""
    return bool(re.match(r"^[a-z]:\\", normalized)) or normalized.startswith("\\\\")


def has_ambiguous_component(path: str) -> bool:
    """True if a component is only dots/spaces (not ``.``/``..``) or an empty stream name."""
    p = path.replace("/", "\\")
    for seg in p.split("\\"):
        if seg in ("", ".", ".."):
            continue
        if not seg.split(":", 1)[0].rstrip(" ."):
            return True
    return False


def has_short_name(normalized: str) -> bool:
    """True if any component looks like an unresolved 8.3 short name (``PROGRA~1``)."""
    return any(_SHORT_NAME_RE.search(c) for c in normalized.split("\\"))


def is_under(normalized: str, normalized_parent: str) -> bool:
    """True if ``normalized`` equals ``normalized_parent`` or lies inside it."""
    parent = normalized_parent.rstrip("\\")
    return normalized == normalized_parent or normalized.startswith(parent + "\\")


def _is_root(normalized: str) -> bool:
    if normalized.startswith("\\\\"):
        return True
    return bool(re.fullmatch(r"[a-z]:\\", normalized))


def _personal_dirs(ctx: SystemContext) -> list[str]:
    dirs = [normalize_windows_path(p) for p in ctx.personal_folders]
    names = ("documents", "desktop", "pictures", "videos", "music")
    for profile in ctx.profile_roots:
        base = normalize_windows_path(profile)
        dirs.extend(base + "\\" + n for n in names)
        dirs.extend(base + "\\onedrive\\" + n for n in names)
    return dirs


def is_protected_path(
    path: str,
    ctx: SystemContext,
    *,
    link_target: str | None = None,
    signer: SignerKind | None = None,
) -> bool:
    """Return True if remediation must never touch ``path``.

    ``link_target`` is the resolved destination when ``path`` is a link or junction; the
    path is protected if either the link or its destination is.

    PROVISIONAL (Phase 0): everything under Program Files is protected, whatever
    ``signer`` says. The definitive rule, per BRIEF section 8, is by signature: only
    items signed by Microsoft or by an antivirus vendor are protected there, and an
    unsigned executable in Program Files must be able to enter a removal plan. Until the
    signature data flows in from the backend (Phase 1 onwards), ``signer`` is accepted but
    not used. See ``test_unsigned_in_program_files_can_be_removed`` (xfail).
    """
    if link_target is not None and is_protected_path(link_target, ctx, signer=signer):
        return True

    n = normalize_windows_path(path)
    if not is_absolute(n) or has_short_name(n) or has_ambiguous_component(path) or _is_root(n):
        return True

    if is_under(n, normalize_windows_path(ctx.system_root)):
        return True
    for pf in ctx.program_files:
        if is_under(n, normalize_windows_path(pf)):
            return True
    program_data = normalize_windows_path(ctx.program_data)
    if is_under(n, program_data + r"\microsoft\windows defender"):
        return True

    if n in (program_data, normalize_windows_path(ctx.users_dir)):
        return True
    if any(n == normalize_windows_path(p) for p in ctx.profile_roots):
        return True
    return any(is_under(n, d) for d in _personal_dirs(ctx))


_PROTECTED_PROCESS_NAMES = frozenset(
    {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "dwm.exe",
        "fontdrvhost.exe",
        "msmpeng.exe",
        "mssense.exe",
        "securityhealthservice.exe",
        "svchost.exe",
        "explorer.exe",
    }
)
_NO_IMAGE_PATH = frozenset({"system", "registry"})
# Expected install locations of Defender processes: (under ProgramData, under Program Files).
_DEFENDER_LOCATIONS = {
    "msmpeng.exe": (r"\microsoft\windows defender\platform", r"\windows defender"),
    "mssense.exe": (None, r"\windows defender advanced threat protection"),
}


def _expected_location(name: str, n_path: str, ctx: SystemContext) -> bool:
    system_root = normalize_windows_path(ctx.system_root)
    if name == "explorer.exe":
        return n_path == system_root + r"\explorer.exe"
    if name in _DEFENDER_LOCATIONS:
        in_data, in_files = _DEFENDER_LOCATIONS[name]
        if in_data and is_under(n_path, normalize_windows_path(ctx.program_data) + in_data):
            return True
        return any(
            is_under(n_path, normalize_windows_path(pf) + in_files) for pf in ctx.program_files
        )
    return n_path == system_root + "\\system32\\" + name


def is_protected_process(
    name: str,
    path: str | None,
    ctx: SystemContext,
    *,
    pid: int | None = None,
) -> bool:
    """Return True if the process must never be terminated.

    Protection depends on name plus expected path only, never on the signature: a system
    binary with a missing or invalid signature is a finding (Phase 1: SUSPEITO, pointing
    to the Defender offline scan), never a reason to put it in a kill plan. ``System`` and
    ``Registry`` have no image file and are protected by name when no path is reported.
    The same name anywhere else is NOT protected: it is a strong sign of malware.
    ZeroBirus's own processes (``ctx.own_pids``) are always protected.
    """
    if pid is not None and pid in ctx.own_pids:
        return True
    lowered = name.strip().lower()
    if lowered not in _PROTECTED_PROCESS_NAMES:
        return False
    if lowered in _NO_IMAGE_PATH:
        return path in (None, "")
    if not path:
        return False
    n_path = normalize_windows_path(path)
    if not is_absolute(n_path) or has_short_name(n_path):
        return False
    return _expected_location(lowered, n_path, ctx)
