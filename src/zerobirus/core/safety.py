"""Safety rules: path normalisation, protected paths and protected processes.

This is the most heavily tested module of the project (BRIEF section 8). It is pure
string logic on Windows paths, with no OS access, so it runs and is tested on Linux.

Contract with the backend: paths handed in here must be canonical, obtained with
GetFinalPathNameByHandle (links, junctions and 8.3 names resolved), never raw text taken
from a process or the registry. Whatever this module cannot judge with certainty is
treated as protected (fail closed): unresolved short names, relative or malformed paths,
wildcards, control characters, device names, ambiguous segments, UNC paths, drive roots.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ABS_RE = re.compile(r"^[a-z]:\\")
_SHORT_NAME_RE = re.compile(r"~\d")
# Wildcards, characters invalid in file names, and '%' (a second environment-variable
# expansion somewhere downstream must never turn a path into another one).
_UNSAFE_CHARS = frozenset('<>"|?*%')
_MAX_PATH_CHARS = 32767

_RESERVED_DEVICES = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$", "clock$"}
    | {f"com{i}" for i in range(10)}
    | {f"lpt{i}" for i in range(10)}
)

# Names that are protected directly under the root of ANY drive (another Windows install,
# boot and recovery data, paging files). Matched as whole components.
_ROOT_PROTECTED = frozenset(
    {
        "windows",
        "boot",
        "bootmgr",
        "bootnxt",
        "efi",
        "recovery",
        "system volume information",
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
        "$recycle.bin",
        "$winreagent",
    }
)

_PERSONAL_NAMES = frozenset({"documents", "desktop", "pictures", "videos", "music"})
_BUILTIN_PROFILES = frozenset({"default", "default user", "all users", "defaultuser0"})
_HIVE_PREFIXES = ("ntuser.dat", "usrclass.dat")


class SignerKind(StrEnum):
    """Who signed a file, as established by the backend (Authenticode)."""

    UNSIGNED = "unsigned"
    MICROSOFT = "microsoft"
    ANTIVIRUS_VENDOR = "antivirus_vendor"
    OTHER = "other"


def _fold(text: str, *, compat: bool) -> str:
    """Case-fold the way Windows might, and (optionally) apply compatibility folding.

    NFKC maps full-width letters, dots and separators onto ASCII (ANSI best-fit mapping does
    similar things). ``upper().lower()`` also catches letters such as the long s, which
    upper-case to an ASCII letter. Over-matching is harmless here: it can only protect more.
    """
    if compat:
        text = unicodedata.normalize("NFKC", text)
    return text.upper().lower()


def _strip_prefix(p: str) -> str:
    """Remove ``\\\\?\\`` and ``\\\\.\\`` prefixes. Expects lower-case, backslash separators."""
    if p[:8] == "\\\\?\\unc\\":
        return "\\\\" + p[8:]
    if p[:4] in ("\\\\?\\", "\\\\.\\"):
        return p[4:]
    return p


def normalize_windows_path(path: str, *, compat: bool = True, collapse: bool = True) -> str:
    """Normalise a Windows path for comparison.

    Handles: case, forward slashes, ``\\\\?\\`` and ``\\\\.\\`` prefixes, ``\\\\?\\UNC\\``,
    ``.`` and ``..``, repeated separators, trailing dots and spaces per component, and
    alternate data streams (``file.txt:stream``, ``::$DATA``). A segment made only of dots
    and spaces (other than ``.`` and ``..``) is dropped here, but how Windows resolves it
    is ambiguous, so ``has_ambiguous_component`` flags it and protection fails closed.

    ``compat`` applies NFKC; ``collapse=False`` keeps ``..`` as a literal component (as in
    ``\\\\?\\`` paths). ``is_protected_path`` evaluates all four combinations.

    Paths that are not absolute (relative, drive-relative, unexpanded ``%VAR%``) are
    returned folded and otherwise untouched; ``is_absolute`` tells them apart.
    """
    p = _strip_prefix(_fold(path, compat=compat).replace("/", "\\"))

    root: str
    rest: str
    if p.startswith("\\\\"):
        segs = [s for s in p.split("\\") if s]
        root = "\\\\" + "\\".join(segs[:2])
        rest = "\\".join(segs[2:])
    elif _DRIVE_RE.match(p) and p[2:3] == "\\":
        root = p[0] + ":\\"
        rest = p[3:]
    else:
        return p

    stack: list[str] = []
    for seg in rest.split("\\"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not collapse:
                stack.append(seg)
            elif stack:
                stack.pop()
            continue
        seg = seg.split(":", 1)[0].rstrip(" .")
        if seg:
            stack.append(seg)

    if not stack:
        return root
    sep = "" if root.endswith("\\") else "\\"
    return root + sep + "\\".join(stack)


def is_absolute(normalized: str) -> bool:
    """True for a normalised drive-absolute or UNC path."""
    return bool(_ABS_RE.match(normalized)) or normalized.startswith("\\\\")


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


def has_unsafe_characters(path: str) -> bool:
    """True for control characters (including NUL), wildcards, and over-long paths."""
    if len(path) > _MAX_PATH_CHARS:
        return True
    p = _strip_prefix(_fold(path, compat=True).replace("/", "\\"))
    return any(ord(c) < 32 or c in _UNSAFE_CHARS for c in p)


def has_reserved_device_name(normalized: str) -> bool:
    """True if any component is a DOS device name (``NUL``, ``COM1``, ``CON.txt`` ...)."""
    return any(c.split(".")[0].rstrip(" ") in _RESERVED_DEVICES for c in normalized.split("\\"))


def is_under(normalized: str, normalized_parent: str) -> bool:
    """True if ``normalized`` equals ``normalized_parent`` or lies inside it."""
    parent = normalized_parent.rstrip("\\")
    return normalized == normalized_parent or normalized.startswith(parent + "\\")


def _is_root(normalized: str) -> bool:
    if normalized.startswith("\\\\"):
        return True
    return bool(re.fullmatch(r"[a-z]:\\", normalized))


def _require_location(name: str, value: str) -> str:
    n = normalize_windows_path(value)
    # _is_root also rejects every UNC path.
    if (
        not value
        or not is_absolute(n)
        or has_short_name(n)
        or has_unsafe_characters(value)
        or _is_root(n)
    ):
        raise ValueError(f"SystemContext.{name} must be a canonical absolute drive path: {value!r}")
    return n


@dataclass(frozen=True, slots=True)
class SystemContext:
    """Machine-specific locations, supplied by the backend (never read from the OS here).

    Every location field is required on purpose: Windows may live on another drive, and an
    empty field would silently mean "nothing protected". Empty or non-canonical values are
    rejected at construction. ``personal_folders`` must hold the folders as resolved by
    SHGetKnownFolderPath (OneDrive redirection, localised names such as "Ambiente de
    Trabalho"); this module cannot guess them. ``own_pids`` must include ZeroBirus's own
    process, its parent and its children.
    """

    system_root: str
    program_files: tuple[str, ...]
    program_data: str
    users_dir: str
    profile_roots: tuple[str, ...]
    personal_folders: tuple[str, ...]
    own_pids: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        _require_location("system_root", self.system_root)
        _require_location("program_data", self.program_data)
        _require_location("users_dir", self.users_dir)
        if not self.program_files:
            raise ValueError("SystemContext.program_files must not be empty")
        if not self.profile_roots:
            raise ValueError("SystemContext.profile_roots must not be empty")
        for pf in self.program_files:
            _require_location("program_files", pf)
        for root in self.profile_roots:
            _require_location("profile_roots", root)
        for folder in self.personal_folders:
            _require_location("personal_folders", folder)


def _profile_parts_protected(parts: list[str]) -> bool:
    """Rules inside one profile. ``parts[0]`` is the profile name, the rest is relative to it."""
    profile = parts[0]
    if len(parts) == 1 or profile in _BUILTIN_PROFILES:
        return True
    sub = parts[1]
    if sub in _PERSONAL_NAMES:
        return True
    if sub.startswith("onedrive"):
        return len(parts) == 2 or parts[2] in _PERSONAL_NAMES
    if sub == "downloads":
        return len(parts) == 2
    if sub == "appdata":
        if len(parts) == 2:
            return True
        if len(parts) == 3:
            return parts[2] in ("local", "roaming", "locallow")
        return len(parts) == 4 and parts[2] == "local" and parts[3] == "temp"
    return False


def _relative_parts(n: str, parent: str) -> list[str]:
    return n[len(parent.rstrip("\\")) + 1 :].split("\\")


def _profile_protected(n: str, users: str, profile_roots: tuple[str, ...]) -> bool:
    """Profile rules for ANY profile under the users directory and for each known root."""
    if is_under(n, users) and n != users and _profile_parts_protected(_relative_parts(n, users)):
        return True
    for root in map(normalize_windows_path, profile_roots):
        if not is_under(n, root):
            continue
        parts = ["profile"] if n == root else ["profile", *_relative_parts(n, root)]
        if _profile_parts_protected(parts):
            return True
    return False


def _normalized_is_protected(n: str, ctx: SystemContext) -> bool:
    if not is_absolute(n) or has_short_name(n) or _is_root(n) or has_reserved_device_name(n):
        return True
    if n.rsplit("\\", 1)[-1].startswith(_HIVE_PREFIXES):
        return True
    if re.match(r"^[a-z]:\\([^\\]+)(\\|$)", n):
        first = n.split("\\")[1]
        if first in _ROOT_PROTECTED:
            return True

    if is_under(n, normalize_windows_path(ctx.system_root)):
        return True
    # PROVISIONAL (Phase 0): all of Program Files; the final rule is by signature.
    if any(is_under(n, normalize_windows_path(pf)) for pf in ctx.program_files):
        return True
    program_data = normalize_windows_path(ctx.program_data)
    if n == program_data:
        return True
    for sub in (
        r"\microsoft\windows defender",
        r"\microsoft\windows defender advanced threat protection",
    ):
        if is_under(n, program_data + sub):
            return True

    users = normalize_windows_path(ctx.users_dir)
    if n == users or _profile_protected(n, users, ctx.profile_roots):
        return True
    return any(is_under(n, normalize_windows_path(p)) for p in ctx.personal_folders)


def is_protected_path(
    path: str,
    ctx: SystemContext,
    *,
    link_target: str | None = None,
    signer: SignerKind | None = None,
) -> bool:
    """Return True if remediation must never touch ``path``.

    ``link_target`` is the final resolved destination when ``path`` is a link or junction;
    the path is protected if either the link or its destination is. The backend resolves
    whole chains (GetFinalPathNameByHandle) before calling.

    The path is evaluated under every plausible reading (with and without compatibility
    folding, with ``..`` collapsed and kept literally); it is protected if any reading is.

    PROVISIONAL (Phase 0): everything under Program Files is protected, whatever
    ``signer`` says. The definitive rule, per BRIEF section 8, is by signature: only
    items signed by Microsoft or by an antivirus vendor are protected there, and an
    unsigned executable in Program Files must be able to enter a removal plan. Until the
    signature data flows in from the backend (Phase 1 onwards), ``signer`` is accepted but
    not used. See ``test_unsigned_in_program_files_can_be_removed`` (xfail).
    """
    if link_target is not None and is_protected_path(link_target, ctx, signer=signer):
        return True

    if has_unsafe_characters(path):
        return True
    forms = {path, _fold(path, compat=True)}
    if any(has_ambiguous_component(f) for f in forms):
        return True
    return any(
        _normalized_is_protected(normalize_windows_path(path, compat=c, collapse=k), ctx)
        for c in (True, False)
        for k in (True, False)
    )


# Process names (lower-case). System-folder binaries live in System32 (or SysWOW64).
_SYSTEM32_PROCESSES = frozenset(
    {
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "dwm.exe",
        "fontdrvhost.exe",
        "securityhealthservice.exe",
        "svchost.exe",
        "sgrmbroker.exe",
        "lsaiso.exe",
    }
)
# Kernel pseudo-processes: no image file, so no path.
_NO_IMAGE_PROCESSES = frozenset(
    {"system", "registry", "memory compression", "secure system", "system idle process"}
)
# Expected install locations of Defender processes: (under ProgramData, under Program Files).
_DEFENDER_LOCATIONS = {
    "msmpeng.exe": (r"\microsoft\windows defender\platform", r"\windows defender"),
    "nissrv.exe": (r"\microsoft\windows defender\platform", r"\windows defender"),
    "mssense.exe": (None, r"\windows defender advanced threat protection"),
}
_PROTECTED_PROCESS_NAMES = (
    _SYSTEM32_PROCESSES
    | _NO_IMAGE_PROCESSES
    | frozenset(_DEFENDER_LOCATIONS)
    | frozenset({"explorer.exe"})
)


def _process_key(name: str) -> str:
    key = _fold(name, compat=True).strip().replace("/", "\\").rpartition("\\")[2]
    key = key.strip().rstrip(" .")
    if key + ".exe" in _PROTECTED_PROCESS_NAMES:
        key += ".exe"
    return key


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
    return n_path in (
        system_root + "\\system32\\" + name,
        system_root + "\\syswow64\\" + name,
    )


def _path_is_canonical(path: str) -> bool:
    """True if normalisation changes nothing but case and an optional extended-length prefix."""
    # Whitespace, compatibility characters, dot-only segments and streams are all removed by
    # normalisation, so the final comparison with the original already rejects them.
    if has_unsafe_characters(path):
        return False
    n = normalize_windows_path(path)
    if not is_absolute(n) or n.startswith("\\\\") or has_short_name(n):
        return False
    body = path[4:] if path[:4] == "\\\\?\\" else path
    return body.lower() == n


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
    to the Defender offline scan), never a reason to put it in a kill plan.

    Fail closed: if the name (or the image file name) is a protected one and the path is
    missing, unreadable (access denied is common for genuine system processes) or not
    canonical, the process stays protected. Only a canonical path outside the expected
    location marks an impostor, which is NOT protected (a strong sign of malware).
    ``System``, ``Registry`` and the other kernel pseudo-processes have no image file and
    are protected by name when no path is reported. ZeroBirus's own processes
    (``ctx.own_pids``) are always protected.
    """
    if pid is not None and pid in ctx.own_pids:
        return True

    keys = {_process_key(name)}
    if path:
        keys.add(_process_key(path))
    protected = keys & _PROTECTED_PROCESS_NAMES
    if not protected:
        return False
    if not path or not _path_is_canonical(path):
        return True

    n_path = normalize_windows_path(path)
    return any(
        _expected_location(key, n_path, ctx) for key in protected if key not in _NO_IMAGE_PROCESSES
    )
