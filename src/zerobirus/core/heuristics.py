"""Pure helpers that judge names, locations and command lines. No I/O, no redaction.

These see the ORIGINAL strings from the machine. Redaction happens only when a report is
written (``core.report``), never before scoring.
"""

from __future__ import annotations

import itertools
import re

from zerobirus.core.safety import SystemContext, normalize_windows_path

_VOWELS = frozenset("aeiou")
_CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxz]{5,}")
_EXE_EXTENSIONS = r"exe|com|bat|cmd|scr|dll|vbs|vbe|js|jse|wsf|ps1|msi|jar|lnk|cpl|hta"
_PATH_IN_TEXT = re.compile(
    rf"(?:[A-Za-z]:\\|\\\\\?\\)[^\"'<>|*?\r\n]*?\.(?:{_EXE_EXTENSIONS})\b", re.IGNORECASE
)
_LEADING_PATH = re.compile(rf"^(.+?\.(?:{_EXE_EXTENSIONS}))(?=\s|$|,)", re.IGNORECASE)
_RUNDLL = re.compile(r'rundll32(?:\.exe)?"?\s+"?([^",]+?)"?\s*(?:,|$)', re.IGNORECASE)
_ENV_WRITABLE = re.compile(
    r"%(?:appdata|localappdata|temp|tmp|programdata|public|userprofile)%", re.IGNORECASE
)
SHELLS = frozenset(
    {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
)
_CRACK_WORDS = ("crack", "keygen", "kmspico", "activator")


def looks_random(name: str) -> bool:
    """True for names that look machine-generated (``kzqpx``, ``Qw3rTy``, ``a1b2c3d4``).

    A weak signal on its own; it never decides anything. Real words have vowels in
    ordinary proportion, so names such as ``Discord``, ``Spotify`` and ``Python312`` pass.
    """
    core = re.sub(r"[^a-z0-9]", "", name.lower())
    if len(core) < 5:
        return False
    if re.fullmatch(r"[0-9a-f]{8,}", core) and any(c.isdigit() for c in core):
        return True
    letters = [c for c in core if c.isalpha()]
    if len(letters) >= 5:
        vowel_ratio = sum(c in _VOWELS for c in letters) / len(letters)
        if vowel_ratio < 0.15:
            return True
        if _CONSONANT_RUN.search("".join(letters)):
            return True
    transitions = sum(a.isdigit() != b.isdigit() for a, b in itertools.pairwise(core))
    return transitions >= 3


def location_kind(path: str, ctx: SystemContext) -> str | None:
    """Which user-writable place ``path`` is in, or None.

    One of ``temp``, ``appdata``, ``programdata``, ``public``, ``downloads``, ``windows_temp``.
    Only used to raise suspicion; protection decisions stay in ``core.safety``.
    """
    n = normalize_windows_path(path)
    system_temp = normalize_windows_path(ctx.system_root) + "\\temp\\"
    if n.startswith(system_temp):
        return "windows_temp"
    users = normalize_windows_path(ctx.users_dir)
    roots = [normalize_windows_path(r) for r in ctx.profile_roots]
    if n.startswith(users + "\\public\\"):
        return "public"
    for root in (*roots, *_profiles_under(n, users)):
        base = root + "\\"
        if not n.startswith(base):
            continue
        rest = n[len(base) :]
        if rest.startswith("appdata\\local\\temp\\"):
            return "temp"
        if rest.startswith("appdata\\"):
            return "appdata"
        if rest.startswith("downloads\\"):
            return "downloads"
    program_data = normalize_windows_path(ctx.program_data) + "\\"
    if n.startswith(program_data):
        if n.startswith(program_data + "microsoft\\windows defender\\"):
            return None
        return "programdata"
    return None


def _profiles_under(n: str, users: str) -> list[str]:
    if not n.startswith(users + "\\"):
        return []
    first = n[len(users) + 1 :].split("\\", 1)[0]
    return [users + "\\" + first] if first else []


def is_writable_location(path: str, ctx: SystemContext) -> bool:
    return location_kind(path, ctx) is not None


def random_component(path: str, ctx: SystemContext) -> str | None:
    """The first folder (or file stem) with a random-looking name just inside a writable place.

    Looks at the first two components after the writable base, which is where droppers
    put their folder (``AppData\\Roaming\\kzqpx\\x.exe``).
    """
    kind = location_kind(path, ctx)
    if kind is None:
        return None
    parts = path.replace("/", "\\").split("\\")
    lowered = [p.lower() for p in parts]
    start: int | None = None
    if kind in ("appdata", "temp"):
        if "appdata" in lowered:
            i = lowered.index("appdata")
            start = i + 2 if i + 2 < len(parts) else None
            if kind == "temp" and i + 3 < len(parts):
                start = i + 3
    elif kind == "programdata":
        pd = normalize_windows_path(ctx.program_data).count("\\") + 1
        start = pd
    elif kind == "public":
        start = lowered.index("public") + 1 if "public" in lowered else None
    elif kind == "downloads":
        start = lowered.index("downloads") + 1 if "downloads" in lowered else None
    if start is None:
        return None
    for comp in parts[start : start + 2]:
        if comp and looks_random(comp.rsplit(".", 1)[0] if "." in comp else comp):
            return comp
    return None


def crack_word(path: str) -> str | None:
    lowered = path.lower()
    return next((w for w in _CRACK_WORDS if w in lowered), None)


def extract_executable(command: str) -> str | None:
    """The program a command line starts, as written (not expanded, not verified).

    ``rundll32 x.dll,Entry`` returns the DLL, because that is what actually runs. Anything
    that cannot be parsed returns None; the caller treats that as "unknown", never as safe.
    """
    text = command.strip()
    if not text:
        return None
    if text[0] == '"':
        end = text.find('"', 1)
        first = text[1:end] if end > 0 else text[1:]
    else:
        m = _LEADING_PATH.match(text)
        first = m.group(1) if m else text.split(None, 1)[0]
    first = first.strip()
    if first.lower().rsplit("\\", 1)[-1] in ("rundll32.exe", "rundll32"):
        m = _RUNDLL.search(text)
        if m:
            return m.group(1).strip()
    return first or None


def paths_in_command(command: str) -> list[str]:
    """Absolute paths to program or script files mentioned anywhere in a command line."""
    found = [m.group(0) for m in _PATH_IN_TEXT.finditer(command)]
    exe = extract_executable(command)
    if exe and exe not in found:
        found.append(exe)
    return found


def mentions_writable_env(command: str) -> bool:
    return _ENV_WRITABLE.search(command) is not None


def runs_a_shell(command: str) -> bool:
    exe = extract_executable(command)
    return exe is not None and exe.replace("/", "\\").rsplit("\\", 1)[-1].lower() in SHELLS
