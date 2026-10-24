"""Adversarial tests for core/safety (Phase 0 audit). Principle: when in doubt, fail closed."""

from collections.abc import Callable

import pytest
from ctx_factory import typical_context
from hypothesis import given, settings
from hypothesis import strategies as st

from zerobirus.core.safety import (
    SystemContext,
    is_protected_path,
    is_protected_process,
    normalize_windows_path,
)

CTX = typical_context()
OTHER_DRIVE = typical_context(
    system_root=r"D:\Windows",
    program_files=(r"D:\Program Files",),
    program_data=r"D:\ProgramData",
    users_dir=r"D:\Users",
    profile_roots=(r"D:\Users\Ana",),
    personal_folders=(),
)

MUST_BE_PROTECTED = [
    # Prefixes and namespaces
    r"\\?\C:\Windows\System32\cmd.exe",
    r"\\.\C:\Windows",
    "//?/C:/Windows/System32",
    r"\\?\c:/windows",
    r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\System32",
    r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\Windows\System32",
    r"\\?\UNC\localhost\C$\Windows",
    r"\\localhost\C$\Windows\System32",
    r"\\?\\?\C:\Windows",
    r"\??\C:\Windows",
    # Separators and dots
    r"C:\\Windows\\\\System32",
    "C:/Windows\\System32/cmd.exe",
    r"C:\Windows\System32\.",
    r"C:\Windows\System32\..\..\Windows\System32\cmd.exe",
    r"C:\Users\Ana\..\..\Windows\notepad.exe",
    r"C:\..\..\..\..\Windows\System32",
    r"C:\Users\Ana\x\..\..\..\Windows",
    # Trailing dots and spaces, alternate data streams
    "C:\\Windows\\System32\\cmd.exe.",
    "C:\\Windows\\System32\\cmd.exe ",
    "C:\\Windows. \\System32",
    "C:\\Windows \\System32\\cmd.exe",
    r"C:\Windows\notepad.exe::$DATA",
    r"C:\Windows::$INDEX_ALLOCATION\system32",
    r"C:\Windows:foo\system32\cmd.exe",
    # Reserved device names, anywhere
    r"C:\Users\Ana\Temp\NUL",
    r"C:\Users\Ana\CON.txt",
    r"C:\Users\Ana\com1",
    r"C:\Users\Ana\LPT9.log",
    r"C:\Users\Ana\aux.exe",
    "C:\\Users\\Ana\\COM\u00b9",
    r"C:\Users\Ana\CONIN$",
    r"C:\Users\Ana\NUL .txt",
    # Short names
    r"C:\WINDOW~1\SYSTEM~1",
    r"C:\PROGRA~2\x",
    r"C:\Users\Ana\APPDAT~1\Local\x.exe",
    # Not absolute, empty, wild or malformed
    "",
    " ",
    "\x00",
    "C:\\Windows\x00\\evil",
    "C:\\Users\\Ana\\a.exe\x00C:\\Windows",
    "C:foo",
    "C:",
    "C:Windows\\x",
    "C::\\Windows",
    "foo.exe",
    r".\foo.exe",
    r"..\foo",
    r"\Windows",
    r"%SystemRoot%\x",
    r"C:\Users\Ana\%WINDIR%\x.exe",
    r"C:\Users\Ana\AppData\Local\Temp\*",
    r"C:\Users\Ana\Temp\?.exe",
    r"C:\Users\Ana\a<b",
    'C:\\Users\\Ana\\a"b',
    "C:\\Users\\Ana\\a|b",
    "C:\\Users\\Ana\\a\x01b",
    "C:\\Users\\Ana\\a\nb",
    "C:\\Windows\\" + "a" * 40000,
    "C:\\Users\\Ana\\" + "a" * 40000,
    # Unicode that Windows or ANSI best-fit may fold onto ASCII
    "C:\\Windows\\\u017fystem32\\cmd.exe",
    "C:\\\uff37\uff29\uff2e\uff24\uff2f\uff37\uff33\\System32",
    "C:\\Windows\\System32\\\uff43\uff4d\uff44.exe",
    "C:\uff3cWindows",
    "\uff23:\\Windows",
    "C:\\Users\\Ana\\x\\\uff0e\uff0e\\\uff0e\uff0e\\\uff0e\uff0e\\Windows\\a.exe",
    "C:\\Users\\Ana\\a\uff0ab",
    # Another Windows installation or system files on any drive
    r"E:\Windows\System32\cmd.exe",
    r"C:\pagefile.sys",
    r"C:\hiberfil.sys",
    r"C:\swapfile.sys",
    r"C:\bootmgr",
    r"C:\Boot\BCD",
    r"C:\System Volume Information\x",
    r"C:\$Recycle.Bin\S-1-5-21\x",
    r"C:\Recovery\WindowsRE\winre.wim",
    r"C:\EFI\Microsoft\Boot\bootmgfw.efi",
    # Profiles
    r"C:\Users\Ana\NTUSER.DAT",
    r"C:\Users\Ana\ntuser.dat.LOG1",
    r"C:\Users\Ana\AppData\Local\Microsoft\Windows\UsrClass.dat",
    r"C:\Users\Bob",
    r"C:\Users\Bob\Documents\a.docx",
    r"C:\Users\Bob\Desktop\x.txt",
    r"C:\Users\Bob\OneDrive\Documents\x.txt",
    r"C:\Users\Default\NTUSER.DAT",
    r"C:\Users\Public",
    r"C:\Users\Ana\AppData",
    r"C:\Users\Ana\AppData\Local",
    r"C:\Users\Ana\AppData\Roaming",
    r"C:\Users\Ana\AppData\Local\Temp",
    r"C:\Users\Ana\Downloads",
    r"C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\x",
]

MUST_BE_REMOVABLE = [
    r"C:\Users\Ana\AppData\Local\Temp\kzqpx\svc.exe",
    r"C:\Users\Ana\AppData\Roaming\kzqpx\a.exe",
    r"C:\ProgramData\kzqpx\svc.exe",
    r"C:\Users\Public\a.exe",
    r"C:\Users\Ana\Downloads\crack\setup.exe",
    r"C:\WindowsEvil\a.exe",
    r"C:\Windowsx\a.exe",
    r"C:\Windows.old\a.exe",
    r"D:\stuff\a.exe",
    r"C:\Users\Ana\AppData\Local\Temp\Wind0ws\a.exe",
    r"C:\Users\Ana\AppData\Local\Temp\console\x.exe",
    r"C:\Users\Ana\AppData\Local\Temp\ctrl\x.exe",
    r"C:\Users\Ana\AppData\Local\Temp\com10.exe",
    r"C:\Users\Ana\AppData\Local\Temp\notnul.exe",
    r"C:\Users\Ana\AppData\Local\Temp\aux1.exe",
]


@pytest.mark.parametrize("path", MUST_BE_PROTECTED, ids=lambda p: repr(p)[:70])
def test_dangerous_path_is_protected(path: str) -> None:
    assert is_protected_path(path, CTX)


@pytest.mark.parametrize("path", MUST_BE_REMOVABLE, ids=lambda p: repr(p)[:70])
def test_legitimate_target_is_not_blocked(path: str) -> None:
    assert not is_protected_path(path, CTX)


@pytest.mark.parametrize(
    "path",
    [
        r"D:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\cmd.exe",
        r"D:\Program Files\X\a.exe",
        r"D:\Users\Ana",
        r"D:\Users\Ana\Documents\a.docx",
        r"D:\ProgramData\Microsoft\Windows Defender\x",
    ],
)
def test_windows_on_another_drive(path: str) -> None:
    assert is_protected_path(path, OTHER_DRIVE)


def test_link_chain_ends_are_both_checked() -> None:
    innocent = r"C:\Users\Ana\AppData\Local\Temp\a"
    assert is_protected_path(innocent, CTX, link_target=r"C:\Windows\System32")
    assert is_protected_path(r"C:\Windows\Temp\link", CTX, link_target=innocent)
    assert is_protected_path(innocent, CTX, link_target="")
    assert is_protected_path(innocent, CTX, link_target=r"relative\thing")
    assert not is_protected_path(innocent, CTX, link_target=r"C:\Users\Ana\AppData\Local\Temp\b")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"system_root": ""},
        {"system_root": "Windows"},
        {"system_root": "C:\\"},
        {"program_files": ()},
        {"program_files": ("",)},
        {"program_data": ""},
        {"users_dir": r"relative"},
        {"profile_roots": ()},
        {"profile_roots": ("",)},
        {"system_root": r"C:\WINDOW~1"},
    ],
)
def test_system_context_rejects_empty_or_bogus_locations(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="SystemContext"):
        typical_context(**kwargs)  # type: ignore[arg-type]  # pyright: ignore


def test_system_context_is_a_system_context() -> None:
    assert isinstance(typical_context(), SystemContext)


# Processes ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("SvcHost.EXE", r"C:\Windows\System32\svchost.exe"),
        (" svchost.exe ", r"C:\Windows\System32\svchost.exe"),
        ("svchost", r"C:\Windows\System32\svchost.exe"),
        ("svchost.exe.", r"C:\Windows\System32\svchost.exe"),
        ("\uff53\uff56\uff43\uff48\uff4f\uff53\uff54.exe", r"C:\Windows\System32\svchost.exe"),
        ("svchost.exe", None),
        ("svchost.exe", ""),
        ("svchost.exe", r"C:\WINDOWS\SYSTEM~1\svchost.exe"),
        ("svchost.exe", r"\\?\C:\Windows\System32\svchost.exe"),
        ("svchost.exe", r"C:\Windows\System32\svchost.exe "),
        ("svchost.exe", "C:/Windows/System32/svchost.exe"),
        ("svchost.exe", r"C:\Windows\SysWOW64\svchost.exe"),
        ("lsass.exe", None),
        ("csrss.exe", r"relative\csrss.exe"),
        ("System", None),
        ("System", ""),
        ("Registry", None),
        ("Memory Compression", None),
        ("Secure System", None),
        ("System Idle Process", None),
        ("MsMpEng.exe", None),
        ("NisSrv.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\NisSrv.exe"),
        ("explorer.exe", r"C:\Windows\explorer.exe"),
        ("anything", r"C:\Windows\System32\svchost.exe"),
    ],
)
def test_protected_processes(name: str, path: str | None) -> None:
    assert is_protected_process(name, path, CTX)


@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("svchost.exe", r"C:\Users\Ana\AppData\Local\Temp\svchost.exe"),
        ("svchost.exe", r"C:\Windows\svchost.exe"),
        ("svchost.exe", r"C:\Windows\System32\evil\svchost.exe"),
        ("svchost.exe", r"C:\Users\Ana\AppData\Roaming\svchost.exe"),
        ("System", r"C:\Users\Ana\System"),
        ("lsass.exe", r"C:\ProgramData\lsass.exe"),
        ("explorer.exe", r"C:\Windows\System32\explorer.exe"),
        ("MsMpEng.exe", r"C:\ProgramData\Windows Defender\MsMpEng.exe"),
        ("xmrig.exe", r"C:\Users\Ana\AppData\Local\Temp\xmrig.exe"),
        ("xmrig.exe", None),
        ("", None),
        ("svchost2.exe", r"C:\Windows\System32\svchost2.exe"),
    ],
)
def test_impostor_or_unknown_processes_are_not_protected(name: str, path: str | None) -> None:
    assert not is_protected_process(name, path, CTX)


def test_own_pids_win_over_everything() -> None:
    ctx = typical_context(own_pids=frozenset({7}))
    assert is_protected_process("xmrig.exe", r"C:\Temp\x.exe", ctx, pid=7)
    assert not is_protected_process("xmrig.exe", r"C:\Temp\x.exe", ctx, pid=8)
    assert not is_protected_process("xmrig.exe", r"C:\Temp\x.exe", ctx)


# Properties ----------------------------------------------------------------------------

_OBFUSCATIONS: list[Callable[[str], str]] = [
    lambda s: s,
    lambda s: s.upper(),
    lambda s: s.swapcase(),
    lambda s: s + ".",
    lambda s: s + " ",
    lambda s: s + " .",
    lambda s: s + ":ads",
    lambda s: s + "::$DATA",
    lambda s: s + "\\.",
    lambda s: s + "\\..\\" + s,
]
_obfuscations = st.sampled_from(_OBFUSCATIONS)
_base_parts = st.sampled_from(
    [
        ["Windows"],
        ["Windows", "System32"],
        ["Windows", "System32", "drivers", "etc", "hosts"],
        ["Windows", "Temp", "x.exe"],
        ["Program Files", "Foo", "a.exe"],
        ["Users", "Ana", "Documents", "a.docx"],
        ["Users", "Ana", "OneDrive", "Ambiente de Trabalho", "n.txt"],
    ]
)
_seps = st.sampled_from(["\\", "/", "\\\\", "/\\", "\\/"])
_prefixes = st.sampled_from(["C:", "c:", "\\\\?\\C:", "\\\\.\\C:", "//?/C:", "\\\\?\\c:"])


@settings(max_examples=2000)
@given(_base_parts, st.lists(_obfuscations, min_size=5, max_size=5), _seps, _prefixes)
def test_obfuscated_protected_paths_stay_protected(
    parts: list[str],
    obfs: list[Callable[[str], str]],
    sep: str,
    prefix: str,
) -> None:
    comps = [obf(p) for obf, p in zip(obfs, parts, strict=False)]
    path = prefix + sep + sep.join(comps)
    assert is_protected_path(path, CTX), path


@settings(max_examples=2000)
@given(st.text())
def test_never_raises_and_normalize_is_idempotent(text: str) -> None:
    once = normalize_windows_path(text)
    assert normalize_windows_path(once) == once
    is_protected_path(text, CTX)
    is_protected_process(text, text, CTX)


@settings(max_examples=2000)
@given(st.text(alphabet=st.characters(blacklist_categories=["Cs"]), min_size=1, max_size=60))
def test_arbitrary_text_under_temp_is_protected_or_clean(tail: str) -> None:
    """Whatever follows a Temp prefix, a path that escapes into Windows must be protected."""
    path = "C:\\Users\\Ana\\AppData\\Local\\Temp\\x\\" + tail
    n = normalize_windows_path(path)
    if n == "c:\\windows" or n.startswith("c:\\windows\\"):
        assert is_protected_path(path, CTX)
