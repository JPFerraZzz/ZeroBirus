import pytest
from ctx_factory import ONEDRIVE_PT_FOLDERS, typical_context
from hypothesis import given
from hypothesis import strategies as st

from zerobirus.core.safety import (
    SignerKind,
    SystemContext,
    has_short_name,
    is_protected_path,
    is_protected_process,
    normalize_windows_path,
)

CTX = typical_context()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (r"C:\Windows\System32", r"c:\windows\system32"),
        ("C:/Windows/System32/", r"c:\windows\system32"),
        (r"\\?\C:\Windows\System32", r"c:\windows\system32"),
        (r"\\.\C:\Windows", r"c:\windows"),
        (r"\\?\UNC\Server\Share\Dir", r"\\server\share\dir"),
        (r"C:\Windows\.\System32\..\System32", r"c:\windows\system32"),
        (r"C:\Windows\System32. ", r"c:\windows\system32"),
        (r"C:\Windows\System32 .\\\cmd.exe", r"c:\windows\system32\cmd.exe"),
        (r"C:\Windows\ \cmd.exe", r"c:\windows\cmd.exe"),
        (r"C:\Windows\notepad.exe:Zone.Identifier", r"c:\windows\notepad.exe"),
        (r"C:\..\..\Windows", r"c:\windows"),
        ("C:\\", "c:\\"),
        ("c:", "c:"),
    ],
)
def test_normalize(raw: str, expected: str) -> None:
    assert normalize_windows_path(raw) == expected


def test_short_names_detected() -> None:
    assert has_short_name(normalize_windows_path(r"C:\PROGRA~1\Foo"))
    assert not has_short_name(normalize_windows_path(r"C:\Program Files\Foo"))


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Windows",
        r"C:\Windows\System32\cmd.exe",
        r"c:\WINDOWS\system32\drivers\etc\hosts",
        r"C:/Windows/System32",
        r"\\?\C:\Windows\System32",
        r"C:\Windows\System32. ",
        r"C:\Windows\notepad.exe:stream",
        r"C:\Users\Ana\AppData\..\..\..\Windows",
        r"C:\PROGRA~1\Foo\a.exe",
        r"C:\Windows\ \0",
        r"C:\Windows\...\x",
        r"C:\Users\Ana\AppData\Local\Temp\ \x.exe",
        "C:\\",
        r"D:\\",
        r"\\server\share\x.exe",
        r"relative\path.exe",
        r"%APPDATA%\x.exe",
        r"\Windows\System32",
        r"C:\ProgramData",
        r"C:\ProgramData\Microsoft\Windows Defender\Scans\x",
        r"C:\Users",
        r"C:\Users\Ana",
        r"C:\Users\Ana\Documents",
        r"C:\Users\Ana\Documents\cv.docx",
        r"C:\Users\Ana\Desktop\notes.txt",
        r"C:\Users\Ana\OneDrive\Pictures\a.jpg",
        r"D:\Dados\Docs\x.txt",
        r"C:\Users\Ana\OneDrive\Ambiente de Trabalho",
        r"C:\Users\Ana\OneDrive\Ambiente de Trabalho\nota.txt",
        r"C:\Users\Ana\OneDrive\Documentos\cv.docx",
        r"C:\Users\Ana\OneDrive\Imagens\Rolo\a.jpg",
        r"C:\Program Files\Microsoft\x.exe",
    ],
)
def test_protected_paths(path: str) -> None:
    assert is_protected_path(path, CTX)


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\Ana\AppData\Local\Temp\x.exe",
        r"C:\Users\Ana\AppData\Roaming\kzqpx\svc.exe",
        r"C:\Users\Ana\Downloads\crack\setup.exe",
        r"C:\Users\Public\a.exe",
        r"C:\ProgramData\kzqpx\svc.exe",
        r"D:\stuff\a.exe",
    ],
)
def test_user_writable_paths_are_removable(path: str) -> None:
    assert not is_protected_path(path, CTX)


def test_link_to_protected_target_is_protected() -> None:
    link = r"C:\Users\Ana\AppData\Local\Temp\link"
    assert not is_protected_path(link, CTX)
    assert is_protected_path(link, CTX, link_target=r"C:\Windows\System32")


def test_microsoft_signed_in_program_files_is_protected() -> None:
    path = r"C:\Program Files\Windows Defender\MsMpEng.exe"
    assert is_protected_path(path, CTX, signer=SignerKind.MICROSOFT)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Phase 0 protects all of Program Files. Final rule (BRIEF section 8): protected only "
        "when signed by Microsoft or an antivirus vendor; an unsigned executable there must "
        "be removable via a plan. Remove this marker when the rule is implemented."
    ),
)
def test_unsigned_in_program_files_can_be_removed() -> None:
    path = r"C:\Program Files\SomeApp\dropper.exe"
    assert not is_protected_path(path, CTX, signer=SignerKind.UNSIGNED)


# Property tests ---------------------------------------------------------------------

_segment: st.SearchStrategy[str] = st.text(alphabet="abcXYZ019_ -.", min_size=1, max_size=8)


def _make_path(drive: str, segs: list[str]) -> str:
    return drive + ":\\" + "\\".join(segs)


_path: st.SearchStrategy[str] = st.builds(
    _make_path, st.sampled_from("CDcd"), st.lists(_segment, max_size=5)
)


@given(_path)
def test_normalize_is_idempotent(path: str) -> None:
    once = normalize_windows_path(path)
    assert normalize_windows_path(once) == once


@given(_path)
def test_normalize_ignores_case_slashes_and_prefix(path: str) -> None:
    base = normalize_windows_path(path)
    assert normalize_windows_path(path.upper()) == base
    assert normalize_windows_path(path.replace("\\", "/")) == base
    assert normalize_windows_path("\\\\?\\" + path) == base


_inside = _segment.filter(lambda seg: seg != "..")  # ".." genuinely leaves the directory


@given(st.lists(_inside, max_size=4), st.sampled_from(["", "\\", ".", " ", ". ", ":ads"]))
def test_everything_under_system_root_is_protected(segs: list[str], tail: str) -> None:
    path = "C:\\Windows\\" + "\\".join(segs) + tail
    assert is_protected_path(path, CTX)
    assert is_protected_path(path.upper().replace("\\", "/"), CTX)
    assert is_protected_path("\\\\?\\" + path, CTX)


@given(st.lists(_segment, min_size=1, max_size=4))
def test_dotdot_cannot_escape_into_protected(segs: list[str]) -> None:
    path = r"C:\Users\Ana\AppData\Local\Temp\x" + "\\.." * (len(segs) + 8) + r"\Windows\a.exe"
    assert is_protected_path(path, CTX)


@given(_path)
def test_decision_is_case_and_slash_invariant(path: str) -> None:
    expected = is_protected_path(path, CTX)
    assert is_protected_path(path.upper(), CTX) == expected
    assert is_protected_path(path.replace("\\", "/"), CTX) == expected


# Processes --------------------------------------------------------------------------


def test_genuine_svchost_is_protected() -> None:
    assert is_protected_process("svchost.exe", r"C:\Windows\System32\svchost.exe", CTX)


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\Ana\AppData\Local\Temp\svchost.exe",
        r"C:\Windows\svchost.exe",
        r"C:\Windows\System32\evil\svchost.exe",
    ],
)
def test_svchost_outside_system32_is_not_protected(path: str | None) -> None:
    assert not is_protected_process(
        "svchost.exe",
        path,
        CTX,
    )


def test_name_check_is_case_insensitive() -> None:
    assert is_protected_process("SVCHOST.EXE", r"c:\WINDOWS\system32\SvcHost.exe", CTX)


def test_explorer_only_from_windows_dir() -> None:
    assert is_protected_process("explorer.exe", r"C:\Windows\explorer.exe", CTX)
    assert not is_protected_process("explorer.exe", r"C:\Users\Ana\explorer.exe", CTX)


def test_defender_engine_locations() -> None:
    good = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe"
    assert is_protected_process(
        "MsMpEng.exe",
        good,
        CTX,
    )
    fake = r"C:\ProgramData\Windows Defender\MsMpEng.exe"
    assert not is_protected_process(
        "MsMpEng.exe",
        fake,
        CTX,
    )


def test_system_process_has_no_image_path() -> None:
    assert is_protected_process(
        "System",
        None,
        CTX,
    )
    assert not is_protected_process(
        "System",
        r"C:\Temp\System",
        CTX,
    )


def test_own_processes_are_protected() -> None:
    ctx = typical_context(own_pids=frozenset({1234}))
    assert is_protected_process("anything.exe", None, ctx, pid=1234)
    assert not is_protected_process("anything.exe", None, ctx, pid=99)


def test_unknown_process_is_not_protected() -> None:
    assert not is_protected_process("xmrig.exe", r"C:\Temp\xmrig.exe", CTX)


def test_onedrive_pt_desktop_is_protected_only_if_backend_supplies_it() -> None:
    desktop = r"C:\Users\Ana\OneDrive\Ambiente de Trabalho\nota.txt"
    assert is_protected_path(desktop, typical_context(personal_folders=ONEDRIVE_PT_FOLDERS))
    # Documents the contract: safety cannot guess localised OneDrive names. If the backend
    # forgets to pass the folder, the user's Desktop is NOT protected.
    without = typical_context(personal_folders=())
    assert not is_protected_path(desktop, without)


def test_system_context_requires_every_location() -> None:
    with pytest.raises(TypeError):
        SystemContext()  # type: ignore[call-arg]  # pyright: ignore[reportCallIssue]


def test_unsigned_svchost_in_system32_is_protected() -> None:
    # Protection is by name + path, never by signature: an invalid signature on a system
    # binary is a finding (Phase 1), not a reason to kill it.
    assert is_protected_process("svchost.exe", r"C:\Windows\System32\svchost.exe", CTX)


def test_system_and_registry_are_protected_by_name_without_path() -> None:
    assert is_protected_process("System", None, CTX)
    assert is_protected_process("Registry", "", CTX)
