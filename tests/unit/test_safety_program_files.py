"""Program Files is protected by signature (BRIEF section 8), failing closed when unknown."""

import pytest
from ctx_factory import typical_context

from zerobirus.core.safety import SignerKind, is_protected_path

CTX = typical_context()
PF = r"C:\Program Files"
PF86 = r"C:\Program Files (x86)"


@pytest.mark.parametrize("signer", [SignerKind.UNSIGNED, SignerKind.OTHER])
@pytest.mark.parametrize("path", [PF + r"\SomeApp\dropper.exe", PF86 + r"\kzqpx\x.dll"])
def test_unsigned_or_third_party_item_is_removable(path: str, signer: SignerKind) -> None:
    assert not is_protected_path(path, CTX, signer=signer)


@pytest.mark.parametrize("signer", [SignerKind.MICROSOFT, SignerKind.ANTIVIRUS_VENDOR, None])
def test_signed_or_unknown_item_is_protected(signer: SignerKind | None) -> None:
    assert is_protected_path(PF + r"\SomeApp\app.exe", CTX, signer=signer)


def test_unknown_signer_is_the_default_and_fails_closed() -> None:
    assert is_protected_path(PF + r"\SomeApp\app.exe", CTX)


@pytest.mark.parametrize("pf", [PF, PF86])
@pytest.mark.parametrize("signer", [SignerKind.UNSIGNED, SignerKind.OTHER])
def test_program_files_folders_themselves_stay_protected(pf: str, signer: SignerKind) -> None:
    assert is_protected_path(pf, CTX, signer=signer)
    assert is_protected_path(pf + "\\", CTX, signer=signer)


@pytest.mark.parametrize("signer", [SignerKind.UNSIGNED, SignerKind.OTHER])
@pytest.mark.parametrize(
    "sub",
    [
        r"\Windows Defender\x.exe",
        r"\Windows Defender Advanced Threat Protection\x.exe",
        r"\WindowsApps\x\y.exe",
        r"\Windows NT\x.exe",
        r"\windows defender\x.exe",
    ],
)
def test_defender_and_windows_managed_folders_ignore_the_signer(
    sub: str, signer: SignerKind
) -> None:
    assert is_protected_path(PF + sub, CTX, signer=signer)


def test_link_into_program_files_uses_the_signer_of_the_target() -> None:
    link = r"C:\Users\Ana\AppData\Local\Temp\link.exe"
    target = PF + r"\SomeApp\app.exe"
    assert is_protected_path(link, CTX, link_target=target)
    assert not is_protected_path(link, CTX, link_target=target, signer=SignerKind.UNSIGNED)


def test_other_protections_still_apply_with_an_unsigned_signer() -> None:
    assert is_protected_path(r"C:\Windows\System32\cmd.exe", CTX, signer=SignerKind.UNSIGNED)
    assert is_protected_path(r"C:\Users\Ana\Documents\a.docx", CTX, signer=SignerKind.UNSIGNED)
