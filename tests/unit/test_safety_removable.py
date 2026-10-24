"""Paths that MUST stay removable.

Persistence and droppers live in user-writable places. If ``is_protected_path`` ever
covers them, the tool silently stops being able to clean the machine, and nothing else
would notice. Each case here is a place real malware uses.
"""

import pytest
from ctx_factory import typical_context

from zerobirus.core.safety import is_protected_path

CTX = typical_context()

USER_STARTUP = r"C:\Users\Ana\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
COMMON_STARTUP = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

# A second profile that lives outside users_dir (relocated profile on another drive).
EXTERNAL_PROFILE = r"D:\Perfis\Bob"
CTX_EXTERNAL = typical_context(profile_roots=(r"C:\Users\Ana", EXTERNAL_PROFILE))


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\Public\x.exe",
        r"C:\Users\Ana\AppData\Roaming\kzqpx\x.exe",
        r"C:\Users\Ana\AppData\Roaming\Qw3rTy\sub\x.exe",
        r"C:\Users\Ana\AppData\Local\Temp\x.exe",
        r"C:\Users\Ana\AppData\Local\Temp\a1b2\x.exe",
        r"C:\Users\Ana\AppData\Local\kzqpx\x.exe",
        r"C:\Users\Ana\AppData\LocalLow\kzqpx\x.exe",
        r"C:\Users\Ana\Downloads\crack.exe",
        r"C:\Users\Ana\Downloads\crack\setup.exe",
        r"C:\ProgramData\kzqpx\x.exe",
        r"C:\ProgramData\Qw3rTy\sub\x.exe",
        USER_STARTUP,
        USER_STARTUP + r"\x.exe",
        USER_STARTUP + r"\x.lnk",
        COMMON_STARTUP,
        COMMON_STARTUP + r"\x.exe",
        COMMON_STARTUP + r"\x.lnk",
    ],
)
def test_typical_malware_locations_are_removable(path: str) -> None:
    assert not is_protected_path(path, CTX)


@pytest.mark.parametrize(
    "path",
    [
        EXTERNAL_PROFILE + r"\AppData\Roaming\kzqpx\x.exe",
        EXTERNAL_PROFILE + r"\AppData\Local\Temp\x.exe",
        EXTERNAL_PROFILE + r"\Downloads\crack.exe",
        EXTERNAL_PROFILE + r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe",
    ],
)
def test_profile_outside_users_dir_is_removable(path: str) -> None:
    assert not is_protected_path(path, CTX_EXTERNAL)


@pytest.mark.parametrize(
    "path",
    [
        EXTERNAL_PROFILE,
        EXTERNAL_PROFILE + r"\Documents\cv.docx",
        EXTERNAL_PROFILE + r"\AppData\Roaming",
    ],
)
def test_profile_outside_users_dir_keeps_personal_data_protected(path: str) -> None:
    """The counterpart: the same profile must still protect what belongs to the person."""
    assert is_protected_path(path, CTX_EXTERNAL)
