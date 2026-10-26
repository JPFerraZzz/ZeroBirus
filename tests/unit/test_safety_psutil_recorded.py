"""Values psutil really produced for kernel pseudo-processes on windows-latest.

Recorded from CI run on 2026-10-26: System (PID 4) has no executable path (``None`` after
AccessDenied or empty), and Registry reports the literal string ``"Registry"`` as its
``exe``. The second one is not a path at all; it stays protected only because a name that
is protected plus a non-canonical path fails closed. These tests pin that on Linux.
"""

import pytest
from ctx_factory import typical_context

from zerobirus.core import safety
from zerobirus.core.safety import is_protected_process

CTX = typical_context()


@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("System", None),
        ("System", ""),
        ("Registry", "Registry"),
        ("Registry", None),
        ("Memory Compression", None),
        ("Memory Compression", "Memory Compression"),
    ],
)
def test_kernel_pseudo_processes_as_psutil_reports_them(name: str, path: str | None) -> None:
    assert is_protected_process(name, path, CTX)


def test_system_exe_in_appdata_is_an_impostor() -> None:
    assert not is_protected_process(
        "System.exe", r"C:\Users\Ana\AppData\Roaming\kzqpx\System.exe", CTX
    )
    assert not is_protected_process("System", r"C:\Users\Ana\AppData\Roaming\kzqpx\System.exe", CTX)


@pytest.mark.parametrize("name", ["Registry", "System", "Memory Compression"])
def test_bare_image_name_is_judged_as_no_image_not_as_bad_path(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Protection of ``Registry`` must come from the no-image rule, not from the fallback
    for non-canonical paths."""

    def boom(path: str) -> bool:
        raise AssertionError("the canonical-path fallback must not be consulted")

    monkeypatch.setattr(safety, "_path_is_canonical", boom)
    assert is_protected_process(name, name, CTX)
    assert is_protected_process(name, name.upper(), CTX)
    assert is_protected_process(name, f" {name} ", CTX)


@pytest.mark.parametrize(
    ("name", "path", "expected"),
    [
        ("Registry", "Registry", True),
        ("Registry", " REGISTRY ", True),
        ("svchost.exe", "svchost.exe", True),
        ("svchost.exe", "svchost", True),
        ("svchost.exe", r"C:\Windows\System32\svchost.exe", False),
        ("Registry", r"C:\Users\Ana\AppData\Roaming\kzqpx\Registry", False),
        ("Registry", "x/Registry", False),
        ("Registry", "Other", False),
    ],
)
def testis_bare_image_name(name: str, path: str, expected: bool) -> None:
    assert safety.is_bare_image_name(path, name) is expected
