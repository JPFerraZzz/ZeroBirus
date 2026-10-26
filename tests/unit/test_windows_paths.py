"""Differential test: what Windows resolves versus what ``is_protected_path`` decides.

Read-only. Real system files are opened for attributes only (CreateFileW, no access
rights) and resolved with GetFinalPathNameByHandle. Nothing is created or written, and
nothing inside the Windows directory is ever modified. If Windows resolves a spelling
into SystemRoot, ``is_protected_path`` must say True for the ORIGINAL spelling. A failure
here is a bug in ``safety``, never a reason to disable the test.
"""

import importlib
import os
from collections.abc import Callable

import pytest
from ctx_factory import typical_context

from zerobirus.core.safety import is_protected_path, is_under, normalize_windows_path

pytestmark = pytest.mark.windows

LONG_S = chr(0x17F)
FULLWIDTH_WINDOWS = "".join(chr(ord(c) + 0xFEE0) for c in "WINDOWS")

# Real files that exist on every Windows 10/11 install.
REAL_FILES = (
    r"System32\cmd.exe",
    r"System32\kernel32.dll",
    r"System32\drivers\etc\hosts",
    r"System32\config",
    r"explorer.exe",
)
# Spellings that are expected to resolve on every Windows; if none of these resolve the
# test is vacuous and must fail instead of passing silently.
MUST_RESOLVE = {"plain", "forward-slashes", "extended-prefix", "upper", "lower", "dotdot", "short"}


def _spellings(path: str, short: Callable[[str], str]) -> dict[str, str]:
    head, _, tail = path.rpartition("\\")
    return {
        "plain": path,
        "forward-slashes": path.replace("\\", "/"),
        "extended-prefix": "\\\\?\\" + path,
        "device-prefix": "\\\\.\\" + path,
        "upper": path.upper(),
        "lower": path.lower(),
        "trailing-dot": path + ".",
        "trailing-space": path + " ",
        "trailing-dots-spaces": path + ". . ",
        "dotdot": head + "\\..\\" + os.path.basename(head) + "\\" + tail,
        "dotdot-from-temp": os.path.dirname(head)
        + "\\Temp\\..\\"
        + path[len(os.path.dirname(head)) + 1 :],
        "dot-segment": head + "\\.\\" + tail,
        "double-backslash": head + "\\\\" + tail,
        "short": short(path),
        "long-s": path.replace("s", LONG_S, 1),
        "fullwidth": path.replace("Windows", FULLWIDTH_WINDOWS),
        "stream-default": path + "::$DATA",
        "stream-explicit": path + ":$DATA",
    }


def test_windows_resolution_agrees_with_is_protected_path() -> None:
    paths = importlib.import_module("zerobirus.platform.windows.paths")
    system_root = paths.canonical_path(os.environ["SYSTEMROOT"])
    ctx = typical_context(system_root=system_root)
    root = normalize_windows_path(system_root)

    failures: list[str] = []
    unresolved: list[str] = []
    resolved_labels: set[str] = set()
    report: list[str] = []

    for rel in REAL_FILES:
        base = system_root + "\\" + rel
        paths.canonical_path(base)  # the file itself must exist, or the test is meaningless
        for label, spelling in _spellings(base, paths.short_path).items():
            try:
                final = paths.canonical_path(spelling)
            except OSError as exc:
                unresolved.append(f"{label}: {spelling!r} ({getattr(exc, 'winerror', exc)})")
                continue
            inside = is_under(normalize_windows_path(final), root)
            protected = is_protected_path(spelling, ctx)
            report.append(f"{label:22} inside={inside!s:5} protected={protected!s:5} {spelling!r}")
            if inside:
                resolved_labels.add(label)
                if not protected:
                    failures.append(f"{label}: {spelling!r} -> {final!r} NOT protected")

    print(ascii("\n".join(report)))
    print(ascii("did not resolve (ignored):\n" + "\n".join(unresolved)))
    missing = MUST_RESOLVE - resolved_labels
    assert not missing, f"vacuous test, these spellings never resolved: {sorted(missing)}"
    assert not failures, "\n".join(failures)
