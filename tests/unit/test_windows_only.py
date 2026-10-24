"""Tests that only make sense on real Windows. Run in CI on windows-latest."""

import importlib
import os
import sys
from pathlib import Path, PureWindowsPath

import pytest

from zerobirus.core.safety import SystemContext, is_protected_path, normalize_windows_path

pytestmark = pytest.mark.windows


def test_platform_is_windows() -> None:
    assert sys.platform == "win32"


def test_windows_backend_imports() -> None:
    importlib.import_module("zerobirus.platform.windows")


def test_safety_agrees_with_real_pathlib() -> None:
    path = r"C:\Windows\System32\cmd.exe"
    assert normalize_windows_path(path) == str(Path(path)).lower()
    assert normalize_windows_path(path) == str(PureWindowsPath(path)).lower()


def test_real_system_root_is_protected() -> None:

    ctx = SystemContext(system_root=os.environ["SYSTEMROOT"])
    assert is_protected_path(os.environ["SYSTEMROOT"] + r"\System32\cmd.exe", ctx)
