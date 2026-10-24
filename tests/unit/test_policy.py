"""Policy tests: rules from CLAUDE.md and BRIEF section 12 enforced on the source."""

import ast
import importlib
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "zerobirus"
PY_FILES = sorted(SRC.rglob("*.py"))
WINDOWS_ONLY = {"winreg", "msvcrt", "_winapi", "winsound"}


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text("utf-8"), filename=str(path))


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{a.name}" for a in node.names)
    return names


def test_source_files_found() -> None:
    assert len(PY_FILES) > 5


@pytest.mark.parametrize("path", PY_FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_no_shell_true(path: Path) -> None:
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            assert not (isinstance(node.value, ast.Constant) and node.value.value), (
                f"{path}:{node.lineno} uses shell=True"
            )


@pytest.mark.parametrize("path", PY_FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_windows_apis_only_in_windows_backend(path: Path) -> None:
    if "windows" in path.relative_to(SRC).parts:
        return
    text = path.read_text("utf-8")
    assert "windll" not in text, f"{path} uses ctypes.windll outside platform/windows"
    assert not (_imports(_tree(path)) & WINDOWS_ONLY), f"{path} imports a Windows-only module"


@pytest.mark.parametrize(
    "path",
    [p for p in PY_FILES if p.relative_to(SRC).parts[0] in {"core", "scanners"}],
    ids=lambda p: str(p.relative_to(SRC)),
)
def test_read_only_code_does_not_import_remediator(path: Path) -> None:
    text = path.read_text("utf-8")
    assert "Remediator" not in text
    assert not any(i.startswith("zerobirus.remediation") for i in _imports(_tree(path)))


@pytest.mark.parametrize("path", PY_FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_no_network_modules(path: Path) -> None:
    banned = {"socket", "urllib.request", "http.client", "requests", "httpx", "ftplib", "smtplib"}
    assert not (_imports(_tree(path)) & banned), f"{path} imports a network module"


def test_windows_backend_not_imported_off_windows() -> None:
    if sys.platform == "win32":
        pytest.skip("only meaningful off Windows")
    importlib.import_module("zerobirus.cli")

    assert "zerobirus.platform.windows" not in sys.modules
