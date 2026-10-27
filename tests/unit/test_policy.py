"""Policy tests: rules from CLAUDE.md and BRIEF section 12 enforced on the source.

The detectors are pure functions over source text. The self-tests at the bottom feed them
synthetic violations, so the policy tests are proven to fail when someone breaks a rule.
"""

import ast
import importlib
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "zerobirus"
PY_FILES = sorted(SRC.rglob("*.py"))

WINDOWS_ONLY = {
    "winreg",
    "_winreg",
    "msvcrt",
    "_winapi",
    "winsound",
    "win32api",
    "win32con",
    "win32com",
    "win32file",
    "win32process",
    "win32service",
    "pywintypes",
    "pythoncom",
    "wmi",
    "comtypes",
    "ctypes.wintypes",
}
NETWORK = {
    "socket",
    "ssl",
    "socketserver",
    "urllib.request",
    "urllib3",
    "http.client",
    "http.server",
    "requests",
    "httpx",
    "aiohttp",
    "websockets",
    "paramiko",
    "ftplib",
    "smtplib",
    "poplib",
    "imaplib",
    "telnetlib",
    "xmlrpc.client",
}
SHELLISH_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "commands.getoutput",
}
SUBPROCESS_CALLS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}
EVAL_CALLS = {"eval", "exec"}


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{a.name}" for a in node.names)
    return names


def _strings(tree: ast.AST) -> set[str]:
    return {
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }


def _dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _aliases(tree: ast.AST) -> dict[str, str]:
    """Map local names to dotted origins: ``import subprocess as sp``, ``from os import system``."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _resolve(call: ast.Call, aliases: dict[str, str]) -> str:
    name = _dotted(call.func)
    head, _, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + ("." + rest if rest else "")
    return name


def shell_violations(source: str) -> list[str]:
    """Calls that could run a shell: shell=<not constant False>, **splat, os.system, eval..."""
    tree = ast.parse(source)
    aliases = _aliases(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _resolve(node, aliases)
        if name in SHELLISH_CALLS or name in EVAL_CALLS:
            found.append(f"line {node.lineno}: call to {name}")
        if name in SUBPROCESS_CALLS:
            for kw in node.keywords:
                if kw.arg is None:
                    found.append(f"line {node.lineno}: **kwargs passed to {name}")
                elif kw.arg == "shell" and not (
                    isinstance(kw.value, ast.Constant) and kw.value.value is False
                ):
                    found.append(f"line {node.lineno}: shell is not literally False in {name}")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.keyword)
            and node.arg == "shell"
            and not (isinstance(node.value, ast.Constant) and node.value.value is False)
        ):
            found.append(f"line {node.value.lineno}: shell keyword is not literally False")
    return sorted(set(found))


def windows_api_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    found = [
        f"imports {m}"
        for m in _imports(tree)
        if m in WINDOWS_ONLY or m.split(".")[0] in WINDOWS_ONLY
    ]
    found += [f"string names Windows-only module {s!r}" for s in _strings(tree) & WINDOWS_ONLY]
    if "windll" in source or "oledll" in source or "WinDLL" in source:
        found.append("uses ctypes windll/oledll/WinDLL")
    if "zerobirus.platform.windows" in _imports(tree) or "zerobirus.platform.windows" in _strings(
        tree
    ):
        found.append("imports zerobirus.platform.windows")
    return sorted(found)


def remediator_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    found = [f"imports {m}" for m in _imports(tree) if m.startswith("zerobirus.remediation")]
    if "Remediator" in source:
        found.append("mentions Remediator")
    found += [
        f"string names {s!r}" for s in _strings(tree) if s.startswith("zerobirus.remediation")
    ]
    return sorted(found)


def network_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    found = [f"imports {m}" for m in _imports(tree) if m in NETWORK]
    found += [f"string names network module {s!r}" for s in _strings(tree) & NETWORK]
    return sorted(found)


def _rel(p: Path) -> str:
    return str(p.relative_to(SRC))


def _is_windows_backend(p: Path) -> bool:
    return p.relative_to(SRC).parts[:2] == ("platform", "windows")


LOADER = "platform/loader.py"
BACKEND_MODULE = "zerobirus.platform.windows"


def test_source_files_found() -> None:
    assert len(PY_FILES) > 5


@pytest.mark.parametrize("path", PY_FILES, ids=_rel)
def test_no_shell(path: Path) -> None:
    assert shell_violations(path.read_text("utf-8")) == []


@pytest.mark.parametrize("path", PY_FILES, ids=_rel)
def test_windows_apis_only_in_windows_backend(path: Path) -> None:
    if _is_windows_backend(path):
        return
    found = windows_api_violations(path.read_text("utf-8"))
    if path.relative_to(SRC).as_posix() == LOADER:
        # The loader is the single allowed place to name the backend; every other rule holds.
        found = [v for v in found if v != "imports zerobirus.platform.windows"]
    assert found == []


def loader_import_is_guarded(source: str) -> bool:
    """True if every mention of the backend module sits inside ``if sys.platform == "win32"``."""
    tree = ast.parse(source)
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and ast.unparse(node.test) == "sys.platform == 'win32'":
            guarded.update(id(n) for stmt in node.body for n in ast.walk(stmt))
    mentions = [
        n for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value == BACKEND_MODULE
    ]
    return bool(mentions) and all(id(n) in guarded for n in mentions)


def test_only_the_loader_names_the_windows_backend_and_it_is_guarded() -> None:
    naming = [
        p.relative_to(SRC).as_posix()
        for p in PY_FILES
        if not _is_windows_backend(p) and BACKEND_MODULE in p.read_text("utf-8")
    ]
    assert naming == [LOADER]
    assert loader_import_is_guarded((SRC / LOADER).read_text("utf-8"))


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\nimportlib.import_module(MOD)",
        "import sys, importlib\nif sys.platform != 'win32':\n    importlib.import_module(MOD)",
        "import sys, importlib\nif sys.platform == 'win32':\n    pass\nimportlib.import_module(MOD)",  # noqa: E501
        "x = 1",
    ],
)
def test_selftest_loader_guard_detector_rejects_unguarded_imports(source: str) -> None:
    assert not loader_import_is_guarded(source.replace("MOD", repr(BACKEND_MODULE)))


def test_selftest_loader_guard_detector_accepts_the_guarded_form() -> None:
    source = (
        "import sys, importlib\n"
        "if sys.platform == 'win32':\n"
        "    importlib.import_module('zerobirus.platform.windows')\n"
    )
    assert loader_import_is_guarded(source)


@pytest.mark.parametrize(
    "path",
    [p for p in PY_FILES if p.relative_to(SRC).parts[0] in {"core", "scanners"}],
    ids=_rel,
)
def test_read_only_code_does_not_import_remediator(path: Path) -> None:
    assert remediator_violations(path.read_text("utf-8")) == []


def redact_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    found = [f"imports {m}" for m in _imports(tree) if m.startswith("zerobirus.core.redact")]
    found += [
        f"string names {s!r}" for s in _strings(tree) if s.startswith("zerobirus.core.redact")
    ]
    return sorted(found)


SCORING_SIDE = {"scanners", "platform"}
SCORING_CORE = {"heuristics.py", "diagnosis.py", "scoring.py"}


@pytest.mark.parametrize(
    "path",
    [
        p
        for p in PY_FILES
        if p.relative_to(SRC).parts[0] == "scanners"
        or p.relative_to(SRC).parts[:2] == ("core", "rules")
        or p.name in SCORING_CORE
    ],
    ids=_rel,
)
def test_scoring_never_imports_redact(path: Path) -> None:
    """Scoring must see the original command line. Redaction is for output only."""
    assert redact_violations(path.read_text("utf-8")) == []


@pytest.mark.parametrize(
    "source",
    [
        "from zerobirus.core.redact import redact",
        "import zerobirus.core.redact",
        "import importlib\nimportlib.import_module('zerobirus.core.redact')",
    ],
)
def test_selftest_redact_detector_catches(source: str) -> None:
    assert redact_violations(source)


def qt_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    found = [f"imports {m}" for m in _imports(tree) if m.split(".")[0] in {"PySide6", "shiboken6"}]
    found += [f"string names {s!r}" for s in _strings(tree) if s.startswith("PySide6")]
    return sorted(found)


@pytest.mark.parametrize(
    "path", [p for p in PY_FILES if p.relative_to(SRC).parts[0] != "ui"], ids=_rel
)
def test_logic_never_depends_on_qt(path: Path) -> None:
    """BRIEF section 7: the logic has no Qt dependency; only ``ui/`` and the CLI's lazy hooks."""
    allowed = path.relative_to(SRC).as_posix() == "cli.py"  # imports ui lazily, inside functions
    found = qt_violations(path.read_text("utf-8"))
    assert allowed or found == []


@pytest.mark.parametrize(
    "source", ["import PySide6", "from PySide6.QtWidgets import QLabel", "import shiboken6"]
)
def test_selftest_qt_detector_catches(source: str) -> None:
    assert qt_violations(source)


@pytest.mark.parametrize("path", PY_FILES, ids=_rel)
def test_no_network_modules(path: Path) -> None:
    assert network_violations(path.read_text("utf-8")) == []


def test_windows_backend_not_imported_off_windows() -> None:
    if sys.platform == "win32":
        pytest.skip("only meaningful off Windows")
    importlib.import_module("zerobirus.cli")

    assert "zerobirus.platform.windows" not in sys.modules


# Self-tests: the detectors must catch these violations -------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run('x', shell=True)",
        "import subprocess\nsubprocess.run('x', shell=1)",
        "import subprocess\nflag = True\nsubprocess.run('x', shell=flag)",
        "import subprocess\nkw = {'shell': True}\nsubprocess.run('x', **kw)",
        "import subprocess as sp\nsp.Popen('x', shell=True)",
        "from subprocess import check_output as co\nco('x', shell=True)",
        "import os\nos.system('x')",
        "from os import system\nsystem('x')",
        "import os\nos.popen('x')",
        "import subprocess\nsubprocess.getoutput('x')",
        "eval('1')",
        "exec('x = 1')",
        "def f(**kw):\n    pass\nf(shell=True)",
    ],
)
def test_selftest_shell_detector_catches(source: str) -> None:
    assert shell_violations(source)


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(['a'], shell=False)",
        "import subprocess\nsubprocess.run(['a'], check=True)",
        "x = 1",
    ],
)
def test_selftest_shell_detector_allows(source: str) -> None:
    assert shell_violations(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "import winreg",
        "from winreg import OpenKey",
        "import ctypes\nx = ctypes.windll",
        "import ctypes as c\nx = c.windll.kernel32",
        "from ctypes import windll",
        "import msvcrt",
        "import ctypes.wintypes",
        "import win32api",
        "import importlib\nimportlib.import_module('winreg')",
        "__import__('winreg')",
        "import zerobirus.platform.windows",
        "from zerobirus.platform import windows\nfrom zerobirus.platform.windows import x",
        "import importlib\nimportlib.import_module('zerobirus.platform.windows')",
    ],
)
def test_selftest_windows_detector_catches(source: str) -> None:
    assert windows_api_violations(source)


@pytest.mark.parametrize(
    "source",
    [
        "from zerobirus.platform.base import Remediator",
        "import zerobirus.remediation",
        "from zerobirus.remediation import quarantine",
        "from zerobirus.remediation.quarantine import move",
        "import importlib\nimportlib.import_module('zerobirus.remediation.registry')",
        "x: 'Remediator'",
    ],
)
def test_selftest_remediator_detector_catches(source: str) -> None:
    assert remediator_violations(source)


@pytest.mark.parametrize(
    "source",
    [
        "import socket",
        "from socket import socket",
        "import urllib.request",
        "from urllib import request\nfrom urllib.request import urlopen",
        "import http.client",
        "import requests",
        "import ssl",
        "__import__('socket')",
        "import importlib\nimportlib.import_module('urllib.request')",
    ],
)
def test_selftest_network_detector_catches(source: str) -> None:
    assert network_violations(source)
