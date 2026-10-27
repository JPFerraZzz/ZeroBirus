"""Detection integration test on windows-latest (read-only product, harmless artifacts).

``tools/windows/make_test_artifacts.ps1`` creates a marked, unsigned, sleeping program in
AppData, a Run value, a scheduled task and a Defender exclusion, with a mining-like command
line aimed at a ``.invalid`` domain. The scan must find them at the right level, change
nothing, and find nothing once ``remove_test_artifacts.ps1`` has cleaned up.
"""

import hashlib
import importlib
import json
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from zerobirus.core.diagnosis import diagnose
from zerobirus.core.models import Level
from zerobirus.core.report import build_report
from zerobirus.scanners.runner import ScanResult, run_scan

pytestmark = pytest.mark.windows

TOOLS = Path(__file__).resolve().parents[2] / "tools" / "windows"
MARKER = "ZeroBirusTest"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _powershell(script: str) -> str:
    exe = os.path.join(
        os.environ["SYSTEMROOT"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
    )
    done = subprocess.run(  # noqa: S603 - absolute path, fixed arguments, no shell
        [
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(TOOLS / script),
        ],
        capture_output=True,
        timeout=300,
        check=False,
    )
    out = done.stdout.decode("utf-8", errors="replace")
    print(ascii(f"{script}: exit={done.returncode} out={out.strip()[-1500:]}"))
    print(ascii(f"{script}: stderr={done.stderr.decode('utf-8', errors='replace')[-800:]}"))
    assert done.returncode == 0, script
    return out


powershell = _powershell  # public name for the other integration tests


def _run_value() -> str | None:
    winreg: Any = importlib.import_module("winreg")
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, MARKER)
            return str(value)
    except FileNotFoundError:
        return None


@pytest.fixture(scope="module")
def artifacts() -> Iterator[dict[str, Any]]:
    _powershell("remove_test_artifacts.ps1")  # in case an earlier run left something
    created = json.loads(_powershell("make_test_artifacts.ps1").strip().splitlines()[-1])
    print(ascii(f"artifacts: {created}"))
    try:
        yield created
    finally:
        _powershell("remove_test_artifacts.ps1")


@pytest.fixture(scope="module")
def inspector() -> Any:
    return importlib.import_module("zerobirus.platform.windows").create_inspector()


@pytest.fixture(scope="module")
def scan_with_artifacts(artifacts: dict[str, Any], inspector: Any) -> ScanResult:
    return run_scan(inspector, timeout=180.0)


def _items(result: ScanResult, check: str, level: Level | None = None) -> list[Any]:
    found = next(c for c in result.checks if c.check == check)
    return [f for f in found.findings if level is None or f.level is level]


def test_artifacts_were_created(artifacts: dict[str, Any]) -> None:
    assert artifacts["exe_created"]
    assert artifacts["run_key"]
    assert artifacts["started"], artifacts


def test_running_test_program_is_suspect_through_its_command_line(
    scan_with_artifacts: ScanResult,
) -> None:
    hits = [f for f in _items(scan_with_artifacts, "processes") if "zbtest.exe" in f.item]
    assert hits, "the running test program was not found"
    assert hits[0].level is Level.SUSPEITO
    assert "cmdline_miner_marker" in {s.code for s in hits[0].signals}
    assert "pool.invalid:3333" in hits[0].evidence[0]


def test_run_value_is_suspect(scan_with_artifacts: ScanResult) -> None:
    hits = [f for f in _items(scan_with_artifacts, "startup") if f.item == MARKER]
    assert hits
    assert hits[0].level is Level.SUSPEITO


def test_scheduled_task_is_suspect(
    artifacts: dict[str, Any], scan_with_artifacts: ScanResult
) -> None:
    if not artifacts["task"]:
        pytest.skip(f"the task could not be created on this runner: {artifacts['errors']}")
    hits = [f for f in _items(scan_with_artifacts, "tasks") if f.item == MARKER]
    assert hits
    assert hits[0].level is Level.SUSPEITO


def test_file_is_suspect_and_carries_its_sha256(
    artifacts: dict[str, Any], scan_with_artifacts: ScanResult
) -> None:
    exe = artifacts["exe"]
    hits = [
        f for f in _items(scan_with_artifacts, "files") if f.path and f.path.lower() == exe.lower()
    ]
    assert hits
    assert hits[0].level is Level.SUSPEITO
    assert hits[0].sha256 == hashlib.sha256(Path(exe).read_bytes()).hexdigest()


def test_defender_exclusion_is_reported_or_the_check_says_why_not(
    artifacts: dict[str, Any], scan_with_artifacts: ScanResult
) -> None:
    check = next(c for c in scan_with_artifacts.checks if c.check == "defender")
    if not artifacts["exclusion"]:
        pytest.skip(f"the exclusion could not be created on this runner: {artifacts['errors']}")
    hits = [f for f in check.findings if f.item.lower() == artifacts["dir"].lower()]
    assert hits, (check.level, check.reason)
    assert hits[0].level in (Level.CONFERIR, Level.SUSPEITO)


def test_diagnosis_names_a_miner_with_high_certainty(scan_with_artifacts: ScanResult) -> None:
    d = diagnose(scan_with_artifacts.checks, scan_with_artifacts.snapshot)
    assert d.overall is Level.SUSPEITO
    assert {t.kind: t.certainty for t in d.threats}["minerador"] == "alta"


def test_the_shared_report_has_no_user_name_and_no_secret(scan_with_artifacts: ScanResult) -> None:
    text = json.dumps(build_report(scan_with_artifacts))
    assert os.environ["USERNAME"].lower() not in text.lower()
    assert "pool.invalid:3333" in text


def test_the_scan_changed_nothing(
    artifacts: dict[str, Any], scan_with_artifacts: ScanResult
) -> None:
    exe = Path(artifacts["exe"])
    assert exe.is_file()
    assert _run_value() is not None
    assert _run_value() == f'"{exe}" {artifacts["args"]}'


def test_after_cleanup_nothing_is_found_any_more(artifacts: dict[str, Any], inspector: Any) -> None:
    _powershell("remove_test_artifacts.ps1")
    assert not Path(artifacts["dir"]).exists()
    assert _run_value() is None
    result = run_scan(inspector, timeout=180.0)
    for check in ("processes", "startup", "tasks", "files"):
        names = [f.item + f.location for f in _items(result, check)]
        assert not any("zbtest" in n.lower() or MARKER.lower() in n.lower() for n in names), (
            check,
            names,
        )
