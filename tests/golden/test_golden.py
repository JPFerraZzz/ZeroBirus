"""Golden tests: whole scans over the synthetic fixtures of BRIEF section 12.

The expectations are written out in full on purpose. If a weight or a rule changes, these
tests change too, and the diff shows exactly which verdicts moved.
"""

import pytest

from zerobirus.core.diagnosis import diagnose
from zerobirus.core.models import CheckResult, Level
from zerobirus.platform.fake import FakeInspector
from zerobirus.scanners.runner import ScanResult, run_scan


def scan(name: str) -> ScanResult:
    return run_scan(FakeInspector(name))


def verdicts(result: ScanResult, *, with_ok: bool = False) -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = {}
    for check in result.checks:
        rows = sorted(
            (f.level.value, f.item) for f in check.findings if with_ok or f.level is not Level.OK
        )
        if rows:
            out[check.check] = rows
    return out


def by_name(result: ScanResult) -> dict[str, CheckResult]:
    return {c.check: c for c in result.checks}


def test_clean_pc_is_ok_with_no_findings_and_no_gaps() -> None:
    result = scan("clean_pc")
    assert verdicts(result) == {}
    assert all(c.verified for c in result.checks)
    assert diagnose(result.checks).overall is Level.OK


def test_miner_pc_is_detected_at_the_right_level_everywhere() -> None:
    result = scan("miner_pc")
    assert verdicts(result) == {
        "processes": [
            ("SUSPEITO", "svchost.exe (PID 6044)"),
            ("SUSPEITO", "svchost32.exe (PID 5120)"),
        ],
        "startup": [("SUSPEITO", "WindowsUpdateHelper")],
        "tasks": [("SUSPEITO", "SystemOptimizer")],
        "files": [
            ("CONFERIR", "setup.exe"),
            ("SUSPEITO", "svchost32.exe"),
        ],
        "network": [("SUSPEITO", "svchost32.exe → 93.184.216.34:3333")],
        "defender": [
            ("CONFERIR", "C:\\Users\\Ana\\AppData\\Roaming\\kzqpx"),
            ("CONFERIR", "Microsoft Defender"),
        ],
        "hosts": [("SUSPEITO", "www.virustotal.com")],
        "wmi_bindings": [("SUSPEITO", "SysConsumer")],
    }
    assert diagnose(result.checks, result.snapshot).overall is Level.SUSPEITO


def test_miner_diagnosis_names_the_threat_and_the_entry_vector() -> None:
    result = scan("miner_pc")
    d = diagnose(result.checks, result.snapshot)
    kinds = {t.kind: t.certainty for t in d.threats}
    assert kinds["minerador"] == "alta"
    assert "crack" in d.entry_vector.lower()
    assert "mesma altura" in d.entry_vector


def test_suspect_files_carry_their_sha256() -> None:
    result = scan("miner_pc")
    files = by_name(result)["files"]
    hashed = [f for f in files.findings if f.level is Level.SUSPEITO]
    assert hashed
    assert all(f.sha256 == "0123456789abcdef" * 4 for f in hashed)


def test_false_positives_pc_has_no_suspect_and_explains_normal_things() -> None:
    result = scan("false_positives_pc")
    assert verdicts(result) == {"services": [("CONFERIR", "Acme Backup")]}
    normal = {f.item for c in result.checks for f in c.findings if f.level is Level.OK}
    for name in ("Discord.exe (PID 7001)", "Spotify.exe (PID 7002)", "steam.exe (PID 7003)"):
        assert name in normal
    assert "svchost.exe (PID 812)" in normal
    assert "MsMpEng.exe (PID 2201)" in normal
    assert "System Idle Process" in normal


def test_genuine_svchost_with_unreadable_path_is_neither_flagged_nor_called_normal() -> None:
    result = scan("false_positives_pc")
    items = {f.item for c in result.checks for f in c.findings}
    assert not any("PID 901" in i for i in items)


def test_no_admin_pc_reports_incomplete_checks_as_nao_verificado_never_ok() -> None:
    result = scan("no_admin_pc")
    levels = {c.check: c.level for c in result.checks}
    assert levels["wmi_bindings"] is Level.NAO_VERIFICADO
    assert levels["defender"] is Level.NAO_VERIFICADO
    assert levels["startup"] is Level.NAO_VERIFICADO
    assert levels["network"] is Level.NAO_VERIFICADO
    for check in ("wmi_bindings", "defender", "startup", "network"):
        assert not by_name(result)[check].verified
        assert by_name(result)[check].reason
    assert diagnose(result.checks).overall is Level.NAO_VERIFICADO
    assert {n.check for n in diagnose(result.checks).not_verified} == {
        "wmi_bindings",
        "defender",
        "startup",
        "network",
    }


@pytest.mark.parametrize("name", ["clean_pc", "miner_pc", "false_positives_pc", "no_admin_pc"])
def test_scans_are_deterministic(name: str) -> None:
    a, b = scan(name), scan(name)
    assert a.checks == b.checks
