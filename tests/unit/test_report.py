"""Output side: redaction, privacy, and the report-to-fixture round trip."""

import json
from pathlib import Path

import pytest
from scan_helpers import inspector

from zerobirus.cli import main
from zerobirus.core import redact as redact_module
from zerobirus.core.models import ConnectionInfo, Level, ProcessInfo
from zerobirus.core.report import build_report, render_text
from zerobirus.platform.fake import FakeInspector, load_snapshot_file
from zerobirus.scanners.runner import ScanResult, run_scan

SECRET = "s3cr3tpw"  # noqa: S105
CMD = rf"x.exe -o stratum+tcp://walletuser:{SECRET}@pool.exemplo:3333 --donate-level=1"
DROP = r"C:\Users\Ana\AppData\Roaming\kzqpx\x.exe"


def miner_inspector() -> FakeInspector:
    return inspector(processes=(ProcessInfo(9, "x.exe", DROP, CMD, r"DESKTOP-A1\Ana", None, 80.0),))


def test_scoring_sees_the_original_command_line_not_the_redacted_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(text: str) -> str:
        raise AssertionError("scoring must never call redact")

    monkeypatch.setattr(redact_module, "redact", boom)
    result = run_scan(miner_inspector())
    finding = next(f for c in result.checks for f in c.findings if f.level is Level.SUSPEITO)
    assert finding.evidence == (CMD,)
    assert "cmdline_miner_marker" in {s.code for s in finding.signals}


def test_redaction_would_hide_the_marker_but_scoring_still_finds_it() -> None:
    cmd = "tool.exe --password stratum+tcp://pool.exemplo:3333 --x"
    assert redact_module.redact(cmd) != cmd
    result = run_scan(
        inspector(processes=(ProcessInfo(9, "miner.exe", DROP, cmd, "PC\\Ana", None, None),))
    )
    assert any(f.level is Level.SUSPEITO for c in result.checks for f in c.findings)


def test_report_keeps_host_and_port_and_hides_the_credentials() -> None:
    text = json.dumps(build_report(run_scan(miner_inspector())), ensure_ascii=False)
    assert "pool.exemplo:3333" in text
    assert SECRET not in text
    assert "[oculto]" in text


def test_report_never_contains_the_secret_anywhere_including_the_snapshot() -> None:
    report = build_report(run_scan(miner_inspector()))
    assert SECRET not in json.dumps(report)
    assert "snapshot" in report


def test_report_replaces_user_names_and_machine_names() -> None:
    insp = inspector(
        processes=(
            ProcessInfo(1, "a.exe", DROP, DROP, r"DESKTOP-A1\Ana", None, None),
            ProcessInfo(2, "b.exe", None, "", r"NT AUTHORITY\SYSTEM", None, None),
        )
    )
    text = json.dumps(build_report(run_scan(insp)))
    assert "Ana" not in text
    assert "DESKTOP-A1" not in text
    assert "Utilizador1" in text
    assert "NT AUTHORITY" in text


def test_report_hides_the_content_of_personal_folders_but_keeps_downloads() -> None:
    doc = r"C:\Users\Ana\Documents\divorcio.docx"
    crack = r"C:\Users\Ana\Downloads\crack.exe"
    insp = inspector(
        processes=(
            ProcessInfo(1, "word.exe", None, rf'word.exe "{doc}"', "PC\\Ana", None, None),
            ProcessInfo(2, "c.exe", crack, crack, "PC\\Ana", None, None),
        )
    )
    text = json.dumps(build_report(run_scan(insp)))
    assert "divorcio" not in text
    assert "[omitido]" in text
    assert "Downloads" in text


def test_report_keeps_only_mining_port_connections_in_the_snapshot() -> None:
    insp = inspector(
        connections=(
            ConnectionInfo(1, "93.184.216.34", 3333, "ESTABLISHED"),
            ConnectionInfo(1, "93.184.216.35", 443, "ESTABLISHED"),
        )
    )
    snap = build_report(run_scan(insp))["snapshot"]
    assert [c["remote_port"] for c in snap["connections"]] == [3333]


def test_report_is_deterministic_and_marks_unverified_checks() -> None:
    a = build_report(run_scan(FakeInspector("no_admin_pc")), generated_at="t")
    b = build_report(run_scan(FakeInspector("no_admin_pc")), generated_at="t")
    assert a == b
    unverified = {c["check"] for c in a["checks"] if not c["verified"]}
    assert unverified == {"startup", "network", "defender", "wmi_bindings"}
    assert a["overall"] == "NAO_VERIFICADO"
    assert not a["elevated"]


def test_a_report_becomes_a_fixture_that_gives_the_same_verdicts(tmp_path: Path) -> None:
    original = run_scan(FakeInspector("miner_pc"))
    report = build_report(original)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), "utf-8")
    replay = run_scan(FakeInspector(load_snapshot_file(path)))

    def shape(result: ScanResult) -> list[tuple[str, str, str]]:
        return sorted(
            (c.check, f.level.value, f.item.split("\\")[-1])
            for c in result.checks
            for f in c.findings
        )

    assert shape(replay) == shape(original)
    assert replay.checks[0].level == original.checks[0].level


def test_cli_scan_out_writes_a_redacted_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "r.json"
    assert main(["scan", "--demo", "miner_pc", "--json", "--out", str(out)]) == 0
    data = json.loads(out.read_text("utf-8"))
    text = out.read_text("utf-8")
    assert data["overall"] == "SUSPEITO"
    assert "pass@" not in text
    assert "Ana" not in text
    assert str(out) in capsys.readouterr().out


def test_cli_scan_json_prints_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--demo", "clean_pc", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["overall"] == "OK"


def test_cli_scan_text_summary(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--demo", "miner_pc"]) == 0
    out = capsys.readouterr().out
    assert "Resultado geral: SUSPEITO" in out
    assert "nada foi alterado" in out


def test_cli_scan_without_demo_refuses_off_windows(capsys: pytest.CaptureFixture[str]) -> None:
    import sys

    if sys.platform == "win32":
        pytest.skip("only meaningful off Windows")
    assert main(["scan", "--json"]) == 3
    assert "Windows" in capsys.readouterr().err


def test_cli_scan_bad_fixture_is_a_clear_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 1, "elevated": true}', "utf-8")
    assert main(["scan", "--fixture", str(bad)]) == 2
    assert "fixture" in capsys.readouterr().err


def test_render_text_mentions_not_verified_reasons() -> None:
    text = render_text(build_report(run_scan(FakeInspector("no_admin_pc"))))
    assert "não verificado" in text
    assert "sem administrador" in text.lower()
