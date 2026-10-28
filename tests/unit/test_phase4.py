"""Stage 5 and 6 logic: diff of scans, Defender scan state from facts, advice, cleanup."""

from datetime import datetime
from pathlib import Path

import pytest

from zerobirus.core.after import PASSWORDS, REFORMAT, advice, render_final_report
from zerobirus.core.compare import (
    Change,
    baseline_from_checks,
    baseline_from_json,
    baseline_to_json,
    compare_scans,
)
from zerobirus.core.defender_scan import ScanEvent, ScanState, interpret
from zerobirus.core.diagnosis import diagnose
from zerobirus.core.models import ActionResult, CheckResult, Finding, Level
from zerobirus.core.session import (
    create_session,
    find_pending_restart_check,
    update_session,
)
from zerobirus.platform.fake import FakeInspector
from zerobirus.platform.fake.defender_scan import FakeDefenderScanner
from zerobirus.remediation.cleanup import purge_session_work
from zerobirus.scanners.runner import run_scan


def check(name: str, *findings: Finding, verified: bool = True) -> CheckResult:
    return CheckResult(
        check=name, findings=findings, verified=verified, reason="" if verified else "x"
    )


def finding(item: str, level: Level = Level.SUSPEITO) -> Finding:
    return Finding(id=item, item=item, location="loc", level=level, description="d")


# diff ------------------------------------------------------------------------------------


def test_diff_splits_gone_remaining_and_came_back() -> None:
    before = baseline_from_checks((check("tasks", finding("A"), finding("B")),))
    after = (check("tasks", finding("B"), finding("C")),)
    diff = compare_scans(before, after)
    assert [c.item for c in diff.gone] == ["A"]
    assert [c.item for c in diff.remaining] == ["B"]
    assert [c.item for c in diff.came_back] == ["C"]
    assert not diff.clean


def test_clean_needs_nothing_suspicious_and_everything_verified() -> None:
    before = baseline_from_checks((check("tasks", finding("A")),))
    assert compare_scans(before, (check("tasks"),)).clean
    unverified = compare_scans(before, (check("tasks", verified=False),))
    assert not unverified.clean
    assert unverified.still_unverified == ("tasks",)


def test_a_conferir_left_over_does_not_make_it_unclean() -> None:
    before = baseline_from_checks((check("tasks", finding("A")),))
    assert compare_scans(before, (check("tasks", finding("A", Level.CONFERIR)),)).clean


def test_matching_ignores_case_and_ok_findings_are_not_tracked() -> None:
    before = [Change("tasks", "Task", "LOC", Level.SUSPEITO)]
    after = (check("tasks", finding("task"), finding("fine", Level.OK)),)
    diff = compare_scans(before, after)
    assert not diff.gone
    assert len(diff.remaining) == 1
    assert not diff.came_back


def test_the_baseline_survives_json_and_is_redacted() -> None:
    base = [Change("files", "x -p hunter2password", r"C:\a", Level.SUSPEITO)]
    data = baseline_to_json(base)
    assert baseline_from_json(data)[0].check == "files"
    assert "hunter2password" not in str(data) or "[oculto]" in str(data)
    with pytest.raises(ValueError, match="list"):
        baseline_from_json({"a": 1})


def test_the_miner_scan_compared_with_itself_remains_unclean() -> None:
    result = run_scan(FakeInspector("miner_pc"))
    diff = compare_scans(baseline_from_checks(result.checks), result.checks)
    assert diff.remaining
    assert not diff.gone
    assert not diff.clean


# Defender scan state ---------------------------------------------------------------------


def ev(i: int, t: str) -> ScanEvent:
    return ScanEvent(i, t)


@pytest.mark.parametrize(
    ("events", "alive", "expected"),
    [
        ([], True, ScanState.RUNNING),
        ([ev(1000, "1")], True, ScanState.RUNNING),
        ([ev(1000, "1"), ev(1001, "2")], False, ScanState.COMPLETED),
        ([ev(1000, "1"), ev(1002, "2")], False, ScanState.STOPPED),
        ([ev(1000, "1"), ev(1005, "2")], False, ScanState.FAILED),
        ([ev(1000, "1")], False, ScanState.UNKNOWN),
        ([], False, ScanState.UNKNOWN),
        ([ev(1001, "1"), ev(1000, "2")], True, ScanState.RUNNING),  # a newer scan started
    ],
)
def test_scan_state_comes_from_events_and_the_process(
    events: list[ScanEvent], alive: bool, expected: ScanState
) -> None:
    assert interpret(events, started=True, process_alive=alive).state is expected


def test_not_started_and_unrelated_events() -> None:
    assert interpret([], started=False, process_alive=None).state is ScanState.NOT_STARTED
    other = interpret([ev(5007, "1")], started=True, process_alive=False)
    assert other.state is ScanState.UNKNOWN


def test_a_vanished_scan_is_never_reported_as_completed() -> None:
    assert interpret([ev(1000, "1")], started=True, process_alive=None).state is ScanState.UNKNOWN


def test_fake_scanner_walks_through_running_to_the_end() -> None:
    s = FakeDefenderScanner(ScanState.COMPLETED, polls_until_end=1)
    assert s.status(None, None).state is ScanState.NOT_STARTED
    pid, started = s.start()
    assert s.status(pid, started).state is ScanState.RUNNING
    assert s.status(pid, started).state is ScanState.COMPLETED


# advice and report -----------------------------------------------------------------------


def miner_diagnosis() -> object:
    r = run_scan(FakeInspector("miner_pc"))
    return diagnose(r.checks, r.snapshot)


def test_passwords_advice_only_for_trojans_and_reformat_rule_always_told() -> None:
    r = run_scan(FakeInspector("miner_pc"))
    d = diagnose(r.checks, r.snapshot)
    lines = advice(d, [ActionResult.REMOVIDO])
    assert REFORMAT in lines
    assert (PASSWORDS in lines) == any(t.kind == "trojan" for t in d.threats)
    assert PASSWORDS not in advice(None)


def test_failures_put_the_reformat_rule_first() -> None:
    assert advice(None, [ActionResult.FALHOU])[0] == REFORMAT
    assert advice(None, [], anything_failed=True)[0] == REFORMAT


def test_final_report_lists_what_was_done_and_what_was_not() -> None:
    text = render_final_report(
        version="0",
        session_id="s",
        overall="SUSPEITO",
        results=[("a.exe", "EM_QUARENTENA", "ok")],
        diff_lines=[],
        defender_text="não foi feita",
        advice_lines=["x"],
    )
    assert "a.exe: EM_QUARENTENA" in text
    assert "(a verificação repetida não foi feita)" in text


# sessions and cleanup --------------------------------------------------------------------


def test_pending_restart_sessions_are_found_newest_first(tmp_path: Path) -> None:
    a = create_session(tmp_path, datetime(2026, 1, 1, 10), tool_version="t", elevated=True)
    b = create_session(tmp_path, datetime(2026, 1, 2, 10), tool_version="t", elevated=True)
    assert find_pending_restart_check(tmp_path) == []
    update_session(a, pending_restart_check=True)
    update_session(b, pending_restart_check=True)
    assert find_pending_restart_check(tmp_path) == [b.session_id, a.session_id]
    update_session(b, pending_restart_check=False)
    assert find_pending_restart_check(tmp_path) == [a.session_id]


def test_purge_removes_only_quarantine_and_undo_and_keeps_reports(tmp_path: Path) -> None:
    s = create_session(tmp_path, datetime(2026, 1, 1), tool_version="t", elevated=True)
    (s.folder / "quarantine").mkdir()
    (s.folder / "quarantine" / "x.quar").write_text("x")
    s.undo_dir.mkdir()
    (s.undo_dir / "i.json").write_text("{}")
    s.write("findings.json", {"a": 1})
    assert sorted(purge_session_work(s)) == ["quarantine", "undo"]
    assert not (s.folder / "quarantine").exists()
    assert (s.folder / "findings.json").is_file()
    assert (s.folder / "session.json").is_file()


def test_purge_never_follows_a_link(tmp_path: Path) -> None:
    s = create_session(tmp_path, datetime(2026, 1, 1), tool_version="t", elevated=True)
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    (s.folder / "quarantine").symlink_to(outside, target_is_directory=True)
    assert purge_session_work(s) == []
    assert (outside / "keep.txt").read_text() == "keep"
