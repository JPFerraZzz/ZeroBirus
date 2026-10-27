"""Stages 5 and 6 through the real widgets (offscreen), with the fake machine and scanner."""

from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox
from pytestqt.qtbot import QtBot
from test_removal import authorise, finish

from zerobirus.core.compare import Change, baseline_to_json
from zerobirus.core.defender_scan import ScanState
from zerobirus.core.models import Level
from zerobirus.core.session import create_session, update_session
from zerobirus.platform.fake import FakeInspector, load_fixture
from zerobirus.platform.fake.defender_scan import FakeDefenderScanner
from zerobirus.platform.fake.ops import FakeOps
from zerobirus.ui.app import apply_theme
from zerobirus.ui.main_window import MainWindow


def make(
    qtbot: QtBot, tmp_path: Path, scanner: FakeDefenderScanner, restarts: list[int]
) -> MainWindow:
    app = QApplication.instance()
    assert isinstance(app, QApplication)
    apply_theme(app, high_contrast=False)
    inspector = FakeInspector("miner_pc")
    ops = FakeOps.from_snapshot(load_fixture("miner_pc"), inspector.temp_entries().items)
    window = MainWindow(
        inspector,
        demo=True,
        data_dir=tmp_path / "data",
        desktop_dir=tmp_path / "Desktop",
        ops_factory=lambda: ops,
        defender_factory=lambda: scanner,
    )
    window.confirm_page._restart = lambda: restarts.append(1)  # pyright: ignore[reportPrivateUsage]
    window.confirm_page._timer.setInterval(20)  # pyright: ignore[reportPrivateUsage]
    qtbot.addWidget(window)
    window.resize(1100, 700)
    window.show()
    qtbot.waitExposed(window)
    return window


def to_confirm(qtbot: QtBot, window: MainWindow) -> None:
    authorise(qtbot, window)
    finish(qtbot, window)
    window.removal_page.continue_button.click()
    assert window.stage() == "confirm"


def test_the_baseline_is_saved_and_the_rescan_shows_the_difference(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = make(qtbot, tmp_path, FakeDefenderScanner(), [])
    to_confirm(qtbot, window)
    assert window.session is not None
    assert (window.session.folder / "baseline.json").is_file()
    page = window.confirm_page
    page.rescan_button.click()
    qtbot.waitUntil(lambda: page.diff is not None, timeout=30_000)
    assert page.diff is not None
    assert page.diff.remaining  # the fake inspector is static: it still "sees" the miner
    assert page.summary.text() != ""
    assert (window.session.folder / "confirmation.json").is_file()
    window.wait_all()


def test_the_defender_scan_ends_only_when_the_events_say_so(qtbot: QtBot, tmp_path: Path) -> None:
    scanner = FakeDefenderScanner(ScanState.COMPLETED, polls_until_end=2)
    window = make(qtbot, tmp_path, scanner, [])
    to_confirm(qtbot, window)
    page = window.confirm_page
    page.defender_button.click()
    qtbot.waitUntil(
        lambda: (
            page.defender_status is not None and page.defender_status.state is ScanState.COMPLETED
        ),
        timeout=10_000,
    )
    assert scanner.start_calls == 1
    assert page.defender_button.isEnabled()
    window.wait_all()


def test_a_scan_that_vanishes_is_not_shown_as_completed(qtbot: QtBot, tmp_path: Path) -> None:
    scanner = FakeDefenderScanner(ScanState.UNKNOWN, polls_until_end=0)
    window = make(qtbot, tmp_path, scanner, [])
    to_confirm(qtbot, window)
    page = window.confirm_page
    page.defender_button.click()
    qtbot.waitUntil(lambda: page.defender_status is not None, timeout=10_000)
    assert page.defender_status is not None
    assert page.defender_status.state is ScanState.UNKNOWN
    window.wait_all()


def test_restart_asks_first_and_marks_the_session(
    qtbot: QtBot, tmp_path: Path, monkeypatch: object
) -> None:
    restarts: list[int] = []
    window = make(qtbot, tmp_path, FakeDefenderScanner(), restarts)
    to_confirm(qtbot, window)
    answers = [QMessageBox.StandardButton.No]

    def fake_question(*_a: object, **_k: object) -> QMessageBox.StandardButton:
        return answers[0]

    getattr(monkeypatch, "setattr")(QMessageBox, "question", fake_question)  # noqa: B009
    window.confirm_page.restart_button.click()
    assert not restarts
    answers[0] = QMessageBox.StandardButton.Yes
    window.confirm_page.restart_button.click()
    assert restarts == [1]
    assert window.session is not None
    assert window.session.read("session.json")["pending_restart_check"] is True
    window.wait_all()


def test_the_next_start_offers_the_post_restart_check_and_compares_with_the_baseline(
    qtbot: QtBot, tmp_path: Path
) -> None:
    data = tmp_path / "data"
    old = create_session(data, datetime(2026, 1, 1, 9), tool_version="t", elevated=True)
    old.write("baseline.json", baseline_to_json([Change("tasks", "Old", "loc", Level.SUSPEITO)]))
    update_session(old, pending_restart_check=True)
    window = make(qtbot, tmp_path, FakeDefenderScanner(), [])
    page = window.context_page
    assert page.pending_button.isVisibleTo(page)
    page.pending_button.click()
    assert window.stage() == "confirm"
    assert window.session is not None
    assert window.session.session_id == old.session_id
    assert window.session.read("session.json")["pending_restart_check"] is False
    window.confirm_page.rescan_button.click()
    qtbot.waitUntil(lambda: window.confirm_page.diff is not None, timeout=30_000)
    assert window.confirm_page.diff is not None
    assert [c.item for c in window.confirm_page.diff.gone] == ["Old"]
    window.wait_all()


def test_the_final_report_is_saved_and_the_work_folder_is_cleaned_only_after_asking(
    qtbot: QtBot, tmp_path: Path, monkeypatch: object
) -> None:
    window = make(qtbot, tmp_path, FakeDefenderScanner(), [])
    to_confirm(qtbot, window)
    window.confirm_page.continue_button.click()
    assert window.stage() == "after"
    page = window.after_page
    assert "Troca" in page.advice_box.text() or "formatar" in page.advice_box.text()
    page.save_button.click()
    saved = list((tmp_path / "Desktop").glob("ZeroBirus-relatorio-final-*.txt"))
    assert len(saved) == 1
    assert "O que foi feito" in saved[0].read_text("utf-8-sig")

    assert window.session is not None
    answers = [QMessageBox.StandardButton.No]

    def fake_question(*_a: object, **_k: object) -> QMessageBox.StandardButton:
        return answers[0]

    getattr(monkeypatch, "setattr")(QMessageBox, "question", fake_question)  # noqa: B009
    page.clean_button.click()
    assert (window.session.folder / "undo").exists()
    answers[0] = QMessageBox.StandardButton.Yes
    page.clean_button.click()
    assert not (window.session.folder / "undo").exists()
    assert (window.session.folder / "relatorio-final.txt").is_file()
    window.wait_all()


def test_keeping_everything_still_reaches_a_useful_last_page(qtbot: QtBot, tmp_path: Path) -> None:
    window = make(qtbot, tmp_path, FakeDefenderScanner(), [])
    from ui_helpers import run_scan

    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    window.authorize_page.keep_button.click()
    assert window.stage() == "after"
    assert "Não foi removido nada" in window.after_page.note.text()
    window.wait_all()
