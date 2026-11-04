"""The stages, their gates, and the authorisation, driven through the real widgets (offscreen)."""

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QCheckBox, QLabel, QPushButton, QRadioButton
from pytestqt.qtbot import QtBot
from ui_helpers import make_window, run_scan

from zerobirus.core.context import Symptom
from zerobirus.core.models import Level
from zerobirus.core.plan import ActionType, AuthorizedPlan
from zerobirus.ui.main_window import STAGE_KEYS, MainWindow


@pytest.fixture
def window(qtbot: QtBot, tmp_path: Path) -> Iterator[MainWindow]:
    w = make_window(qtbot, tmp_path)
    yield w
    w.scan_page.cancel()
    w.scan_page.wait()


def test_the_window_starts_on_the_first_stage_and_nothing_later_is_open(window: MainWindow) -> None:
    assert window.stage() == "context"
    assert window.unlocked_stage() == "context"
    for key in STAGE_KEYS[1:]:
        window.go(key)
        assert window.stage() == "context", f"{key} opened before its time"
    enabled = [bool(window.rail.item(i).flags() & Qt.ItemFlag.ItemIsEnabled) for i in range(7)]
    assert enabled == [True] + [False] * 6


def test_the_stages_open_one_at_a_time_as_each_one_is_finished(
    qtbot: QtBot, window: MainWindow
) -> None:
    window.context_page.next_button.click()
    assert window.stage() == "verify"
    assert window.unlocked_stage() == "verify"
    window.go("authorize")
    assert window.stage() == "verify"
    window.scan_page.start_button.click()
    qtbot.waitUntil(lambda: window.result is not None, timeout=30_000)
    assert window.unlocked_stage() == "diagnosis"
    assert window.stage() == "verify"  # finished, but the person still has to press the button
    window.scan_page.next_button.click()
    assert window.stage() == "diagnosis"
    window.diagnosis_page.next_button.click()
    assert window.stage() == "authorize"
    assert window.unlocked_stage() == "authorize"
    window.go("context")  # going back is always allowed
    assert window.stage() == "context"
    window.go("authorize")
    assert window.stage() == "authorize"


def test_the_scan_changes_nothing_and_reports_progress(qtbot: QtBot, window: MainWindow) -> None:
    window.context_page.next_button.click()
    window.scan_page.start_button.click()
    qtbot.waitUntil(lambda: window.result is not None, timeout=30_000)
    assert window.scan_page.progress.value() == window.scan_page.progress.maximum() == 9
    assert "9 de 9" in window.scan_page.progress_text.text()
    assert "Nada foi alterado" in window.scan_page.status.text()
    assert window.session is not None
    assert (window.session.folder / "findings.json").is_file()
    assert window.session.read("session.json")["stage"] == "diagnosis"


def test_symptoms_reorder_the_checks_but_every_check_still_runs(
    qtbot: QtBot, window: MainWindow
) -> None:
    window.context_page.boxes[Symptom.ANTIVIRUS_OFF].setChecked(True)
    window.context_page.boxes[Symptom.OTHER].setChecked(True)
    window.context_page.other.setText("<b>x</b>")
    window.context_page.next_button.click()
    order = list(window.scan_page.rows())
    assert order[0] == "defender"
    assert len(order) == 9
    window.scan_page.start_button.click()
    qtbot.waitUntil(lambda: window.result is not None, timeout=30_000)
    assert len(window.result.checks) == 9  # type: ignore[union-attr]
    assert window.session is not None
    saved = window.session.read("context.json")
    assert saved["symptoms"] == ["antivirus_off", "other"]
    assert saved["other_text"] == "<b>x</b>"


def test_the_authorisation_page_preselects_suspeito_and_never_conferir(
    qtbot: QtBot, window: MainWindow
) -> None:
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    page = window.authorize_page
    rows = page.rows()
    assert rows
    for row in rows:
        if row.item.level is Level.CONFERIR:
            assert row.keep.isChecked(), row.item
        if (
            row.item.level is Level.SUSPEITO
            and row.item.action is not ActionType.ADD_FIREWALL_BLOCK
        ):
            assert row.remove.isChecked(), row.item


def test_the_removing_button_stays_off_until_the_person_confirms_and_the_safe_action_has_focus(
    qtbot: QtBot, window: MainWindow
) -> None:
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    page = window.authorize_page
    assert not page.remove_button.isEnabled()
    assert page.back_button.isDefault()
    assert page.remove_button.property("role") == "danger"
    assert str(len(page.selected_items())) in page.remove_button.text()
    page.ack.setChecked(True)
    assert page.remove_button.isEnabled()
    for row in page.rows():
        row.keep.setChecked(True)
    assert not page.remove_button.isEnabled()  # nothing selected: nothing to authorise
    assert "nenhum item" in page.summary.text()


def test_escape_on_the_authorisation_page_goes_back_not_forward(
    qtbot: QtBot, window: MainWindow
) -> None:
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    QTest.keyClick(window.authorize_page, Qt.Key.Key_Escape)
    assert window.stage() == "diagnosis"
    assert window.authorization is None


def test_authorising_saves_the_plan_before_anything_and_builds_the_immutable_plan(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = make_window(qtbot, tmp_path)
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    page = window.authorize_page
    chosen = {i.id for i in page.selected_items()}
    page.ack.setChecked(True)
    page.remove_button.click()
    qtbot.waitUntil(lambda: window.authorization is not None)
    auth = window.authorization
    assert isinstance(auth, AuthorizedPlan)
    assert {i.id for i in auth.items} == chosen
    assert auth.verify()
    plan_files = list((tmp_path / "Desktop").glob("ZeroBirus-plano-*.txt"))
    assert len(plan_files) == 1
    text = plan_files[0].read_text("utf-8-sig")
    assert "Nada foi alterado ainda" in text
    assert text.count("\n  [x] ") == len(chosen)
    assert window.session is not None
    stored = window.session.read("plan.json")
    assert {i["id"] for i in stored["items"] if i["approved"]} == chosen
    assert window.stage() == "removal"
    qtbot.waitUntil(lambda: window.removal_page.outcome is not None, timeout=30_000)
    window.removal_page.wait()
    window.wait_background()
    window.scan_page.wait()


def test_a_plan_that_cannot_be_saved_stops_everything(qtbot: QtBot, tmp_path: Path) -> None:
    window = make_window(qtbot, tmp_path)
    blocker = tmp_path / "Desktop"
    blocker.write_text("this is a file, not a folder", "utf-8")
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    page = window.authorize_page
    page.ack.setChecked(True)
    page.remove_button.click()
    assert window.authorization is None
    assert "Nada foi alterado" in page.message.text()
    assert window.stage() == "authorize"
    window.scan_page.wait()


def test_keeping_everything_removes_nothing_and_creates_no_authorisation(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = make_window(qtbot, tmp_path)
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    window.authorize_page.keep_button.click()
    assert window.authorization is None
    assert window.stage() == "after"
    assert not list((tmp_path / "Desktop").glob("*.txt"))
    window.scan_page.wait()


def test_every_button_has_a_name_a_shortcut_and_every_label_is_plain_text(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = make_window(qtbot, tmp_path)
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    for label in window.findChildren(QLabel):
        assert label.textFormat() == Qt.TextFormat.PlainText, label.text()
    for b in window.findChildren(QPushButton):
        assert b.accessibleName(), b.text()
        if b.property("role") not in ("link", "card", "group"):  # Tab + Enter, no Alt letter
            assert "&" in b.text(), f"no Alt shortcut on {b.text()!r}"
    for box in window.findChildren(QCheckBox) + window.findChildren(QRadioButton):
        assert box.accessibleName() or box.text()
    window.scan_page.wait()


def test_the_session_files_hold_no_secret(qtbot: QtBot, tmp_path: Path) -> None:
    window = make_window(qtbot, tmp_path)
    run_scan(qtbot, window)
    assert window.session is not None
    for file in window.session.folder.glob("*.json"):
        assert "pass@" not in file.read_text("utf-8")
        json.loads(file.read_text("utf-8"))
    window.scan_page.wait()
