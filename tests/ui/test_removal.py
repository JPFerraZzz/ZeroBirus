"""Stage 4 through the real widgets (offscreen), against the fake machine."""

from collections.abc import Callable
from pathlib import Path

from PySide6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot
from ui_helpers import run_scan

from zerobirus.core.models import ActionResult, Level
from zerobirus.core.plan import ActionType
from zerobirus.platform.fake import FakeInspector, load_fixture
from zerobirus.platform.fake.ops import FakeOps
from zerobirus.ui.app import apply_theme
from zerobirus.ui.main_window import MainWindow


def make(qtbot: QtBot, tmp_path: Path, **ops_kwargs: object) -> tuple[MainWindow, FakeOps]:
    app = QApplication.instance()
    assert isinstance(app, QApplication)
    apply_theme(app, high_contrast=False)
    inspector = FakeInspector("miner_pc")
    ops = FakeOps.from_snapshot(
        load_fixture("miner_pc"), inspector.temp_entries().items, **ops_kwargs
    )
    window = MainWindow(
        inspector,
        demo=True,
        data_dir=tmp_path / "data",
        desktop_dir=tmp_path / "Desktop",
        ops_factory=lambda: ops,
    )
    qtbot.addWidget(window)
    window.resize(1100, 700)
    window.show()
    qtbot.waitExposed(window)
    return window, ops


def authorise(qtbot: QtBot, window: MainWindow, *, with_temp: bool = False) -> None:
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    page = window.authorize_page
    if with_temp:
        for row in page.rows():
            if row.item.action in (ActionType.CLEAN_TEMP_FILE, ActionType.CLEAN_TEMP_FOLDER):
                row.remove.setChecked(True)
    page.ack.setChecked(True)
    if page.extra.isVisible():
        page.extra.setText(str(len(page.selected_items())))
    page.remove_button.click()
    qtbot.waitUntil(lambda: window.authorization is not None)


def finish(qtbot: QtBot, window: MainWindow) -> None:
    qtbot.waitUntil(lambda: window.removal_page.outcome is not None, timeout=30_000)
    window.removal_page.wait()
    window.wait_background()
    window.scan_page.wait()


def test_temp_files_are_offered_but_never_preselected(qtbot: QtBot, tmp_path: Path) -> None:
    window, _ = make(qtbot, tmp_path)
    run_scan(qtbot, window)
    window.go("diagnosis")
    window.diagnosis_page.next_button.click()
    temp_rows = [
        r
        for r in window.authorize_page.rows()
        if r.item.action in (ActionType.CLEAN_TEMP_FILE, ActionType.CLEAN_TEMP_FOLDER)
    ]
    assert temp_rows
    assert all(r.item.level is Level.OK and not r.selected() for r in temp_rows)
    # fresh (age 0) entries are not offered at all
    assert not any("in-use" in r.item.target for r in temp_rows)
    window.wait_background()
    window.scan_page.wait()


def test_removal_runs_the_authorised_plan_and_shows_each_result(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window, ops = make(qtbot, tmp_path)
    authorise(qtbot, window)
    finish(qtbot, window)
    page = window.removal_page
    assert window.stage() == "removal"
    outcome = page.outcome
    assert outcome is not None
    assert outcome.restore_point == "criado"
    assert not [r for r in outcome.results if r.result is ActionResult.FALHOU]
    assert page.continue_button.isVisibleTo(page)
    assert set(page._rows) == {r.item_id for r in outcome.results}  # pyright: ignore[reportPrivateUsage]
    assert 5120 not in ops.processes
    assert window.session is not None
    assert (window.session.folder / "results.json").is_file()
    assert list(window.session.undo_dir.glob("*.json"))


def test_undo_all_puts_everything_back(qtbot: QtBot, tmp_path: Path) -> None:
    window, ops = make(qtbot, tmp_path)
    before = (dict(ops.tasks), set(ops.files), set(ops.exclusions))
    authorise(qtbot, window)
    finish(qtbot, window)
    assert (dict(ops.tasks), set(ops.files), set(ops.exclusions)) != before
    window.removal_page.undo_all_button.click()
    qtbot.waitUntil(lambda: (dict(ops.tasks), set(ops.files), set(ops.exclusions)) == before)
    window.removal_page.wait()


def test_without_a_restore_point_nothing_changes_until_the_person_confirms(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window, ops = make(qtbot, tmp_path, restore_point_error="a proteção do sistema está desligada")
    authorise(qtbot, window)
    page = window.removal_page
    qtbot.waitUntil(lambda: page.go_on_button.isVisibleTo(page), timeout=30_000)
    page.wait()
    assert "desligada" in page.status.text()
    assert page.outcome is None
    assert not any(c.startswith(("move", "kill", "perform")) for c in ops.calls)
    page.go_on_button.click()
    finish(qtbot, window)
    assert page.outcome is not None
    assert page.outcome.restore_point.startswith("não criado")


def test_stopping_at_the_restore_point_question_changes_nothing(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window, ops = make(qtbot, tmp_path, restore_point_error="sem permissão")
    authorise(qtbot, window)
    page = window.removal_page
    qtbot.waitUntil(lambda: page.stop_button.isVisibleTo(page), timeout=30_000)
    page.wait()
    page.stop_button.click()
    assert "Nada foi alterado" in page.status.text()
    assert not any(c.startswith(("move", "kill", "perform")) for c in ops.calls)
    window.wait_background()
    window.scan_page.wait()


def test_temp_cleaning_goes_to_quarantine_and_deleting_it_asks_first(
    qtbot: QtBot, tmp_path: Path, monkeypatch: object
) -> None:
    from PySide6.QtWidgets import QMessageBox

    window, ops = make(qtbot, tmp_path)
    authorise(qtbot, window, with_temp=True)
    finish(qtbot, window)
    outcome = window.removal_page.outcome
    assert outcome is not None
    temp = [
        r
        for r in outcome.results
        if r.action in (ActionType.CLEAN_TEMP_FILE, ActionType.CLEAN_TEMP_FOLDER)
    ]
    assert temp
    assert {r.result for r in temp} == {ActionResult.EM_QUARENTENA}
    assert not any(c.startswith("delete:") for c in ops.calls)

    answers: list[QMessageBox.StandardButton] = [QMessageBox.StandardButton.No]
    setter: Callable[..., None] = getattr(monkeypatch, "setattr")  # noqa: B009
    setter(QMessageBox, "question", lambda *a, **k: answers[0])
    window.removal_page.delete_button.click()
    assert not any(c.startswith("delete:") for c in ops.calls)  # "No" deletes nothing
    answers[0] = QMessageBox.StandardButton.Yes
    window.removal_page.delete_button.click()
    qtbot.waitUntil(lambda: any(c.startswith("delete:") for c in ops.calls))
    window.removal_page.wait()
