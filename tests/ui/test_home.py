"""The home menu and the collapsible groups of the authorisation page (offscreen)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from PySide6.QtWidgets import QPushButton
from pytestqt.qtbot import QtBot
from ui_helpers import make_window, qt_warnings, run_scan

from zerobirus.ui import catalog
from zerobirus.ui.main_window import MainWindow


@pytest.fixture
def home(qtbot: QtBot, tmp_path: Path) -> Iterator[MainWindow]:
    w = make_window(qtbot, tmp_path, home=True)
    yield w
    w.wait_all()


def test_the_app_opens_on_the_menu_with_the_deep_analysis_last(home: MainWindow) -> None:
    assert home.at_home()
    keys = list(home.home_page.cards)
    assert keys[-1] == catalog.HOME_DEEP
    assert keys[:-1] == [k for k, *_ in catalog.HOME_CARDS]
    grid = home.home_page.grid
    last = grid.itemAtPosition(grid.rowCount() - 1, 0)
    assert last is not None
    assert last.widget() is home.home_page.deep  # alone on the last row


def test_choosing_the_deep_analysis_opens_the_first_stage_and_the_menu_link_returns(
    home: MainWindow,
) -> None:
    home.home_page.deep.click()
    assert not home.at_home()
    assert home.stage() == "context"
    home.home_button.click()
    assert home.at_home()


def test_a_card_that_does_not_exist_yet_says_so_and_changes_nothing(home: MainWindow) -> None:
    home.home_page.cards["clean"].click()
    assert home.at_home()
    assert home.home_page.note.text() == catalog.HOME_SOON_NOTE


def test_the_menu_link_is_off_while_the_scan_runs_and_back_on_after(
    qtbot: QtBot, home: MainWindow
) -> None:
    home.home_page.deep.click()
    assert home.home_button.isEnabled()
    home.context_page.next_button.click()
    assert home.stage() == "verify"
    assert not home.home_button.isEnabled()
    run_scan_after_start(qtbot, home)
    home.go("diagnosis")
    assert home.home_button.isEnabled()


def run_scan_after_start(qtbot: QtBot, window: MainWindow) -> None:
    window.scan_page.start_button.click()
    qtbot.waitUntil(lambda: window.result is not None, timeout=30_000)
    window.scan_page.wait()


@pytest.mark.parametrize("width", [480, 700, 1100])
def test_every_card_is_a_keyboard_button_with_a_name_and_fits_at_any_width(
    qtbot: QtBot, tmp_path: Path, width: int
) -> None:
    with qt_warnings() as warnings:
        w = make_window(qtbot, tmp_path, home=True, size=(width, 480))
        qtbot.wait(50)
    assert not warnings, warnings
    for card in w.home_page.cards.values():
        assert isinstance(card, QPushButton)
        assert card.accessibleName()
        assert card.focusPolicy().name in ("StrongFocus", "TabFocus")
    assert w.home_page.deep.width() >= w.home_page.cards["clean"].width()


def test_groups_open_by_default_only_where_a_decision_is_needed_and_counts_stay_whole(
    qtbot: QtBot, tmp_path: Path
) -> None:
    w = make_window(qtbot, tmp_path)
    run_scan(qtbot, w)
    w.go("diagnosis")
    w.diagnosis_page.next_button.click()
    page = w.authorize_page
    groups = page.groups()
    assert groups
    assert any(g.is_expanded() for g in groups)
    before = len(page.selected_items())
    page.close_all.click()
    assert not any(g.is_expanded() for g in groups)
    assert len(page.selected_items()) == before  # closing hides rows, it never drops them
    assert str(before) in page.summary.text() or before == 0
    page.open_all.click()
    assert all(g.is_expanded() for g in groups)
    for g in groups:
        assert g.header.text().startswith(("▾", "▸"))
        assert "remover" in g.header.accessibleName()
    w.wait_all()
