"""The home menu and the collapsible groups of the authorisation page (offscreen)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from PySide6.QtWidgets import QPushButton
from pytestqt.qtbot import QtBot
from ui_helpers import make_window, qt_warnings, run_scan

from zerobirus.ui.main_window import MainWindow


def run_scan_after_start(qtbot: QtBot, window: MainWindow) -> None:
    window.scan_page.start_button.click()
    qtbot.waitUntil(lambda: window.result is not None, timeout=30_000)
    window.scan_page.wait()


@pytest.fixture
def home(qtbot: QtBot, tmp_path: Path) -> Iterator[MainWindow]:
    w = make_window(qtbot, tmp_path, home=True)
    yield w
    w.wait_all()


def test_the_app_opens_on_the_menu_with_three_cards_and_nerdo_outlined(home: MainWindow) -> None:
    assert home.at_home()
    assert list(home.home_page.cards) == ["jogo", "pitstop", "nerdo"]
    assert home.home_page.deep is home.home_page.cards["nerdo"]
    assert home.home_page.deep.property("deep") == "true"


def test_nerdo_opens_the_seven_stage_flow_and_the_menu_button_goes_back(
    home: MainWindow,
) -> None:
    home.home_page.deep.click()
    assert not home.at_home()
    assert home.stage() == "context"
    home.home_button.click()
    assert home.at_home()


@pytest.mark.parametrize(
    ("card", "modules"),
    [
        ("jogo", ["fps", "ram", "mega"]),
        ("pitstop", ["first", "allup", "bigdiag", "drivers"]),
    ],
)
def test_each_hub_shows_its_modules_as_skeleton_and_goes_back(
    home: MainWindow, card: str, modules: list[str]
) -> None:
    home.home_page.cards[card].click()
    hub = home.hubs[card]
    assert home.screens.currentWidget() is hub
    assert list(hub.cards) == modules
    first = hub.cards[modules[0]]
    first.click()
    assert "chega numa versão seguinte" in hub.note.text()
    assert home.screens.currentWidget() is hub  # a skeleton module changes nothing
    hub.back_button.click()
    assert home.at_home()


def test_the_menu_button_is_disabled_while_the_scan_runs(qtbot: QtBot, home: MainWindow) -> None:
    home.home_page.deep.click()
    assert home.home_button.isEnabled()
    home.context_page.next_button.click()
    assert home.stage() == "verify"
    assert not home.home_button.isEnabled()
    run_scan_after_start(qtbot, home)
    home.go("diagnosis")
    assert home.home_button.isEnabled()
    home.wait_all()


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


def test_authorisation_is_grouped_by_risk_with_temporaries_last_and_unticked(
    qtbot: QtBot, tmp_path: Path
) -> None:
    w = make_window(qtbot, tmp_path)
    run_scan(qtbot, w)
    w.go("diagnosis")
    w.diagnosis_page.next_button.click()
    page = w.authorize_page
    titles = [g.header.accessibleName().split(",")[0] for g in page.groups()]
    levels = ["Crítico", "Grave", "Suspeito", "Anómalo", "Incomum"]
    ranked = [t for t in titles if t in levels]
    assert ranked == sorted(ranked, key=levels.index)  # most serious first
    assert titles[0] == "Crítico"
    for group in page.groups():
        name = group.header.accessibleName().split(",")[0]
        assert group.is_expanded() is (name in ("Crítico", "Grave"))
    for row in page.rows():
        if row.item.risk is None:
            assert row.keep.isChecked()  # Arquivos Temporários never start marked
    w.wait_all()
