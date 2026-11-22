"""FPS Optimizer and RAM Lover on the fake machine (offscreen)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot
from ui_helpers import make_window

from zerobirus.core.models import ActionResult
from zerobirus.core.tweaks import CATALOG, CATEGORIES, MEGA_TWEAKS, Danger
from zerobirus.platform.fake.ops import FakeOps
from zerobirus.ui import catalog
from zerobirus.ui.main_window import MainWindow
from zerobirus.ui.page_game import FpsPage, MegaPage, RamPage


@pytest.fixture
def window(qtbot: QtBot, tmp_path: Path) -> Iterator[MainWindow]:
    w = make_window(qtbot, tmp_path, home=True)
    yield w
    w.wait_all()


def open_module(qtbot: QtBot, w: MainWindow, key: str, waiting_for: str) -> None:
    w.home_page.cards["jogo"].click()
    w.hubs["jogo"].cards[key].click()
    page = w.modules[key]
    assert w.screens.currentWidget() is page
    page.wait()
    qtbot.waitUntil(lambda: not page.status.text().startswith(waiting_for), timeout=10_000)


def test_the_game_hub_opens_all_three_modules(window: MainWindow) -> None:
    window.home_page.cards["jogo"].click()
    assert {"fps", "ram", "mega"} <= catalog.MODULES_AVAILABLE
    for key in ("fps", "ram", "mega"):
        window.hubs["jogo"].cards[key].click()
        assert window.screens.currentWidget() is window.modules[key]
        window.modules[key].wait()
        window.modules[key].back_button.click()
        assert window.screens.currentWidget() is window.hubs["jogo"]


def test_fps_lists_the_settings_with_the_safe_ones_ticked_and_nothing_changes_until_applied(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(qtbot, window, "fps", "A ler")
    page = window.modules["fps"]
    assert isinstance(page, FpsPage)
    ops = page.ops()
    assert isinstance(ops, FakeOps)
    assert ops.settings == {}
    ticked = {k for k, r in page.rows.items() if r.check.isChecked()}
    assert ticked == {"game_mode", "gamebar_capture", "app_capture"}
    assert not page.rows["hags"].check.isEnabled()  # not exposed on the fake PC
    assert page.apply_button.isEnabled()


def test_fps_apply_confirms_each_setting_and_undo_puts_them_back(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(qtbot, window, "fps", "A ler")
    page = window.modules["fps"]
    assert isinstance(page, FpsPage)
    ops = page.ops()
    assert isinstance(ops, FakeOps)
    page.apply_button.click()
    qtbot.waitUntil(lambda: bool(page.results), timeout=10_000)
    page.wait()
    assert len(ops.settings) == 3
    assert "3 definições aplicadas" in page.status.text()
    assert "antes" in page.status.text()
    assert page.undo_button.isVisibleTo(page)
    page.undo_button.click()
    page.wait()
    qtbot.waitUntil(lambda: ops.settings == {}, timeout=10_000)


def test_fps_asks_before_going_on_without_a_restore_point(qtbot: QtBot, window: MainWindow) -> None:
    open_module(qtbot, window, "fps", "A ler")
    page = window.modules["fps"]
    assert isinstance(page, FpsPage)
    ops = page.ops()
    assert isinstance(ops, FakeOps)
    ops.restore_point_error = "proteção do sistema desativada"
    page.apply_button.click()
    qtbot.waitUntil(lambda: page.continue_button.isVisibleTo(page), timeout=10_000)
    assert ops.settings == {}  # nothing changed while the person decides
    page.continue_button.click()
    qtbot.waitUntil(lambda: len(ops.settings) == 3, timeout=10_000)
    page.wait()


def test_ram_shows_the_numbers_and_closing_needs_the_acknowledgement(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(qtbot, window, "ram", "A ler")
    page = window.modules["ram"]
    assert isinstance(page, RamPage)
    assert "RAM em uso" in page.status.text()
    names = [r.check.text() for r in page.rows.values()]
    assert names  # Discord, Spotify and the others the demo can offer
    assert not any(r.check.isChecked() for r in page.rows.values())  # nothing is pre-ticked
    assert not page.apply_button.isEnabled()
    first = next(iter(page.rows.values()))
    first.check.setChecked(True)
    assert not page.apply_button.isEnabled()  # still needs the acknowledgement
    page.ack.setChecked(True)
    assert page.apply_button.isEnabled()
    assert "Fechar o programa" in page.apply_button.text().replace("&", "")
    page.ack.setChecked(False)
    assert not page.apply_button.isEnabled()


def test_ram_never_offers_a_windows_process(qtbot: QtBot, window: MainWindow) -> None:
    open_module(qtbot, window, "ram", "A ler")
    page = window.modules["ram"]
    assert isinstance(page, RamPage)
    offered = " ".join(r.check.text().lower() for r in page.rows.values())
    assert "svchost" not in offered
    assert "system" not in offered


def test_ram_closes_the_chosen_program_asks_for_no_restore_point_and_cannot_undo(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(qtbot, window, "ram", "A ler")
    page = window.modules["ram"]
    assert isinstance(page, RamPage)
    ops = page.ops()
    assert isinstance(ops, FakeOps)
    pid = next(iter(page.rows))
    assert pid in ops.processes
    page.rows[pid].check.setChecked(True)
    page.ack.setChecked(True)
    page.apply_button.click()
    qtbot.waitUntil(lambda: bool(page.results), timeout=10_000)
    page.wait()
    assert pid not in ops.processes
    assert "restore_point" not in ops.calls
    assert not page.undo_button.isVisibleTo(page)
    assert "Fechados 1 de 1" in page.status.text()


def test_the_plan_is_saved_in_the_session_before_anything_changes(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(qtbot, window, "fps", "A ler")
    page = window.modules["fps"]
    assert isinstance(page, FpsPage)
    page.apply_button.click()
    qtbot.waitUntil(lambda: bool(page.results), timeout=10_000)
    page.wait()
    plan = next(window.data_dir.glob("Sessions/*/plan.json"))
    assert "game_mode" in plan.read_text("utf-8")


def test_megatweaker_groups_by_category_and_keeps_the_aggressive_ones_unticked(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(qtbot, window, "mega", "A ler")
    page = window.modules["mega"]
    assert isinstance(page, MegaPage)
    titles = [g.header.accessibleName().split(",")[0] for g in page.groups]
    assert titles[:4] == list(CATEGORIES)
    assert titles[-1] == catalog.MEGA_RISKY_GROUP
    assert [g.is_expanded() for g in page.groups] == [True, False, False, False, False]
    for tid, row in page.rows.items():
        danger = CATALOG[tid].danger
        assert row.check.isChecked() is (danger is Danger.SEGURO and row.check.isEnabled()), tid
    assert not page.risky.isVisibleTo(page)


def test_ticking_an_aggressive_setting_needs_the_acknowledgement(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(qtbot, window, "mega", "A ler")
    page = window.modules["mega"]
    assert isinstance(page, MegaPage)
    assert page.apply_button.isEnabled()
    page.rows["visual_fx"].check.setChecked(True)
    assert page.risky.isVisibleTo(page)
    assert not page.apply_button.isEnabled()
    page.risky.setChecked(True)
    assert page.apply_button.isEnabled()
    page.rows["visual_fx"].check.setChecked(False)
    assert not page.risky.isVisibleTo(page)


def test_megatweaker_applies_only_what_is_ticked_and_resets_one_or_all(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(qtbot, window, "mega", "A ler")
    page = window.modules["mega"]
    assert isinstance(page, MegaPage)
    ops = page.ops()
    assert isinstance(ops, FakeOps)
    safe_user = [t for t in MEGA_TWEAKS if t.danger is Danger.SEGURO and not t.needs_admin]
    page.apply_button.click()
    qtbot.waitUntil(lambda: bool(page.results), timeout=10_000)
    page.wait()
    done = [r for r in page.results if r.result is ActionResult.APLICADO]
    # The fake machine is not elevated, so the safe settings that need administrator stay out.
    assert len(done) == len(safe_user)
    assert len(ops.settings) == len(safe_user)
    assert "restore_point" in ops.calls
    page.undo_button.click()
    page.wait()
    qtbot.waitUntil(lambda: ops.settings == {}, timeout=10_000)
