"""BigDiag and AllUp on the fake machine (offscreen)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot
from ui_helpers import make_window

from zerobirus.platform.fake.winget import FakePackageUpdater
from zerobirus.ui import catalog
from zerobirus.ui.main_window import MainWindow
from zerobirus.ui.page_pitstop import AllUpPage, BigDiagPage


@pytest.fixture
def window(qtbot: QtBot, tmp_path: Path) -> Iterator[MainWindow]:
    w = make_window(qtbot, tmp_path, home=True)
    yield w
    w.wait_all()


def open_module(w: MainWindow, key: str) -> None:
    w.home_page.cards["pitstop"].click()
    w.hubs["pitstop"].cards[key].click()
    assert w.screens.currentWidget() is w.modules[key]


def test_the_pitstop_hub_opens_bigdiag_and_allup_and_the_rest_stay_skeletons(
    window: MainWindow,
) -> None:
    assert {"bigdiag", "allup"} <= catalog.MODULES_AVAILABLE
    window.home_page.cards["pitstop"].click()
    hub = window.hubs["pitstop"]
    for key in ("bigdiag", "allup"):
        hub.cards[key].click()
        window.modules[key].wait()
        window.modules[key].back_button.click()
        assert window.screens.currentWidget() is hub
    hub.cards["first"].click()
    assert window.screens.currentWidget() is hub
    assert "chega numa versão seguinte" in hub.note.text()


def test_bigdiag_reads_shows_every_section_and_saves_a_redacted_file(
    qtbot: QtBot, window: MainWindow, tmp_path: Path
) -> None:
    open_module(window, "bigdiag")
    page = window.modules["bigdiag"]
    assert isinstance(page, BigDiagPage)
    assert not page.save_button.isEnabled()
    page.run_button.click()
    qtbot.waitUntil(lambda: page.report is not None, timeout=10_000)
    page.wait()
    assert page.report is not None
    assert len(page.report.sections) == 9
    assert "Resumo" in page.status.text()
    assert page.save_button.isEnabled()
    page.save_button.click()
    assert page.saved_path is not None
    text = page.saved_path.read_text("utf-8-sig")
    assert "só de leitura" in text
    assert page.saved_path.parent == tmp_path / "Desktop"


def test_allup_lists_nothing_ticked_and_needs_the_acknowledgement(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(window, "allup")
    page = window.modules["allup"]
    assert isinstance(page, AllUpPage)
    page.wait()
    qtbot.waitUntil(lambda: bool(page.rows), timeout=10_000)
    assert not any(r.check.isChecked() for r in page.rows.values())
    assert not page.apply_button.isEnabled()
    page.all_button.click()
    assert all(r.check.isChecked() for r in page.rows.values())
    assert not page.apply_button.isEnabled()  # still needs the acknowledgement
    page.ack.setChecked(True)
    assert page.apply_button.isEnabled()


def test_allup_updates_the_ticked_ones_writes_the_plan_first_and_confirms_each(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(window, "allup")
    page = window.modules["allup"]
    assert isinstance(page, AllUpPage)
    page.wait()
    qtbot.waitUntil(lambda: bool(page.rows), timeout=10_000)
    updater = page.svc.updater_factory()
    assert isinstance(updater, FakePackageUpdater)
    page.rows["Demo.Browser"].check.setChecked(True)
    page.ack.setChecked(True)
    page.apply_button.click()
    qtbot.waitUntil(lambda: bool(page.results), timeout=10_000)
    page.wait()
    assert [r.confirmed for r in page.results] == [True]
    assert "1 de 1" in page.status.text()
    plan = next(window.data_dir.glob("Sessions/*/allup-plan.json"))
    assert "Demo.Browser" in plan.read_text("utf-8")
