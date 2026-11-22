"""FirstSetup and AllDrivers on the fake machine (offscreen)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot
from ui_helpers import make_window

from zerobirus.core.drivers import OPTIONAL_UPDATES
from zerobirus.core.firstsetup import CATEGORIES, SCRIPT_NAME
from zerobirus.ui.main_window import MainWindow
from zerobirus.ui.page_pitstop import DriversPage, FirstSetupPage


@pytest.fixture
def window(qtbot: QtBot, tmp_path: Path) -> Iterator[MainWindow]:
    w = make_window(qtbot, tmp_path, home=True)
    yield w
    w.wait_all()


def open_module(w: MainWindow, key: str) -> None:
    w.home_page.cards["pitstop"].click()
    w.hubs["pitstop"].cards[key].click()
    assert w.screens.currentWidget() is w.modules[key]


def test_the_whole_pitstop_hub_is_built(window: MainWindow) -> None:
    window.home_page.cards["pitstop"].click()
    hub = window.hubs["pitstop"]
    assert all(card.property("role") == "card" for card in hub.cards.values())
    for key in ("first", "allup", "bigdiag", "drivers"):
        hub.cards[key].click()
        assert window.screens.currentWidget() is window.modules[key]
        window.modules[key].back_button.click()
        assert window.screens.currentWidget() is hub


def test_firstsetup_shows_the_ninite_categories_with_nothing_ticked(window: MainWindow) -> None:
    open_module(window, "first")
    page = window.modules["first"]
    assert isinstance(page, FirstSetupPage)
    assert list(page.groups) == list(CATEGORIES)
    assert not page.selected()
    assert not page.create_button.isEnabled()


def test_firstsetup_writes_the_installer_to_the_desktop_and_never_overwrites(
    window: MainWindow, tmp_path: Path
) -> None:
    open_module(window, "first")
    page = window.modules["first"]
    assert isinstance(page, FirstSetupPage)
    page.boxes["Mozilla.Firefox"].setChecked(True)
    page.boxes["VideoLAN.VLC"].setChecked(True)
    assert "2" in page.create_button.text()
    page.create_button.click()
    first = tmp_path / "Desktop" / SCRIPT_NAME
    assert page.saved_path == first
    text = first.read_bytes().decode("ascii")
    assert "Mozilla.Firefox" in text
    assert "VideoLAN.VLC" in text
    page.create_button.click()  # a second click must not replace the first file
    assert page.saved_path != first
    assert first.read_bytes().decode("ascii") == text


def test_alldrivers_lists_the_drivers_and_opens_only_the_pages_it_offers(
    qtbot: QtBot, window: MainWindow
) -> None:
    open_module(window, "drivers")
    page = window.modules["drivers"]
    assert isinstance(page, DriversPage)
    page.run_button.click()
    qtbot.waitUntil(lambda: bool(page.sections), timeout=10_000)
    page.wait()
    assert page.sections[0].title == "Drivers instalados"
    assert page.links  # the demo has an NVIDIA graphics card
    page.open_button.click()
    assert page.opened == [OPTIONAL_UPDATES]


def test_alldrivers_reports_a_refused_link_instead_of_opening_it(window: MainWindow) -> None:
    open_module(window, "drivers")
    page = window.modules["drivers"]
    assert isinstance(page, DriversPage)
    # The real opener (platform.windows.open_uri) refuses anything outside core.drivers.LINKS;
    # here the page must show that refusal instead of crashing.
    refused: list[str] = []

    class Refusing:
        def __call__(self, uri: str) -> None:
            refused.append(uri)
            raise ValueError("este endereço não é um dos permitidos")

    page.open_with(Refusing(), "https://evil.example/")
    assert refused == ["https://evil.example/"]
    assert "Não foi possível abrir" in page.status.text()
    assert page.opened == []
