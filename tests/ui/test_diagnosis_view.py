"""The diagnosis table, its detail panel, the glyphs, and the small-window layout."""

from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot
from ui_helpers import make_window, qt_warnings, run_scan

from zerobirus.core.models import Level
from zerobirus.platform.fake import FakeInspector
from zerobirus.ui.app import apply_theme
from zerobirus.ui.main_window import MainWindow
from zerobirus.ui.models import LEVEL_COLUMN
from zerobirus.ui.theme import level_style
from zerobirus.ui.widgets import paint_level_glyph


def open_diagnosis(qtbot: QtBot, tmp_path: Path, fixture: str = "miner_pc") -> MainWindow:
    window = make_window(qtbot, tmp_path, fixture)
    run_scan(qtbot, window)
    window.go("diagnosis")
    return window


def test_the_table_lists_every_non_ok_finding_worst_first(qtbot: QtBot, tmp_path: Path) -> None:
    window = open_diagnosis(qtbot, tmp_path)
    page = window.diagnosis_page
    assert page.diagnosis is not None
    assert page.proxy.rowCount() == len(page.diagnosis.rows) > 0
    levels = page.row_levels()
    assert levels[0] is Level.SUSPEITO
    assert Level.OK not in levels
    words = [page.proxy.index(r, LEVEL_COLUMN).data() for r in range(page.proxy.rowCount())]
    assert set(words) <= {"SUSPEITO", "CONFERIR", "NÃO VERIFICADO"}
    headers = [page.proxy.headerData(c, Qt.Orientation.Horizontal) for c in range(4)]
    assert headers == ["Item", "Onde está", "Nível", "O que é"]
    window.scan_page.wait()


def test_the_selected_row_opens_plain_language_first_and_technical_detail_on_request(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = open_diagnosis(qtbot, tmp_path)
    page = window.diagnosis_page
    miner = next(
        r
        for r in range(page.proxy.rowCount())
        if page.proxy.index(r, 0).data() == "svchost32.exe (PID 5120)"
    )
    page.table.selectRow(miner)
    detail = page.detail
    assert detail.title.text() == "svchost32.exe (PID 5120)"
    assert not detail.tech.isVisible()
    assert "marcas típicas de mineração" in detail.why.text()
    QTest.keyClick(page, Qt.Key.Key_T)
    assert detail.tech.isVisible()
    text = detail.tech.text()
    assert "pool.exemplo:3333" in text
    assert "s3cr3t" not in text
    assert "pass@" not in text
    assert "[oculto]" in text
    assert "cmdline_miner_marker" in text
    QTest.keyClick(page, Qt.Key.Key_T)
    assert not detail.tech.isVisible()
    window.scan_page.wait()


def test_the_other_tabs_explain_threats_normal_things_and_what_was_not_verified(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = open_diagnosis(qtbot, tmp_path)
    page = window.diagnosis_page
    assert "Minerador de criptomoeda" in page.threat_view.text()
    assert "Ameaça não classificada" in page.threat_view.text()
    assert "não distingue" in page.threat_view.text().lower()
    assert "Por onde pode ter entrado" in page.threat_view.text()
    assert "svchost.exe" in page.normal_view.text()
    window.scan_page.wait()
    quiet = make_window(qtbot, tmp_path / "q", "no_admin_pc")
    run_scan(qtbot, quiet)
    quiet.go("diagnosis")
    nv = quiet.diagnosis_page.not_verified_view.text()
    assert "Microsoft Defender" in nv
    assert "sem administrador" in nv.lower()
    assert "NÃO VERIFICADO" in quiet.diagnosis_page.summary.text()
    quiet.scan_page.wait()


def test_a_clean_machine_says_there_is_nothing_to_remove(qtbot: QtBot, tmp_path: Path) -> None:
    window = open_diagnosis(qtbot, tmp_path, "clean_pc")
    page = window.diagnosis_page
    assert page.proxy.rowCount() == 0
    assert "Não encontrei nada" in page.summary.text()
    page.next_button.click()
    assert not window.authorize_page.selected_items()
    assert not window.authorize_page.remove_button.isEnabled()
    window.scan_page.wait()


def paint(level: Level) -> QImage:
    img = QImage(24, 24, QImage.Format.Format_ARGB32)
    img.fill(QColor("#F5F2EA"))
    painter = QPainter(img)
    paint_level_glyph(painter, QRectF(4, 4, 16, 16), level)
    painter.end()
    return img


def test_each_level_glyph_has_its_own_shape_and_uses_its_own_colour() -> None:
    images = {lv: paint(lv) for lv in Level}
    assert len({bytes(im.constBits()) for im in images.values()}) == 4
    for lv, im in images.items():
        want = QColor(level_style(lv).color)
        seen = {im.pixelColor(x, y).name() for x in range(24) for y in range(24)}
        close = [
            c
            for c in seen
            if abs(QColor(c).red() - want.red())
            + abs(QColor(c).green() - want.green())
            + abs(QColor(c).blue() - want.blue())
            < 40
        ]
        assert close, f"no pixel near {want.name()} for {lv}"


def test_a_1280x720_screen_at_150_percent_is_usable_with_keyboard_reach(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = make_window(qtbot, tmp_path, size=(853, 480))
    run_scan(qtbot, window)
    window.go("diagnosis")
    qtbot.wait(100)
    assert window.rail.item(0).text() == "1"  # the rail shows only numbers when narrow
    page = window.diagnosis_page
    frame = window.rect()
    for widget in (page.table, page.tabs, page.next_button):
        top_left = widget.mapTo(window, widget.rect().topLeft())
        bottom_right = widget.mapTo(window, widget.rect().bottomRight())
        assert frame.contains(top_left), widget
        assert frame.contains(bottom_right), widget
    assert page.table.height() >= 100
    window.go("context")
    qtbot.wait(50)
    assert window.context_page.next_button.isVisible()
    window.scan_page.wait()


def test_building_and_showing_every_page_raises_no_qt_warning(qtbot: QtBot, tmp_path: Path) -> None:
    with qt_warnings() as messages:
        window = make_window(qtbot, tmp_path)
        run_scan(qtbot, window)
        window.go("diagnosis")
        window.diagnosis_page.next_button.click()
        for key in ("context", "verify", "diagnosis", "authorize", "removal"):
            window.go(key)
            qtbot.wait(20)
        window.scan_page.wait()
    assert messages == []


def test_high_contrast_drops_our_style_and_uses_the_system_palette(qapp: QApplication) -> None:
    try:
        apply_theme(qapp, high_contrast=True)
        assert qapp.styleSheet() == ""
    finally:
        apply_theme(qapp, high_contrast=False)
    assert "QPushButton" in qapp.styleSheet()


def test_without_animations_the_scan_shows_text_and_nothing_spins(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = make_window(qtbot, tmp_path, animations=False)
    window.context_page.next_button.click()
    window.scan_page.start_button.click()
    assert window.scan_page.status.text() in {
        "A trabalhar...",
        "Verificação concluída. Nada foi alterado.",
    }
    qtbot.waitUntil(lambda: window.result is not None, timeout=30_000)
    window.scan_page.wait()


class SlowInspector(FakeInspector):
    def processes(self):  # type: ignore[no-untyped-def]
        import time

        time.sleep(2)
        return super().processes()


def test_cancelling_a_scan_stops_it_and_changes_nothing(qtbot: QtBot, tmp_path: Path) -> None:
    window = MainWindow(
        SlowInspector("miner_pc"), demo=True, data_dir=tmp_path / "d", desktop_dir=tmp_path / "x"
    )
    qtbot.addWidget(window)
    window.show()
    window.context_page.next_button.click()
    window.scan_page.start_button.click()
    qtbot.wait(100)
    assert window.scan_page.cancel_button.isEnabled()
    window.scan_page.cancel_button.click()
    qtbot.waitUntil(lambda: "cancelada" in window.scan_page.status.text(), timeout=10_000)
    assert window.result is None
    assert window.unlocked_stage() == "verify"
    assert window.scan_page.start_button.isEnabled()
    assert not (tmp_path / "x").exists()


def test_without_administrator_the_context_page_explains_and_offers_the_restart(
    qtbot: QtBot, tmp_path: Path
) -> None:
    window = make_window(qtbot, tmp_path, "no_admin_pc")
    page = window.context_page
    assert "não está a correr como administrador" in page.admin_label.text()
    assert page.restart.isVisible()
    assert not page.restart.isEnabled()  # demo mode never relaunches anything
    elevated = make_window(qtbot, tmp_path / "e", "miner_pc")
    assert not elevated.context_page.restart.isVisible()
