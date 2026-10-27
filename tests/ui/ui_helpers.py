from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from PySide6.QtCore import QtMsgType, qInstallMessageHandler
from PySide6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from zerobirus.platform.fake import FakeInspector
from zerobirus.ui.app import apply_theme
from zerobirus.ui.main_window import MainWindow


@contextmanager
def qt_warnings() -> Generator[list[str]]:
    """Collect the Qt warnings raised inside the block (bad style sheets, bad properties...)."""
    messages: list[str] = []

    def handler(kind: QtMsgType, _context: object, message: str) -> None:
        if kind in (QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
            messages.append(message)

    previous = qInstallMessageHandler(handler)
    try:
        yield messages
    finally:
        qInstallMessageHandler(previous)


def make_window(
    qtbot: QtBot,
    tmp_path: Path,
    fixture: str = "miner_pc",
    *,
    size: tuple[int, int] = (1100, 700),
    animations: bool = True,
) -> MainWindow:
    app = QApplication.instance()
    if isinstance(app, QApplication):
        apply_theme(app, high_contrast=False)
    window = MainWindow(
        FakeInspector(fixture),
        demo=True,
        data_dir=tmp_path / "data",
        desktop_dir=tmp_path / "Desktop",
        animations=animations,
    )
    qtbot.addWidget(window)
    window.resize(*size)
    window.show()
    qtbot.waitExposed(window)
    return window


def run_scan(qtbot: QtBot, window: MainWindow) -> None:
    window.context_page.next_button.click()
    window.scan_page.start_button.click()
    qtbot.waitUntil(lambda: window.result is not None, timeout=30_000)
    window.scan_page.wait()
