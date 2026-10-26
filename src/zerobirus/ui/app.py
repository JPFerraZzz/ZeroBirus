"""Start the interface: the application object, the theme, the window."""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from zerobirus.platform.base import Inspector
from zerobirus.platform.loader import animations_enabled, high_contrast_active, relaunch_elevated
from zerobirus.ui.main_window import MainWindow
from zerobirus.ui.theme import TOKENS, stylesheet


def make_application(argv: Sequence[str] = ()) -> QApplication:
    app = QApplication.instance()
    if isinstance(app, QApplication):
        return app
    return QApplication(list(argv) or ["zerobirus"])


def apply_theme(app: QApplication, *, high_contrast: bool) -> None:
    """Our flat theme, unless Windows high contrast is on: then the system palette wins."""
    if high_contrast:
        app.setStyleSheet("")
        return
    app.setStyleSheet(stylesheet())
    font = QFont()
    font.setPointSizeF(TOKENS.font_body_pt)
    app.setFont(font)


def default_data_dir(inspector: Inspector, *, demo: bool) -> Path:
    """``%ProgramData%\\ZeroBirus`` on the machine; a temporary folder for the demo."""
    if demo or sys.platform != "win32":
        return Path(tempfile.mkdtemp(prefix="zerobirus-"))
    return Path(inspector.system_context().program_data) / "ZeroBirus"


def default_desktop(inspector: Inspector, *, demo: bool) -> Path | None:
    if demo or sys.platform != "win32":
        return Path(tempfile.mkdtemp(prefix="zerobirus-desktop-"))
    folder = inspector.desktop_folder()
    return Path(folder) if folder else None


def build_window(inspector: Inspector, *, demo: bool) -> MainWindow:
    hc = high_contrast_active()
    app = make_application()
    apply_theme(app, high_contrast=hc)
    return MainWindow(
        inspector,
        demo=demo,
        data_dir=default_data_dir(inspector, demo=demo),
        desktop_dir=default_desktop(inspector, demo=demo),
        animations=animations_enabled(),
        relaunch=None if demo else relaunch_elevated,
    )


def run_gui(inspector: Inspector, *, demo: bool) -> int:
    app = make_application(sys.argv)
    window = build_window(inspector, demo=demo)
    window.resize(1100, 700)
    window.show()
    return int(app.exec())
