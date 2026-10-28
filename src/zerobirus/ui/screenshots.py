"""Render the interface to PNG files, as the person sees it (BRIEF section 2, layer 3).

Used by the CI to produce the 100% and 150% screenshots for design review, and by the tests.
Run: ``zerobirus screenshots --out DIR [--scale 1.5] [--fixture miner_pc]``.

The window is sized to 1280x720 PHYSICAL pixels. At scale 1.5 that is about 853x480 logical
points, the case the design has to survive.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

PHYSICAL_SIZE = (1280, 720)
STAGES = ("context", "verify", "diagnosis", "authorize")


def capture(out_dir: Path, *, scale: float, fixture: str) -> list[Path]:
    """Write ``<fixture>-<scale>-<n>-<stage>.png`` files and return their paths."""
    # Must be set before the QApplication exists. Off Windows there is no screen to draw on, so
    # render offscreen. On Windows the native platform is used unless the caller chose one: the
    # offscreen plugin there finds no system fonts and draws empty boxes instead of text.
    if sys.platform != "win32":
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    os.environ["QT_SCALE_FACTOR"] = str(scale)
    from zerobirus.platform.fake import FakeInspector
    from zerobirus.ui.app import build_window, make_application

    app = make_application()
    window = build_window(FakeInspector(fixture), demo=True)
    window.resize(round(PHYSICAL_SIZE[0] / scale), round(PHYSICAL_SIZE[1] / scale))
    window.show()

    def pump(rounds: int = 25) -> None:
        for _ in range(rounds):
            app.processEvents()
            time.sleep(0.01)

    out_dir.mkdir(parents=True, exist_ok=True)
    label = f"{scale * 100:.0f}"
    written: list[Path] = []

    def shot(n: int, stage: str) -> None:
        pump()
        path = out_dir / f"{fixture}-{label}pct-{n}-{stage}.png"
        window.grab().save(str(path), "PNG")
        written.append(path)

    pump()
    shot(1, "home")
    window.show_flow()
    shot(2, "context")
    window.context_page.next_button.click()
    window.scan_page.start_button.click()
    window.scan_page.wait()
    pump(80)
    shot(3, "verify")
    window.go("diagnosis")
    shot(4, "diagnosis")
    window.diagnosis_page.tabs.setCurrentIndex(1)
    shot(5, "diagnosis-threat")
    window.diagnosis_page.next_button.click()
    shot(6, "authorize")
    window.authorize_page.open_all.click()
    window.authorize_page.scroller.verticalScrollBar().setValue(
        window.authorize_page.scroller.verticalScrollBar().maximum()
    )
    shot(7, "authorize-end")
    window.close()
    return written


def capture_in_temp(scale: float, fixture: str = "miner_pc") -> list[Path]:
    return capture(Path(tempfile.mkdtemp(prefix="zerobirus-shots-")), scale=scale, fixture=fixture)
