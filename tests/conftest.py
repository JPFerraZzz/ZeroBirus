import os
import sys
from collections.abc import Iterator

import pytest
from hypothesis import settings

# The interface tests run without a screen (BRIEF section 2, layer 3).
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# "ci" is the default. "deep" is for occasional local audits:
#   HYPOTHESIS_PROFILE=deep uv run pytest tests/unit
settings.register_profile("ci", max_examples=300, deadline=None)
settings.register_profile("deep", max_examples=5000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if sys.platform == "win32":
        return
    skip = pytest.mark.skip(reason="windows marker: only runs on real Windows (CI windows-latest)")
    for item in items:
        if "windows" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def finish_background_threads() -> Iterator[None]:
    """A QThread destroyed while it still runs aborts the whole process. After every test,
    let each interface window's worker threads finish before the window is torn down."""
    yield
    if "PySide6.QtWidgets" not in sys.modules:
        return
    from PySide6.QtWidgets import QApplication

    from zerobirus.ui.main_window import MainWindow

    if not isinstance(QApplication.instance(), QApplication):
        return
    for widget in QApplication.topLevelWidgets():
        if isinstance(widget, MainWindow):
            widget.scan_page.cancel()
            widget.wait_all()
