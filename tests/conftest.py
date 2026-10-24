import sys

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if sys.platform == "win32":
        return
    skip = pytest.mark.skip(reason="windows marker: only runs on real Windows (CI windows-latest)")
    for item in items:
        if "windows" in item.keywords:
            item.add_marker(skip)
