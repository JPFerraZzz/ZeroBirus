import os
import sys

import pytest
from hypothesis import settings

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
