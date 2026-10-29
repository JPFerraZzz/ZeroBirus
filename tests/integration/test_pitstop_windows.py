"""BigDiag and winget on windows-latest. Read only: nothing is installed or changed."""

import importlib
from typing import Any

import pytest

from zerobirus.core.bigdiag import STATUS_WORD, build_report

pytestmark = pytest.mark.windows


def test_bigdiag_reads_the_real_machine_and_builds_every_section() -> None:
    windows: Any = importlib.import_module("zerobirus.platform.windows")
    raw = windows.create_diag_probe().read()
    memory = windows.create_memory_probe().snapshot()
    report = build_report(raw, memory=memory, defender=None, generated_at="test")
    titles = [s.title for s in report.sections]
    assert titles[0] == "Sistema"
    assert len(titles) == 9
    print(ascii({s.title: STATUS_WORD[s.status.value] for s in report.sections}))
    # A runner always has an OS, a CPU and a disk to read.
    assert "os" in raw
    assert raw.get("cpu")
    assert raw.get("disks")


def test_winget_lists_without_installing_anything() -> None:
    windows: Any = importlib.import_module("zerobirus.platform.windows")
    updater = windows.create_package_updater()
    try:
        found = updater.list_upgrades()
    except RuntimeError as exc:
        pytest.skip(f"winget is not available on this runner: {exc}")
    print(ascii([u.id for u in found]))
    assert isinstance(found, tuple)


def test_the_driver_reading_works_and_never_installs_anything() -> None:
    windows: Any = importlib.import_module("zerobirus.platform.windows")
    raw = windows.create_driver_probe().read()
    print(ascii({k: (len(v) if isinstance(v, list) else v) for k, v in raw.items()}))
    assert raw.get("installed")  # a runner has display and network drivers
