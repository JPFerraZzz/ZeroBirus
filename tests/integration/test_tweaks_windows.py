"""Modo Jogo settings on windows-latest: applied by the real backend, read back independently.

The registry is read here with ``winreg`` directly, not through the product code, so an
APLICADO has to match what Windows really holds. The runner is disposable, and every test
puts the old value back (through the engine's own undo, which is what is being proved).
"""

import importlib
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from zerobirus.core.models import ActionResult
from zerobirus.core.plan import Plan, authorize
from zerobirus.core.session import create_session
from zerobirus.core.tweaks import CATALOG, HIGH_PERFORMANCE_PLAN, tweak_item
from zerobirus.remediation.engine import Remediation, RestorePointFailed

pytestmark = pytest.mark.windows

SYSTEM32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"


def _read(key: str, value: str) -> int | None:
    winreg: Any = importlib.import_module("winreg")

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            data, _kind = winreg.QueryValueEx(k, value)
            return int(data)
    except FileNotFoundError:
        return None


def _active_plan() -> str:
    out = subprocess.run(  # noqa: S603 - absolute path, fixed arguments
        [str(SYSTEM32 / "powercfg.exe"), "/getactivescheme"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    return out.split(":", 1)[1].split()[0].lower()


@pytest.fixture
def engine(tmp_path: Path) -> Remediation:
    windows: Any = importlib.import_module("zerobirus.platform.windows")
    inspector = windows.create_inspector()
    session = create_session(
        tmp_path, datetime.now(), tool_version="test", elevated=inspector.is_elevated()
    )
    return Remediation(windows.create_remediation_ops(), inspector.system_context(), session)


def _run(engine: Remediation, *ids: str) -> Any:
    items = [tweak_item(CATALOG[i]) for i in ids]
    plan = authorize(
        Plan(tuple(items), ()),
        [i.id for i in items],
        session_id="t",
        authorised_at="now",
        extra_confirmation_count=len(items),
    )
    try:
        return engine.run(plan)
    except RestorePointFailed:
        return engine.run(plan, proceed_without_restore_point=True)


def test_game_mode_is_set_confirmed_and_undone(engine: Remediation) -> None:
    key = r"Software\Microsoft\GameBar"
    before = _read(key, "AutoGameModeEnabled")
    outcome = _run(engine, "game_mode")
    assert [r.result for r in outcome.results] == [ActionResult.APLICADO]
    assert _read(key, "AutoGameModeEnabled") == 1
    assert engine.undo_item(outcome.results[0].item_id).ok
    assert _read(key, "AutoGameModeEnabled") == before


def test_capture_settings_are_turned_off_and_undone(engine: Remediation) -> None:
    keys = [
        (r"System\GameConfigStore", "GameDVR_Enabled"),
        (r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled"),
    ]
    before = [_read(k, v) for k, v in keys]
    outcome = _run(engine, "gamebar_capture", "app_capture")
    assert all(r.result is ActionResult.APLICADO for r in outcome.results)
    assert [_read(k, v) for k, v in keys] == [0, 0]
    for r in outcome.results:
        assert engine.undo_item(r.item_id).ok
    assert [_read(k, v) for k, v in keys] == before


def test_the_high_performance_plan_is_set_and_the_old_one_comes_back(engine: Remediation) -> None:
    listing = subprocess.run(  # noqa: S603 - absolute path, fixed arguments
        [str(SYSTEM32 / "powercfg.exe"), "/list"], capture_output=True, text=True, timeout=30
    ).stdout.lower()
    if HIGH_PERFORMANCE_PLAN not in listing:
        pytest.skip("this machine has no High performance power plan (Modern Standby)")
    before = _active_plan()
    outcome = _run(engine, "power_high")
    assert [r.result for r in outcome.results] == [ActionResult.APLICADO]
    assert _active_plan() == HIGH_PERFORMANCE_PLAN
    assert engine.undo_item(outcome.results[0].item_id).ok
    assert _active_plan() == before
