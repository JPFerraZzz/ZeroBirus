"""Modo Jogo settings and RAM Lover through the engine, against the fake machine."""

import dataclasses
from datetime import datetime
from pathlib import Path

import pytest
from ctx_factory import typical_context

from zerobirus.core.models import ActionResult, Level, Signature, SignatureStatus
from zerobirus.core.plan import ActionType, AuthorizedPlan, Plan, PlanItem, authorize, item_id
from zerobirus.core.ram import (
    MEGA,
    MemoryProcess,
    MemorySnapshot,
    Pressure,
    closable,
    close_item,
    diagnose,
    pressure_of,
    signers_of,
)
from zerobirus.core.safety import SignerKind, normalize_windows_path
from zerobirus.core.session import Session, create_session
from zerobirus.core.tweaks import CATALOG, FPS_TWEAKS, HIGH_PERFORMANCE_PLAN, tweak_item
from zerobirus.platform.fake.memory import FakeMemoryProbe
from zerobirus.platform.fake.ops import FakeOps
from zerobirus.remediation.engine import Remediation

CTX = typical_context()
HAGS = (
    "HKLM",
    r"system\currentcontrolset\control\graphicsdrivers",
    "hwschmode",
)
GAME_MODE = ("HKCU", r"software\microsoft\gamebar", "autogamemodeenabled")


@pytest.fixture
def session(tmp_path: Path) -> Session:
    return create_session(tmp_path, datetime(2026, 1, 1, 12, 0, 0), tool_version="t", elevated=True)


def authorise(*items: PlanItem) -> AuthorizedPlan:
    return authorize(
        Plan(tuple(items), ()),
        [i.id for i in items],
        session_id="s",
        authorised_at="now",
        extra_confirmation_count=len(items),
    )


def test_catalog_has_unique_ids_and_never_touches_security() -> None:
    assert len({t.id for t in FPS_TWEAKS}) == len(FPS_TWEAKS)
    forbidden = ("defender", "firewall", "windows update", "antivirus", "wuauserv", "sense")
    for t in FPS_TWEAKS:
        text = (t.title + " " + " ".join(v for _k, v in t.params)).lower()
        assert not any(f in text for f in forbidden), t.id
        assert t.params
        assert dict(t.params)["tweak"] == t.id


def test_apply_then_undo_every_tweak(session: Session) -> None:
    ops = FakeOps()
    ops.settings[HAGS] = 1  # supported, currently off
    items = [tweak_item(t) for t in FPS_TWEAKS]
    eng = Remediation(ops, CTX, session)
    outcome = eng.run(authorise(*items))
    assert [r.result for r in outcome.results] == [ActionResult.APLICADO] * len(items)
    assert ops.settings[GAME_MODE] == 1
    assert ops.settings[HAGS] == 2
    assert ops.power_plan == HIGH_PERFORMANCE_PLAN
    for r in outcome.results:
        assert eng.undo_item(r.item_id).ok
    assert GAME_MODE not in ops.settings  # it did not exist before: it is removed again
    assert ops.settings[HAGS] == 1
    assert ops.power_plan == "381b4222-f694-41f0-9685-ff5bb260df2e"


def test_a_setting_that_does_not_exist_here_is_not_touched(session: Session) -> None:
    ops = FakeOps()  # no HwSchMode: the PC does not expose hardware scheduling
    item = tweak_item(CATALOG["hags"])
    outcome = Remediation(ops, CTX, session).run(authorise(item))
    assert outcome.results[0].result is ActionResult.FALHOU
    assert HAGS not in ops.settings


def test_a_change_that_does_not_stick_is_not_reported_as_done(session: Session) -> None:
    ops = FakeOps(unverifiable={"1"})
    outcome = Remediation(ops, CTX, session).run(authorise(tweak_item(CATALOG["game_mode"])))
    assert outcome.results[0].result is ActionResult.FALHOU


def test_an_item_outside_the_catalog_is_refused(session: Session) -> None:
    evil = (
        ("data", "0"),
        ("key", r"SOFTWARE\Policies\Microsoft\Windows Defender"),
        ("root", "HKLM"),
        ("tweak", "game_mode"),
        ("type", "dword"),
        ("value", "DisableAntiSpyware"),
    )
    item = PlanItem(
        id=item_id(ActionType.SET_REGISTRY_VALUE, evil),
        action=ActionType.SET_REGISTRY_VALUE,
        target="x",
        params=evil,
        level=Level.OK,
        why="",
        finding_id="f",
        default_selected=True,
    )
    ops = FakeOps()
    outcome = Remediation(ops, CTX, session).run(authorise(item))
    assert outcome.results[0].result is ActionResult.IGNORADO
    assert ops.settings == {}


def test_an_unknown_power_plan_is_refused(session: Session) -> None:
    good = tweak_item(CATALOG["power_high"])
    params = tuple(
        ("plan", "00000000-0000-0000-0000-000000000000") if k == "plan" else (k, v)
        for k, v in good.params
    )
    item = dataclasses.replace(good, params=params, id=item_id(good.action, params))
    ops = FakeOps()
    outcome = Remediation(ops, CTX, session).run(authorise(item))
    assert outcome.results[0].result is ActionResult.IGNORADO
    assert ops.power_plan != "00000000-0000-0000-0000-000000000000"


def test_a_tampered_undo_record_is_not_acted_on(session: Session) -> None:
    ops = FakeOps()
    eng = Remediation(ops, CTX, session)
    item = tweak_item(CATALOG["game_mode"])
    eng.run(authorise(item))
    path = session.undo_dir / f"{item.id}.json"
    text = path.read_text("utf-8").replace("AutoGameModeEnabled", "DisableAntiSpyware")
    path.write_text(text, "utf-8")
    undone = eng.undo_item(item.id)
    assert not undone.ok  # the record no longer matches its id
    assert ops.settings[GAME_MODE] == 1


def test_tweaks_run_after_everything_else_in_the_plan(session: Session) -> None:
    ops = FakeOps()
    ops.processes[4101] = r"C:\Program Files\Google\Chrome\chrome.exe"
    proc = close_item(
        MemoryProcess(4101, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe", 900 * MEGA)
    )
    game = tweak_item(CATALOG["game_mode"])
    outcome = Remediation(ops, CTX, session).run(authorise(game, proc))
    assert [r.action for r in outcome.results] == [
        ActionType.KILL_PROCESS,
        ActionType.SET_REGISTRY_VALUE,
    ]


# RAM Lover ------------------------------------------------------------------------------


def test_pressure_bands() -> None:
    assert pressure_of(59) is Pressure.BAIXA
    assert pressure_of(60) is Pressure.MEDIA
    assert pressure_of(85) is Pressure.ALTA


def test_diagnosis_reads_the_numbers_and_ranks_the_biggest() -> None:
    snap = FakeMemoryProbe().snapshot()
    report = diagnose(snap)
    assert report.percent == 81
    assert report.pressure is Pressure.MEDIA
    assert report.top[0].name == "chrome.exe"
    assert [p.rss for p in report.top] == sorted((p.rss for p in report.top), reverse=True)


CHROME = r"C:\Program Files\Google\Chrome\chrome.exe"


def test_a_program_under_program_files_is_offered_only_with_a_checked_signer() -> None:
    snap = FakeMemoryProbe().snapshot()
    unknown = [p.name for p in closable(snap, CTX, {})]
    assert "chrome.exe" not in unknown  # unknown signer fails closed
    assert {"Discord.exe", "Spotify.exe"} <= set(unknown)
    other = {normalize_windows_path(CHROME): SignerKind.OTHER}
    assert "chrome.exe" in [p.name for p in closable(snap, CTX, other)]


def test_an_antivirus_or_windows_program_is_never_offered() -> None:
    snap = FakeMemoryProbe().snapshot()
    av = r"C:\Program Files\Kaspersky Lab\avp.exe"
    big = (*snap.processes, MemoryProcess(77, "avp.exe", av, 800 * MEGA))
    snap = MemorySnapshot(snap.total, snap.available, big)
    signers = {
        normalize_windows_path(av): SignerKind.ANTIVIRUS_VENDOR,
        normalize_windows_path(CHROME): SignerKind.OTHER,
    }
    names = [p.name for p in closable(snap, CTX, signers)]
    assert "avp.exe" not in names
    assert "svchost.exe" not in names  # protected Windows process
    assert "System" not in names  # no image file


def test_signers_ignore_signatures_that_were_not_checked() -> None:
    sigs = [
        Signature(CHROME, SignatureStatus.UNKNOWN, SignerKind.OTHER),
        Signature(r"C:\x.exe", SignatureStatus.VALID, SignerKind.MICROSOFT),
    ]
    assert signers_of(sigs) == {normalize_windows_path(r"C:\x.exe"): SignerKind.MICROSOFT}


def test_the_tool_itself_is_never_offered() -> None:
    mine = MemoryProcess(999, "python.exe", r"C:\Users\Ana\AppData\Local\zb\python.exe", 500 * MEGA)
    ctx = typical_context(own_pids=frozenset({999}))
    assert closable(MemorySnapshot(MEGA * 1000, MEGA * 500, (mine,)), ctx, {}) == ()


def test_closing_a_program_whose_pid_was_reused_is_refused(session: Session) -> None:
    ops = FakeOps()
    ops.processes[4101] = r"C:\Windows\System32\something.exe"  # another program now has the pid
    item = close_item(
        MemoryProcess(4101, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe", 900 * MEGA)
    )
    outcome = Remediation(ops, CTX, session).run(authorise(item))
    assert outcome.results[0].result is ActionResult.IGNORADO
    assert 4101 in ops.processes
