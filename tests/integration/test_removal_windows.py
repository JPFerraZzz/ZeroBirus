"""Stage 4 on windows-latest: the real backend removes marked, harmless artifacts and undoes it.

Only items that carry the test marker are ever authorised, so nothing else on the runner is
touched. The state is checked by ``tools/windows/check_state.ps1``, which does not use the
product code, so a verified REMOVIDO has to match what Windows really holds.
"""

import hashlib
import importlib
import json
import os
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from test_detection_windows import MARKER, powershell

from zerobirus.core.models import ActionResult, Level
from zerobirus.core.plan import (
    ActionType,
    Plan,
    PlanItem,
    authorize,
    build_plan,
    item_id,
    temp_items,
)
from zerobirus.core.session import create_session
from zerobirus.remediation.engine import (
    ItemResult,
    Outcome,
    Remediation,
    RestorePointFailed,
)
from zerobirus.scanners.runner import run_scan

pytestmark = pytest.mark.windows

HOSTS = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
HOSTS_MARK_LINE = "0.0.0.0 zerobirus-test.invalid"
FIREWALL_ADDRESS = "93.184.216.34"


def _state() -> dict[str, Any]:
    out = powershell("check_state.ps1").strip().splitlines()[-1]
    state: dict[str, Any] = json.loads(out)
    print(ascii(f"state: {state}"))
    return state


def _item(action: ActionType, target: str = "", **params: str) -> PlanItem:
    pairs = tuple(sorted(params.items()))
    return PlanItem(
        id=item_id(action, pairs),
        action=action,
        target=target or next(iter(params.values()), ""),
        params=pairs,
        level=Level.SUSPEITO,
        why="integration test",
        finding_id="test",
        default_selected=True,
    )


@pytest.fixture(scope="module")
def inspector() -> Any:
    return importlib.import_module("zerobirus.platform.windows").create_inspector()


@pytest.fixture
def engine(inspector: Any, tmp_path: Path) -> Remediation:
    ops = importlib.import_module("zerobirus.platform.windows").create_remediation_ops()
    session = create_session(tmp_path, datetime.now(), tool_version="test", elevated=True)
    return Remediation(ops, inspector.system_context(), session)


@pytest.fixture
def artifacts() -> Iterator[dict[str, Any]]:
    powershell("remove_test_artifacts.ps1")
    powershell("remove_removal_extras.ps1")
    created = json.loads(powershell("make_test_artifacts.ps1").strip().splitlines()[-1])
    extras = json.loads(powershell("make_removal_extras.ps1").strip().splitlines()[-1])
    print(ascii(f"artifacts: {created} extras: {extras}"))
    try:
        yield {**created, "extras": extras}
    finally:
        powershell("remove_removal_extras.ps1")
        powershell("remove_test_artifacts.ps1")


def run_plan(engine: Remediation, plan: Plan, ids: list[str]) -> Outcome:
    auth = authorize(
        plan,
        ids,
        session_id="itest",
        authorised_at=datetime.now().isoformat(timespec="seconds"),
        extra_confirmation_count=len(ids),
    )
    try:
        return engine.run(auth)
    except RestorePointFailed as exc:
        print(ascii(f"restore point not created on this runner: {exc.reason}"))
        return engine.run(auth, proceed_without_restore_point=True)


def by_action(outcome: Outcome, action: ActionType) -> list[ItemResult]:
    return [r for r in outcome.results if r.action is action]


def marked(item: PlanItem) -> bool:
    text = (item.target + "".join(v for _, v in item.params)).lower()
    return MARKER.lower() in text or "zbtest" in text


def test_the_detected_artifacts_are_removed_verified_independently_and_undone(
    artifacts: dict[str, Any], inspector: Any, engine: Remediation
) -> None:
    result = run_scan(inspector, timeout=180.0)
    plan = build_plan(result.checks, result.snapshot.system, result.snapshot)
    ours = [i for i in plan.items if marked(i)]
    kinds = {i.action for i in ours}
    assert {ActionType.KILL_PROCESS, ActionType.REMOVE_REGISTRY_VALUE}.issubset(kinds), ours
    before = _state()
    assert before["process"]
    assert before["run_value"]
    exe = Path(artifacts["exe"])
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()

    outcome = run_plan(engine, plan, [i.id for i in ours])
    for r in outcome.results:
        print(ascii(f"{r.action.value} {r.result.value}: {r.detail}"))
    assert not [r for r in outcome.results if r.result is ActionResult.FALHOU], outcome.results

    after = _state()  # independent of the product's own verification
    assert not after["process"]
    assert not after["run_value"]
    assert not after["exe"]
    if artifacts["task"]:
        assert not after["task"]
    if artifacts["exclusion"]:
        assert not after["exclusion"]
    quarantined = list((engine.session.folder / "quarantine").iterdir())
    assert quarantined
    assert any(
        p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() == digest for p in quarantined
    )

    undone = engine.undo_session()
    for u in undone:
        print(ascii(f"undo {u.item_id}: {u.ok} {u.detail}"))
    restored = _state()
    assert restored["run_value"] == before["run_value"]
    assert restored["exe"]
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == digest
    if artifacts["task"]:
        assert restored["task"]
    if artifacts["exclusion"]:
        assert restored["exclusion"]


def test_an_item_outside_the_authorised_plan_does_nothing_on_a_real_machine(
    artifacts: dict[str, Any], engine: Remediation
) -> None:
    exe = Path(artifacts["exe"])
    allowed = _item(ActionType.REMOVE_REGISTRY_VALUE, root="HKU\\S-1-5-21-1-2-3-1001", key="x")
    forged = _item(ActionType.QUARANTINE_FILE, path=str(exe))
    auth = authorize(Plan((allowed,), ()), [allowed.id], session_id="itest", authorised_at="now")
    with pytest.raises(Exception, match="plano autorizado"):
        engine.apply_item(auth, forged)
    assert exe.is_file()


def test_protected_paths_are_refused_even_when_the_plan_asks(engine: Remediation) -> None:
    target = Path(os.environ["SYSTEMROOT"]) / "System32" / "drivers" / "etc" / "hosts"
    bad = _item(ActionType.QUARANTINE_FILE, path=str(target))
    outcome = run_plan(engine, Plan((bad,), ()), [bad.id])
    assert outcome.results[0].result is ActionResult.IGNORADO
    assert target.is_file()


def test_wmi_subscription_is_removed_and_restored(
    artifacts: dict[str, Any], engine: Remediation
) -> None:
    if not artifacts["extras"]["wmi"]:
        pytest.skip(f"WMI artifact not created here: {artifacts['extras']['errors']}")
    item = _item(
        ActionType.REMOVE_WMI_BINDING,
        filter=MARKER + "Filter",
        consumer=MARKER + "Consumer",
        consumer_class="CommandLineEventConsumer",
    )
    assert _state()["wmi_binding"]
    outcome = run_plan(engine, Plan((item,), ()), [item.id])
    print(ascii(str(outcome.results)))
    assert outcome.results[0].result is ActionResult.REMOVIDO
    assert not _state()["wmi_binding"]
    assert engine.undo_item(item.id).ok
    assert _state()["wmi_binding"]


def test_service_is_disabled_and_restored(artifacts: dict[str, Any], engine: Remediation) -> None:
    if not artifacts["extras"]["service"]:
        pytest.skip(f"service not created here: {artifacts['extras']['errors']}")
    exe = artifacts["exe"]
    item = _item(ActionType.DISABLE_SERVICE, name=MARKER + "Svc", image=exe)
    outcome = run_plan(engine, Plan((item,), ()), [item.id])
    print(ascii(str(outcome.results)))
    assert outcome.results[0].result is ActionResult.REMOVIDO
    assert _state()["service_start"] == "Disabled"
    assert engine.undo_item(item.id).ok
    assert _state()["service_start"] == "Manual"


def test_hosts_line_is_removed_and_restored_and_a_block_is_added_and_undone(
    artifacts: dict[str, Any], engine: Remediation
) -> None:
    original = HOSTS.read_bytes()
    try:
        with HOSTS.open("ab") as fh:
            fh.write(b"\r\n" + HOSTS_MARK_LINE.encode() + b"\r\n")
        remove = _item(ActionType.REMOVE_HOSTS_LINE, line=HOSTS_MARK_LINE)
        outcome = run_plan(engine, Plan((remove,), ()), [remove.id])
        assert outcome.results[0].result is ActionResult.REMOVIDO
        assert not _state()["hosts_lines"]
        assert engine.undo_item(remove.id).ok
        assert HOSTS_MARK_LINE in _state()["hosts_lines"]

        HOSTS.write_bytes(original)
        block = _item(ActionType.ADD_HOSTS_BLOCK, host="zerobirus-test.invalid")
        outcome = run_plan(engine, Plan((block,), ()), [block.id])
        assert outcome.results[0].result is ActionResult.REMOVIDO
        assert any("# ZeroBirus" in line for line in _state()["hosts_lines"])
        assert engine.undo_item(block.id).ok
        assert not _state()["hosts_lines"]
    finally:
        HOSTS.write_bytes(original)


def test_firewall_block_is_added_verified_and_undone(engine: Remediation) -> None:
    item = _item(ActionType.ADD_FIREWALL_BLOCK, address=FIREWALL_ADDRESS)
    outcome = run_plan(engine, Plan((item,), ()), [item.id])
    print(ascii(str(outcome.results)))
    powershell("dump_firewall.ps1")  # diagnostics for the log
    assert outcome.results[0].result is ActionResult.REMOVIDO
    assert _state()["firewall_rules"] >= 1
    assert engine.undo_item(item.id).ok
    assert _state()["firewall_rules"] == 0


def test_old_temp_entries_are_listed_quarantined_and_restored(
    inspector: Any, engine: Remediation
) -> None:
    temp = Path(os.environ["TEMP"]).resolve()  # TEMP may use 8.3 short names
    folder = temp / (MARKER + "_tmp_dir")
    folder.mkdir(exist_ok=True)
    (folder / "a.tmp").write_bytes(b"temporary")
    old = datetime.now().timestamp() - 5 * 86400
    os.utime(folder / "a.tmp", (old, old))
    os.utime(folder, (old, old))
    try:
        listed = inspector.temp_entries().items
        mine = [e for e in listed if e.path.lower() == str(folder).lower()]
        assert mine, "the old test folder was not listed"
        items = [i for i in temp_items(mine, inspector.system_context())]
        assert [i.action for i in items] == [ActionType.CLEAN_TEMP_FOLDER]
        assert not items[0].default_selected
        outcome = run_plan(engine, Plan(tuple(items), ()), [items[0].id])
        print(ascii(str(outcome.results)))
        assert outcome.results[0].result is ActionResult.EM_QUARENTENA
        assert not folder.exists()
        assert engine.undo_item(items[0].id).ok
        assert (folder / "a.tmp").read_bytes() == b"temporary"
    finally:
        powershell("remove_removal_extras.ps1")


def test_after_the_removal_the_program_and_its_file_are_really_gone(
    artifacts: dict[str, Any], inspector: Any, engine: Remediation
) -> None:
    result = run_scan(inspector, timeout=180.0)
    plan = build_plan(result.checks, result.snapshot.system, result.snapshot)
    ours = [i for i in plan.items if marked(i)]
    outcome = run_plan(engine, plan, [i.id for i in ours])
    for r in outcome.results:
        print(ascii(f"{r.action.value} {r.result.value}: {r.detail}"))
    state = _state()
    assert not state["process"]
    assert not state["exe"]
    assert not state["run_value"]
    again = run_scan(inspector, timeout=180.0)
    names = [
        f.item + f.location
        for c in again.checks
        if c.check in ("processes", "startup", "files")
        for f in c.findings
    ]
    assert not any("zbtest" in n.lower() or MARKER.lower() in n.lower() for n in names), names
