"""Stage 4 engine against the in-memory fake machine (and a real folder for the file moves)."""

import dataclasses
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from ctx_factory import typical_context

from zerobirus.core.models import ActionResult, Level, TempEntry
from zerobirus.core.plan import (
    ActionType,
    AuthorizedPlan,
    Plan,
    PlanItem,
    authorize,
    build_plan,
    item_id,
)
from zerobirus.core.session import Session, create_session
from zerobirus.platform.fake import FakeInspector
from zerobirus.platform.fake.ops import FakeOps
from zerobirus.remediation.engine import (
    NotAuthorized,
    Remediation,
    RestorePointFailed,
)
from zerobirus.remediation.ops import LocalFileOps
from zerobirus.scanners.runner import run_scan

CTX = typical_context()
DROP = r"C:\Users\Ana\AppData\Roaming\kzqpx\svchost32.exe"
TEMP = r"C:\Users\Ana\AppData\Local\Temp"


@pytest.fixture
def session(tmp_path: Path) -> Session:
    return create_session(tmp_path, datetime(2026, 1, 1, 12, 0, 0), tool_version="t", elevated=True)


def make_item(action: ActionType, **params: str) -> PlanItem:
    pairs = tuple(sorted(params.items()))
    return PlanItem(
        id=item_id(action, pairs),
        action=action,
        target=next(iter(params.values()), ""),
        params=pairs,
        level=Level.SUSPEITO,
        why="x",
        finding_id="f",
        default_selected=True,
    )


def authorize_items(*items: PlanItem) -> AuthorizedPlan:
    plan = Plan(tuple(items), ())
    return authorize(
        plan,
        [i.id for i in items],
        session_id="s",
        authorised_at="now",
        extra_confirmation_count=len(items),
    )


def engine(ops: FakeOps, session: Session) -> Remediation:
    return Remediation(ops, CTX, session)


def miner_setup(session: Session, **kw: Any) -> tuple[FakeOps, AuthorizedPlan, Plan]:
    result = run_scan(FakeInspector("miner_pc"))
    temp = [TempEntry(TEMP + r"\cache.tmp", False, 5_000_000, 9)]
    plan = build_plan(result.checks, result.snapshot.system, result.snapshot, temp)
    ops = FakeOps.from_snapshot(result.snapshot, temp, **kw)
    auth = authorize(
        plan,
        [i.id for i in plan.items],
        session_id="s",
        authorised_at="now",
        extra_confirmation_count=len(plan.items),
    )
    return ops, auth, plan


# the whole flow ---------------------------------------------------------------------------


def test_the_miner_machine_is_cleaned_verified_and_fully_undone(session: Session) -> None:
    ops, auth, _plan = miner_setup(session)
    before = (
        dict(ops.registry),
        dict(ops.tasks),
        set(ops.wmi),
        set(ops.exclusions),
        list(ops.hosts),
        dict(ops.services),
        set(ops.files),
    )
    outcome = engine(ops, session).run(auth)
    assert outcome.restore_point == "criado"
    bad = [r for r in outcome.results if r.result is ActionResult.FALHOU]
    assert not bad, bad
    ok = (ActionResult.REMOVIDO, ActionResult.EM_QUARENTENA)
    assert sum(r.result in ok for r in outcome.results) >= 8
    assert not any(ops.processes.get(5120) for _ in [0])
    assert DROP.lower() not in ops.files
    assert not any(k[0].startswith("HKU") for k in ops.registry)
    assert not ops.wmi - {("SCM Event Log Filter", "SCM Event Log Consumer")}
    assert not ops.exclusions
    assert "0.0.0.0 www.virustotal.com" not in ops.hosts
    assert (session.folder / "results.json").is_file()

    undone = engine(ops, session).undo_session()
    assert all(u.ok for u in undone if "terminado" not in u.detail), undone
    after = (
        dict(ops.registry),
        dict(ops.tasks),
        set(ops.wmi),
        set(ops.exclusions),
        list(ops.hosts),
        dict(ops.services),
        set(ops.files),
    )
    assert after == before


def test_order_is_processes_then_persistence_then_files(session: Session) -> None:
    ops, auth, _ = miner_setup(session)
    engine(ops, session).run(auth)
    calls = ops.calls
    assert calls[0] == "restore_point"
    first_move = next(i for i, c in enumerate(calls) if c.startswith("move:"))
    last_kill = max(i for i, c in enumerate(calls) if c.startswith("kill:"))
    first_perform = next(i for i, c in enumerate(calls) if c.startswith("perform:"))
    assert last_kill < first_perform < first_move


# authorisation barrier -------------------------------------------------------------------


def test_an_item_outside_the_plan_is_refused_and_nothing_changes(session: Session) -> None:
    ops, auth, _ = miner_setup(session)
    forged = make_item(ActionType.QUARANTINE_FILE, path=r"C:\Users\Ana\Downloads\other.exe")
    ops.add_file(forged.param("path"))
    with pytest.raises(NotAuthorized):
        engine(ops, session).apply_item(auth, forged)
    assert not ops.calls
    assert ops.file_kind(forged.param("path")) == "file"


def test_a_plan_altered_after_authorisation_is_refused(session: Session) -> None:
    ops, auth, _ = miner_setup(session)
    extra = make_item(ActionType.QUARANTINE_FILE, path=r"C:\Users\Ana\Downloads\other.exe")
    tampered = dataclasses.replace(auth, items=(*auth.items, extra))
    with pytest.raises(NotAuthorized):
        engine(ops, session).run(tampered)
    assert not ops.calls


def test_an_item_whose_id_does_not_match_its_content_is_refused(session: Session) -> None:
    good = make_item(ActionType.QUARANTINE_FILE, path=r"C:\Users\Ana\Downloads\a.exe")
    lying = dataclasses.replace(good, params=(("path", r"C:\Users\Ana\Downloads\b.exe"),))
    auth = authorize_items(lying)
    ops = FakeOps()
    with pytest.raises(NotAuthorized):
        engine(ops, session).apply_item(auth, lying)


# safety re-checks (the plan itself is hostile here) --------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Users\Ana\Documents\a.docx",
        r"C:\Program Files\Windows Defender\MsMpEng.exe",
        r"C:\Users\Ana",
    ],
)
def test_a_protected_path_in_an_authorised_plan_is_still_refused(
    session: Session, path: str
) -> None:
    ops = FakeOps()
    ops.add_file(path)
    item = make_item(ActionType.QUARANTINE_FILE, path=path)
    result = engine(ops, session).run(authorize_items(item)).results[0]
    assert result.result is ActionResult.IGNORADO
    assert not any(c.startswith("move:") for c in ops.calls)
    assert ops.file_kind(path) == "file"


def test_a_link_or_a_path_through_a_link_is_not_followed(session: Session) -> None:
    ops = FakeOps()
    p1, p2 = r"C:\Users\Ana\Downloads\l", r"C:\Users\Ana\Downloads\j\x.exe"
    ops.add_link(p1)
    ops.add_file(p2)
    ops.aliased.add(p2.lower())
    for p in (p1, p2):
        item = make_item(ActionType.QUARANTINE_FILE, path=p)
        assert engine(ops, session).run(authorize_items(item)).results[0].result is (
            ActionResult.IGNORADO
        )


def test_a_folder_with_a_junction_inside_is_refused(session: Session) -> None:
    ops = FakeOps()
    path = r"C:\Users\Ana\AppData\Local\Temp\dir"
    ops.add_file(path, is_dir=True)
    ops.files[path.lower()].has_inner_link = True
    item = make_item(ActionType.CLEAN_TEMP_FOLDER, path=path)
    assert engine(ops, session).run(authorize_items(item)).results[0].result is (
        ActionResult.IGNORADO
    )


def test_a_reused_pid_and_a_protected_process_are_not_terminated(session: Session) -> None:
    ops = FakeOps()
    ops.processes[900] = r"C:\Users\Ana\AppData\Local\Other\other.exe"
    ops.processes[901] = r"C:\Windows\System32\lsass.exe"
    reused = make_item(ActionType.KILL_PROCESS, pid="900", name="x.exe", path=DROP)
    system = make_item(
        ActionType.KILL_PROCESS,
        pid="901",
        name="lsass.exe",
        path=r"C:\Windows\System32\lsass.exe",
    )
    out = engine(ops, session).run(authorize_items(reused, system)).results
    assert {r.result for r in out} == {ActionResult.IGNORADO}
    assert 900 in ops.processes
    assert 901 in ops.processes


def test_our_own_process_is_never_terminated(session: Session) -> None:
    ctx = typical_context(own_pids=frozenset({777}))
    ops = FakeOps()
    ops.processes[777] = DROP
    item = make_item(ActionType.KILL_PROCESS, pid="777", name="svchost32.exe", path=DROP)
    r = Remediation(ops, ctx, session).run(authorize_items(item)).results[0]
    assert r.result is ActionResult.IGNORADO
    assert 777 in ops.processes


@pytest.mark.parametrize(
    ("key", "value"),
    [
        (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
        (r"SYSTEM\CurrentControlSet\Services\Foo", "ImagePath"),
        (r"Software\Microsoft\Windows\CurrentVersion\Run\..\..", "x"),
    ],
)
def test_only_autorun_registry_keys_can_be_changed(session: Session, key: str, value: str) -> None:
    ops = FakeOps()
    ops.registry[("HKLM", key, value.lower())] = "v"
    item = make_item(ActionType.REMOVE_REGISTRY_VALUE, root="HKLM", key=key, value=value, view="64")
    assert engine(ops, session).run(authorize_items(item)).results[0].result is (
        ActionResult.IGNORADO
    )
    assert ops.registry


@pytest.mark.parametrize("address", ["10.0.0.1", "192.168.1.5", "127.0.0.1", "not-an-ip", ""])
def test_only_public_addresses_are_blocked(session: Session, address: str) -> None:
    ops = FakeOps()
    item = make_item(ActionType.ADD_FIREWALL_BLOCK, address=address)
    assert engine(ops, session).run(authorize_items(item)).results[0].result is (
        ActionResult.IGNORADO
    )
    assert not ops.firewall


@pytest.mark.parametrize("host", ["update.microsoft.com", "localhost", "bad host", "x"])
def test_names_that_must_never_be_blocked_are_refused(session: Session, host: str) -> None:
    ops = FakeOps()
    item = make_item(ActionType.ADD_HOSTS_BLOCK, host=host)
    assert engine(ops, session).run(authorize_items(item)).results[0].result is (
        ActionResult.IGNORADO
    )


def test_a_public_ip_and_a_normal_host_are_blocked_and_verified(session: Session) -> None:
    ops = FakeOps()
    a = make_item(ActionType.ADD_FIREWALL_BLOCK, address="93.184.216.34")
    h = make_item(ActionType.ADD_HOSTS_BLOCK, host="pool.exemplo.org")
    out = engine(ops, session).run(authorize_items(a, h)).results
    assert {r.result for r in out} == {ActionResult.REMOVIDO}
    assert "93.184.216.34" in ops.firewall
    assert any("pool.exemplo.org" in x and "# ZeroBirus" in x for x in ops.hosts)


def test_localhost_lines_in_hosts_are_never_removed(session: Session) -> None:
    ops = FakeOps(hosts=["127.0.0.1 localhost"])
    item = make_item(ActionType.REMOVE_HOSTS_LINE, line="127.0.0.1 localhost")
    assert engine(ops, session).run(authorize_items(item)).results[0].result is (
        ActionResult.IGNORADO
    )
    assert ops.hosts == ["127.0.0.1 localhost"]


# failures are reported, not hidden -------------------------------------------------------


def test_a_locked_file_fails_with_help_and_stays_in_place(session: Session) -> None:
    ops = FakeOps()
    path = r"C:\Users\Ana\Downloads\busy.exe"
    ops.add_file(path)
    ops.locked.add(path.lower())
    r = engine(ops, session).run(authorize_items(make_item(ActionType.QUARANTINE_FILE, path=path)))
    res = r.results[0]
    assert res.result is ActionResult.FALHOU
    assert "Modo de Segurança" in res.detail
    assert ops.file_kind(path) == "file"


def test_a_process_that_will_not_die_blocks_the_move_of_its_file(session: Session) -> None:
    ops = FakeOps(stubborn_pids={5})
    ops.processes[5] = DROP
    ops.add_file(DROP)
    kill = make_item(ActionType.KILL_PROCESS, pid="5", name="svchost32.exe", path=DROP)
    move = make_item(ActionType.QUARANTINE_FILE, path=DROP)
    out = {r.item_id: r for r in engine(ops, session).run(authorize_items(kill, move)).results}
    assert out[kill.id].result is ActionResult.FALHOU
    assert out[move.id].result is ActionResult.FALHOU
    assert ops.file_kind(DROP) == "file"


def test_a_change_the_machine_does_not_confirm_is_a_failure(session: Session) -> None:
    class Lying(FakeOps):
        def perform(self, item: PlanItem) -> None:  # claims success, changes nothing
            self.calls.append("perform")

    ops = Lying()
    ops.exclusions.add(("path", r"C:\x"))
    item = make_item(ActionType.REMOVE_DEFENDER_EXCLUSION, exclusion_kind="pasta", value=r"C:\x")
    res = engine(ops, session).run(authorize_items(item)).results[0]
    assert res.result is ActionResult.FALHOU


def test_if_undo_information_cannot_be_saved_nothing_is_changed(session: Session) -> None:
    ops = FakeOps()  # no such task: capture raises
    item = make_item(ActionType.REMOVE_TASK, folder="\\", name="Ghost")
    res = engine(ops, session).run(authorize_items(item)).results[0]
    assert res.result is ActionResult.FALHOU
    assert not any(c.startswith("perform") for c in ops.calls)


def test_restore_point_failure_stops_unless_the_person_confirms(session: Session) -> None:
    ops, auth, _ = miner_setup(session, restore_point_error="Proteção do sistema desativada")
    with pytest.raises(RestorePointFailed) as exc:
        engine(ops, session).run(auth)
    assert "desativada" in exc.value.reason
    assert not any(c.startswith(("move", "kill", "perform")) for c in ops.calls)
    out = engine(ops, session).run(auth, proceed_without_restore_point=True)
    assert out.restore_point.startswith("não criado")
    assert any(c.startswith("move") for c in ops.calls)


# undo ------------------------------------------------------------------------------------


def test_undo_never_overwrites_something_new_at_the_original_place(session: Session) -> None:
    ops = FakeOps()
    path = r"C:\Users\Ana\Downloads\a.exe"
    ops.add_file(path)
    item = make_item(ActionType.QUARANTINE_FILE, path=path)
    eng = engine(ops, session)
    assert eng.run(authorize_items(item)).results[0].result is ActionResult.EM_QUARENTENA
    ops.add_file(path, content="new")
    u = eng.undo_item(item.id)
    assert not u.ok
    assert ops.files[path.lower()].content == "new"


def test_undo_of_something_not_done_or_unknown_is_a_clear_no(session: Session) -> None:
    eng = engine(FakeOps(), session)
    assert not eng.undo_item("i-000000000000").ok
    assert not eng.undo_item("../../etc/passwd").ok


def test_delete_from_quarantine_only_after_quarantine_and_only_on_request(
    session: Session,
) -> None:
    ops = FakeOps()
    path = r"C:\Users\Ana\Downloads\a.exe"
    ops.add_file(path)
    item = make_item(ActionType.QUARANTINE_FILE, path=path)
    eng = engine(ops, session)
    assert not eng.delete_quarantined([item.id])[0].ok  # nothing quarantined yet
    eng.run(authorize_items(item))
    assert not any(c.startswith("delete:") for c in ops.calls)  # run never deletes
    assert eng.delete_quarantined([item.id])[0].ok
    assert not eng.undo_item(item.id).ok  # gone for good


# real file system ------------------------------------------------------------------------


class _FilesOnly(LocalFileOps):
    calls: list[str]

    def __init__(self) -> None:
        self.calls = []

    def create_restore_point(self, description: str) -> str | None:
        return None

    def process_image(self, pid: int) -> str | None:
        return None

    def terminate(self, pid: int) -> None: ...

    def capture(self, item: PlanItem) -> dict[str, Any]:
        return {}

    def perform(self, item: PlanItem) -> None: ...

    def verify(self, item: PlanItem) -> bool:
        return False

    def restore(self, item: PlanItem, saved: dict[str, Any]) -> None: ...


def real_engine(session: Session) -> Remediation:
    return Remediation(_FilesOnly(), CTX, session, is_protected=lambda p: False)


def test_real_file_is_quarantined_hashed_and_restored(tmp_path: Path, session: Session) -> None:
    f = tmp_path / "wörk" / "malware ñ.exe"
    f.parent.mkdir()
    f.write_bytes(b"MZ-synthetic")
    item = make_item(ActionType.QUARANTINE_FILE, path=str(f))
    eng = real_engine(session)
    res = eng.run(authorize_items(item)).results[0]
    assert res.result is ActionResult.EM_QUARENTENA
    assert not f.exists()
    quarantined = session.folder / "quarantine" / f"{item.id}.quar"
    assert quarantined.read_bytes() == b"MZ-synthetic"
    assert eng.undo_item(item.id).ok
    assert f.read_bytes() == b"MZ-synthetic"


def test_real_folder_is_moved_whole_and_a_symlink_inside_stops_it(
    tmp_path: Path, session: Session
) -> None:
    d = tmp_path / "junk"
    (d / "sub").mkdir(parents=True)
    (d / "sub" / "a.tmp").write_text("a")
    ok = make_item(ActionType.CLEAN_TEMP_FOLDER, path=str(d))
    eng = real_engine(session)
    assert eng.run(authorize_items(ok)).results[0].result is ActionResult.EM_QUARENTENA
    assert not d.exists()
    assert eng.undo_item(ok.id).ok
    assert (d / "sub" / "a.tmp").read_text() == "a"

    (d / "evil").symlink_to(tmp_path)
    again = eng.run(authorize_items(ok)).results[0]
    assert again.result is ActionResult.IGNORADO
    assert (d / "sub" / "a.tmp").exists()
    assert tmp_path.exists()


def test_real_symlink_to_a_file_is_not_followed(tmp_path: Path, session: Session) -> None:
    target = tmp_path / "keep.txt"
    target.write_text("keep")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    item = make_item(ActionType.QUARANTINE_FILE, path=str(link))
    res = real_engine(session).run(authorize_items(item)).results[0]
    assert res.result is ActionResult.IGNORADO
    assert target.read_text() == "keep"
    assert link.is_symlink()


# adversarial: the plan and the session folder are not trusted either ------------------------


@pytest.mark.parametrize(
    "root",
    [r"HKU\S-1-5-21-1-2-3-1001\..\..", r"HKU\.DEFAULT", r"HKCU", r"HKLM\..", ""],
)
def test_registry_roots_are_validated_strictly(session: Session, root: str) -> None:
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    ops = FakeOps()
    ops.registry[(root, key, "x")] = "v"
    item = make_item(ActionType.REMOVE_REGISTRY_VALUE, root=root, key=key, value="x", view="64")
    assert engine(ops, session).run(authorize_items(item)).results[0].result is (
        ActionResult.IGNORADO
    )


def test_antivirus_scheduled_tasks_are_never_removed(session: Session) -> None:
    ops = FakeOps()
    folder = "\\Microsoft\\Windows\\Windows Defender\\"
    ops.tasks[(folder, "Windows Defender Scheduled Scan")] = "<x/>"
    item = make_item(ActionType.REMOVE_TASK, folder=folder, name="Windows Defender Scheduled Scan")
    assert engine(ops, session).run(authorize_items(item)).results[0].result is (
        ActionResult.IGNORADO
    )
    assert ops.tasks


def test_our_own_pid_is_never_terminated_even_if_the_context_forgot_it(session: Session) -> None:
    import os

    ops = FakeOps()
    ops.processes[os.getpid()] = DROP
    item = make_item(ActionType.KILL_PROCESS, pid=str(os.getpid()), name="x.exe", path=DROP)
    assert engine(ops, session).run(authorize_items(item)).results[0].result is (
        ActionResult.IGNORADO
    )


def test_a_tampered_undo_record_cannot_move_arbitrary_files(session: Session) -> None:
    import json

    ops = FakeOps()
    path = r"C:\Users\Ana\Downloads\a.exe"
    ops.add_file(path)
    item = make_item(ActionType.QUARANTINE_FILE, path=path)
    eng = engine(ops, session)
    eng.run(authorize_items(item))
    record_path = session.undo_dir / f"{item.id}.json"
    record = json.loads(record_path.read_text("utf-8"))
    victim = r"C:\Users\Ana\Downloads\victim.exe"
    ops.add_file(victim)
    record["undo"]["quarantined_to"] = victim
    record["undo"]["original"] = r"C:\Users\Ana\AppData\Roaming\evil.exe"
    record_path.write_text(json.dumps(record), "utf-8")
    assert not eng.undo_item(item.id).ok
    assert ops.file_kind(victim) == "file"


def test_a_tampered_record_cannot_delete_outside_the_quarantine(session: Session) -> None:
    import json

    ops = FakeOps()
    path = r"C:\Users\Ana\Downloads\a.exe"
    ops.add_file(path)
    item = make_item(ActionType.QUARANTINE_FILE, path=path)
    eng = engine(ops, session)
    eng.run(authorize_items(item))
    record_path = session.undo_dir / f"{item.id}.json"
    record = json.loads(record_path.read_text("utf-8"))
    record["undo"]["quarantined_to"] = r"C:\Users\Ana\Documents\important.docx"
    record_path.write_text(json.dumps(record), "utf-8")
    assert not eng.delete_quarantined([item.id])[0].ok
    assert not any(c.startswith("delete:") for c in ops.calls)
