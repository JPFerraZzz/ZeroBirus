import pytest
from ctx_factory import typical_context

from zerobirus.core.models import CheckResult, Finding, Level
from zerobirus.core.plan import (
    IMPACT_LIMIT,
    ActionType,
    AuthorizedPlan,
    Plan,
    PlanItem,
    authorize,
    build_plan,
    digest,
    item_id,
    needs_extra_confirmation,
    render_plan_text,
)
from zerobirus.platform.fake import FakeInspector
from zerobirus.scanners.runner import run_scan

CTX = typical_context()
DROP = r"C:\Users\Ana\AppData\Roaming\kzqpx\svchost32.exe"


def miner_plan() -> Plan:
    result = run_scan(FakeInspector("miner_pc"))
    return build_plan(result.checks, result.snapshot.system, result.snapshot)


def by_action(plan: Plan, action: ActionType) -> list[PlanItem]:
    return [i for i in plan.items if i.action is action]


def test_the_miner_machine_gets_a_plan_with_every_kind_of_item() -> None:
    plan = miner_plan()
    kinds = {i.action for i in plan.items}
    assert kinds >= {
        ActionType.KILL_PROCESS,
        ActionType.REMOVE_TASK,
        ActionType.REMOVE_REGISTRY_VALUE,
        ActionType.REMOVE_WMI_BINDING,
        ActionType.QUARANTINE_FILE,
        ActionType.REMOVE_DEFENDER_EXCLUSION,
        ActionType.REMOVE_HOSTS_LINE,
        ActionType.ADD_FIREWALL_BLOCK,
    }
    assert [t for t, _ in plan.groups()][:3] == [
        "Processos",
        "Tarefas agendadas",
        "Valores de registo",
    ]


def test_suspeito_is_preselected_and_conferir_never_is() -> None:
    plan = miner_plan()
    for item in plan.items:
        if item.level is Level.CONFERIR:
            assert not item.default_selected, item
        if item.level is Level.SUSPEITO and item.action is not ActionType.ADD_FIREWALL_BLOCK:
            assert item.default_selected, item


def test_blocking_is_opt_in_even_for_a_suspect_connection() -> None:
    [block] = by_action(miner_plan(), ActionType.ADD_FIREWALL_BLOCK)
    assert block.level is Level.SUSPEITO
    assert not block.default_selected


def test_the_registry_value_is_identified_exactly() -> None:
    [reg] = by_action(miner_plan(), ActionType.REMOVE_REGISTRY_VALUE)
    assert (
        reg.param("root") == "HKU\\" + reg.param("root").split("\\", 1)[1]
        or reg.param("root") == "HKCU"
    )
    assert reg.param("value") == "WindowsUpdateHelper"
    assert reg.param("key").endswith(r"CurrentVersion\Run")
    assert reg.param("view") in ("64", "32")


def test_a_file_reached_by_several_findings_is_one_item() -> None:
    files = [
        i for i in by_action(miner_plan(), ActionType.QUARANTINE_FILE) if i.param("path") == DROP
    ]
    assert len(files) == 1


def test_ids_are_stable_and_unique() -> None:
    a, b = miner_plan(), miner_plan()
    assert [i.id for i in a.items] == [i.id for i in b.items]
    assert len({i.id for i in a.items}) == len(a.items)
    assert item_id(ActionType.REMOVE_TASK, [("name", "x"), ("folder", "\\")]) == item_id(
        ActionType.REMOVE_TASK, [("folder", "\\"), ("name", "x")]
    )


def finding(
    subject: dict[str, str], level: Level = Level.SUSPEITO, path: str | None = None
) -> CheckResult:
    f = Finding(
        id="f1",
        item="x",
        location="y",
        level=level,
        description="d",
        path=path,
        subject=tuple(subject.items()),
    )
    return CheckResult(check="c", findings=(f,))


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Users\Ana\Documents\a.docx",
        r"C:\Users\Ana",
        "C:\\",
        r"C:\Program Files\Windows Defender\MsMpEng.exe",
    ],
)
def test_a_protected_path_is_never_planned_and_is_explained(path: str) -> None:
    plan = build_plan([finding({"kind": "file", "path": path})], CTX)
    assert plan.items == ()
    assert plan.not_plannable
    assert plan.not_plannable[0].reason


def test_a_protected_process_is_never_planned() -> None:
    plan = build_plan([finding({"kind": "process", "pid": "4", "name": "System", "path": ""})], CTX)
    assert plan.items == ()
    assert "protegido" in plan.not_plannable[0].reason


def test_our_own_process_is_never_planned() -> None:
    ctx = typical_context(own_pids=frozenset({77}))
    plan = build_plan(
        [finding({"kind": "process", "pid": "77", "name": "a.exe", "path": DROP})], ctx
    )
    assert plan.items == ()


def test_winlogon_and_appinit_have_no_automatic_removal() -> None:
    for kind in ("winlogon", "appinit"):
        plan = build_plan(
            [
                finding(
                    {"kind": "autorun", "autorun_kind": kind, "name": "Shell", "source": "HKLM\\x"}
                )
            ],
            CTX,
        )
        assert plan.items == ()
        assert "não é removido automaticamente" in plan.not_plannable[0].reason


def test_an_unparsable_registry_source_is_refused_not_guessed() -> None:
    plan = build_plan(
        [
            finding(
                {"kind": "autorun", "autorun_kind": "run", "name": "x", "source": "something odd"}
            )
        ],
        CTX,
    )
    assert plan.items == ()


def test_ok_and_unverified_findings_never_become_actions() -> None:
    for level in (Level.OK, Level.NAO_VERIFICADO):
        assert build_plan([finding({"kind": "file", "path": DROP}, level)], CTX).items == ()


def test_a_service_in_a_protected_place_is_refused_and_a_third_party_one_is_planned() -> None:
    bad = build_plan(
        [finding({"kind": "service", "name": "X", "image": r"C:\Windows\System32\x.exe"})], CTX
    )
    assert bad.items == ()
    good = build_plan([finding({"kind": "service", "name": "Evil", "image": DROP})], CTX)
    assert {i.action for i in good.items} == {
        ActionType.DISABLE_SERVICE,
        ActionType.QUARANTINE_FILE,
    }


# The authorised plan ---------------------------------------------------------------------


def test_authorising_keeps_only_the_approved_items() -> None:
    plan = miner_plan()
    chosen = [i.id for i in plan.items if i.default_selected][:3]
    auth = authorize(plan, chosen, session_id="s", authorised_at="t")
    assert [i.id for i in auth.items] == chosen
    assert auth.verify()
    outside = next(i for i in plan.items if i.id not in chosen)
    assert not auth.contains(outside)
    assert not auth.contains_id(outside.id)
    assert auth.contains_id(chosen[0])


def test_authorising_nothing_or_an_unknown_id_is_an_error() -> None:
    plan = miner_plan()
    with pytest.raises(ValueError, match="nothing was approved"):
        authorize(plan, [], session_id="s", authorised_at="t")
    with pytest.raises(ValueError, match="not in the plan"):
        authorize(plan, ["i-forged"], session_id="s", authorised_at="t")


def test_an_authorised_plan_altered_afterwards_fails_verification() -> None:
    plan = miner_plan()
    auth = authorize(plan, [plan.items[0].id], session_id="s", authorised_at="t")
    extra = plan.items[1]
    forged = AuthorizedPlan(
        auth.session_id, auth.authorised_at, (*auth.items, extra), auth.plan_digest
    )
    assert not forged.verify()
    assert not forged.contains(extra)
    assert not forged.contains_id(extra.id)


def test_the_digest_ignores_order_but_not_content() -> None:
    items = list(miner_plan().items)
    assert digest(items) == digest(reversed(items))
    assert digest(items) != digest(items[1:])


def test_big_plans_and_folders_need_the_second_confirmation() -> None:
    plan = miner_plan()
    many = [
        PlanItem(
            id=f"i-{n}",
            action=ActionType.QUARANTINE_FILE,
            target=f"C:\\x{n}",
            params=(("path", f"C:\\x{n}"),),
            level=Level.SUSPEITO,
            why="w",
            finding_id="f",
            default_selected=True,
        )
        for n in range(IMPACT_LIMIT + 1)
    ]
    assert needs_extra_confirmation(many)
    assert not needs_extra_confirmation(many[:IMPACT_LIMIT])
    folder = PlanItem(
        id="i-f",
        action=ActionType.QUARANTINE_FOLDER,
        target="C:\\d",
        params=(("path", "C:\\d"),),
        level=Level.SUSPEITO,
        why="w",
        finding_id="f",
        default_selected=True,
    )
    assert needs_extra_confirmation([folder])
    big = Plan(tuple(many), ())
    with pytest.raises(ValueError, match="second confirmation"):
        authorize(big, [i.id for i in many], session_id="s", authorised_at="t")
    with pytest.raises(ValueError, match="second confirmation"):
        authorize(
            big, [i.id for i in many], session_id="s", authorised_at="t", extra_confirmation_count=3
        )
    ok = authorize(
        big,
        [i.id for i in many],
        session_id="s",
        authorised_at="t",
        extra_confirmation_count=len(many),
    )
    assert len(ok.items) == len(many)
    assert plan  # silence: the module-level plan is built once above


def test_the_plan_text_marks_what_was_authorised_and_says_nothing_changed_yet() -> None:
    plan = miner_plan()
    chosen = [i.id for i in plan.items if i.default_selected]
    text = render_plan_text(
        plan, chosen, session_id="s1", authorised_at="2026-10-26 10:00", version="9.9"
    )
    assert "Nada foi alterado ainda" in text
    assert "quarentena" in text
    assert "Sessão: s1" in text
    assert "[x] Terminar o processo svchost32.exe" in text
    assert sum(1 for ln in text.splitlines() if ln.startswith("  [x]")) == len(chosen)
    assert "[ ] " in text  # CONFERIR items stay unticked
    assert f"Itens autorizados: {len(chosen)} de {len(plan.items)}." in text
    assert "—" not in text


def test_a_run_value_seen_in_both_registry_views_is_one_item() -> None:
    src = r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run"
    both = CheckResult(
        check="startup",
        findings=tuple(
            Finding(
                id=f"f{view}",
                item="Evil",
                location="x",
                level=Level.SUSPEITO,
                description="d",
                subject=(
                    ("kind", "autorun"),
                    ("autorun_kind", "run"),
                    ("source", f"{src} ({view})"),
                    ("name", "Evil"),
                ),
            )
            for view in ("64", "32")
        ),
    )
    plan = build_plan([both], CTX)
    items = by_action(plan, ActionType.REMOVE_REGISTRY_VALUE)
    assert len(items) == 1
    assert items[0].param("view") == "64"
