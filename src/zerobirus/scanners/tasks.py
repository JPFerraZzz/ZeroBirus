"""Scheduled tasks. Every task is analysed, including those inside \\Microsoft."""

from __future__ import annotations

from zerobirus.core.heuristics import (
    extract_executable,
    location_kind,
    mentions_writable_env,
    paths_in_command,
    random_component,
    runs_a_shell,
)
from zerobirus.core.models import CheckResult, Finding, Level, Signal, Signature, TaskInfo
from zerobirus.core.rules import Rules, load_rules
from zerobirus.core.safety import SystemContext
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import (
    command_signals,
    finish,
    lookup,
    make_finding,
    merge_gaps,
    signature_map,
    signature_signals,
    under_any,
)

CHECK = "tasks"
FREQUENT_MINUTES = 5


def _in_microsoft_folder(task: TaskInfo) -> bool:
    return task.folder.strip("\\").lower().split("\\")[0] == "microsoft"


def judge(
    task: TaskInfo, ctx: SystemContext, rules: Rules, sigs: dict[str, Signature]
) -> Finding | None:
    signals: list[Signal] = []
    evidence: list[str] = []
    writable = False
    random_hit = False
    first_target: str | None = None
    for action in task.actions:
        command = f"{action.execute} {action.arguments}".strip()
        evidence.append(command)
        signals += command_signals(command, rules)
        target = extract_executable(action.execute) or extract_executable(command)
        first_target = first_target or target
        paths = paths_in_command(command)
        if any(location_kind(p, ctx) for p in paths) or mentions_writable_env(command):
            writable = True
        if any(random_component(p, ctx) for p in paths):
            random_hit = True
        if runs_a_shell(command) and writable:
            signals.append(rules.signal("shell_command"))
        signals += signature_signals(lookup(sigs, target), rules)

    if writable:
        signals.append(
            rules.signal(
                "task_disguised_microsoft" if _in_microsoft_folder(task) else "task_from_writable"
            )
        )
        if random_hit:
            signals.append(rules.signal("random_folder"))
    if not _in_microsoft_folder(task):
        signals.append(rules.signal("task_outside_microsoft"))
    if task.repeat_minutes is not None and 0 < task.repeat_minutes <= FREQUENT_MINUTES:
        signals.append(rules.signal("task_frequent"))

    finding = make_finding(
        CHECK,
        f"{task.folder}\\{task.name}",
        item=task.name,
        location=task.folder or "\\",
        rules=rules,
        signals=signals,
        evidence=evidence,
        path=first_target,
        subject=(("kind", "task"), ("folder", task.folder), ("name", task.name)),
        description="Tarefa agendada" + ("" if task.enabled else " (desativada)") + ".",
    )
    return finding if finding.level is not Level.OK else None


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    ctx = inspector.system_context()
    observed = inspector.scheduled_tasks()
    to_sign = [
        t
        for task in observed.items
        for a in task.actions
        if (t := extract_executable(a.execute))
        and not under_any(t, [ctx.system_root])
        and t[1:3] == ":\\"
    ]
    sigs, sig_gaps = signature_map(inspector, to_sign)
    findings = [f for t in observed.items if (f := judge(t, ctx, rules, sigs)) is not None]
    return finish(CHECK, findings, [*merge_gaps(observed), *sig_gaps], len(observed.items))
