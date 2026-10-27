"""Everything that starts with Windows: Run keys, Winlogon, AppInit, IFEO, Startup folders."""

from __future__ import annotations

from zerobirus.core.heuristics import (
    extract_executable,
    location_kind,
    mentions_writable_env,
    paths_in_command,
    random_component,
    runs_a_shell,
)
from zerobirus.core.models import (
    AutorunEntry,
    CheckResult,
    Finding,
    Level,
    Signal,
    Signature,
    SignatureStatus,
)
from zerobirus.core.rules import Rules, load_rules
from zerobirus.core.safety import SystemContext, normalize_windows_path
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import (
    command_signals,
    finish,
    lookup,
    make_finding,
    merge_gaps,
    signature_map,
    signature_signals,
)

CHECK = "startup"


def _winlogon_changed(entry: AutorunEntry, ctx: SystemContext) -> bool:
    value = (
        normalize_windows_path(entry.command)
        if entry.command[1:3] == ":\\"
        else entry.command.lower()
    )
    value = value.strip()
    if entry.name.lower() == "shell":
        return value != "explorer.exe"
    if entry.name.lower() == "userinit":
        expected = normalize_windows_path(ctx.system_root + "\\system32\\userinit.exe")
        return value.rstrip(",") != expected
    return False


def judge(
    entry: AutorunEntry, ctx: SystemContext, rules: Rules, sigs: dict[str, Signature]
) -> Finding | None:
    signals: list[Signal] = command_signals(entry.command, rules)
    target = extract_executable(entry.command)
    path_hits = [p for p in paths_in_command(entry.command) if location_kind(p, ctx)]

    if entry.kind == "winlogon":
        if _winlogon_changed(entry, ctx):
            signals.append(rules.signal("winlogon_changed"))
    elif entry.kind == "appinit" and entry.command.strip():
        signals.append(rules.signal("appinit_dll"))
    elif entry.kind == "ifeo" and entry.command.strip():
        signals.append(rules.signal("ifeo_debugger"))

    sig = lookup(sigs, target)
    if path_hits or mentions_writable_env(entry.command):
        signals.append(rules.signal("persist_writable"))
        random_hit = next((p for p in path_hits if random_component(p, ctx)), None)
        if random_hit:
            signals.append(rules.signal("random_folder"))
        if random_hit and sig is not None and sig.status is SignatureStatus.UNSIGNED:
            signals.append(rules.signal("persist_unsigned_random_writable"))
    if runs_a_shell(entry.command) and (path_hits or command_signals(entry.command, rules)):
        signals.append(rules.signal("shell_command"))
    signals += signature_signals(sig, rules)

    if not signals:
        return None
    finding = make_finding(
        CHECK,
        f"{entry.kind}:{entry.source}:{entry.name}:{entry.user}",
        item=entry.name,
        location=entry.source,
        rules=rules,
        description="Arranca com o Windows.",
        signals=signals,
        evidence=(entry.command,),
        path=target,
        subject=(
            ("kind", "autorun"),
            ("autorun_kind", entry.kind),
            ("source", entry.source),
            ("name", entry.name),
            ("user", entry.user),
            ("command", entry.command),
            ("path", entry.path),
        ),
    )
    return finding if finding.level is not Level.OK else None


def targets_to_sign(entries: tuple[AutorunEntry, ...]) -> list[str]:
    out: list[str] = []
    for e in entries:
        t = extract_executable(e.command)
        if t and e.kind in ("run", "runonce", "policies_run", "startup_folder"):
            out.append(t)
    return out


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    ctx = inspector.system_context()
    observed = inspector.autoruns()
    sigs, sig_gaps = signature_map(inspector, targets_to_sign(observed.items))
    findings = [f for e in observed.items if (f := judge(e, ctx, rules, sigs)) is not None]
    return finish(CHECK, findings, [*merge_gaps(observed), *sig_gaps], len(observed.items))
