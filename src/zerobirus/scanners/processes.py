"""Running processes: where they run from, command line, CPU, signature, impostors."""

from __future__ import annotations

from zerobirus.core.heuristics import location_kind
from zerobirus.core.models import (
    CheckResult,
    Finding,
    Level,
    ProcessInfo,
    Signature,
    SignatureStatus,
)
from zerobirus.core.rules import KnownGood, Rules, load_rules
from zerobirus.core.safety import (
    SystemContext,
    is_bare_image_name,
    is_no_image_process_name,
    is_protected_process,
    is_system_process_name,
    normalize_windows_path,
)
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import (
    command_signals,
    finish,
    is_microsoft_signed,
    location_signals,
    lookup,
    make_finding,
    merge_gaps,
    signature_map,
    signature_signals,
)

CHECK = "processes"
HIGH_CPU = 50.0
TOP_CPU_CANDIDATES = 15
NO_IMAGE_TEXT = "Processo interno do Windows, sem ficheiro no disco."


def _stem(name: str) -> str:
    low = name.lower()
    return low[:-4] if low.endswith(".exe") else low


def _known_good(
    p: ProcessInfo, sig: Signature | None, rules: Rules, ctx: SystemContext
) -> KnownGood | None:
    if p.path is None or sig is None or sig.status is not SignatureStatus.VALID:
        return None
    n = normalize_windows_path(p.path)
    for entry in rules.known_good:
        if (
            p.name.lower() == entry.name
            and entry.publisher in sig.subject.lower()
            and entry.where in n
        ):
            return entry
    return None


def _candidates(procs: tuple[ProcessInfo, ...], ctx: SystemContext) -> list[str]:
    by_cpu = sorted(
        (p for p in procs if p.cpu_percent is not None and p.path),
        key=lambda p: p.cpu_percent or 0.0,
        reverse=True,
    )[:TOP_CPU_CANDIDATES]
    chosen = {p.pid for p in by_cpu}
    paths: list[str] = []
    for p in procs:
        if not p.path or is_bare_image_name(p.path, p.name):
            continue
        if (
            p.pid in chosen
            or location_kind(p.path, ctx) is not None
            or is_system_process_name(p.name)
            or p.name.lower() in {k.name for k in load_rules().known_good}
        ):
            paths.append(p.path)
    return paths


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    ctx = inspector.system_context()
    observed = inspector.processes()
    procs = observed.items
    sigs, sig_gaps = signature_map(inspector, _candidates(procs, ctx))
    findings: list[Finding] = []

    for p in procs:
        if p.pid in ctx.own_pids:
            continue
        finding = _judge(p, ctx, rules, lookup(sigs, p.path))
        if finding is not None:
            findings.append(finding)
    return finish(CHECK, findings, [*merge_gaps(observed), *sig_gaps], len(procs))


def _judge(
    p: ProcessInfo, ctx: SystemContext, rules: Rules, sig: Signature | None
) -> Finding | None:
    key = f"{p.pid}:{p.name}"
    where = p.path or "(sem caminho)"
    label = f"{p.name} (PID {p.pid})"
    has_image = bool(p.path) and not is_bare_image_name(p.path or "", p.name)
    scary = p.name.lower() in rules.scary_system_names or _stem(p.name) in rules.scary_system_names

    if is_system_process_name(p.name):
        protected = is_protected_process(p.name, p.path, ctx, pid=p.pid)
        if protected and not has_image:
            if scary and is_no_image_process_name(p.name):
                return make_finding(
                    CHECK,
                    key,
                    item=p.name,
                    location="(sem ficheiro)",
                    description=NO_IMAGE_TEXT,
                    signals=(),
                    level=Level.OK,
                    rules=rules,
                )
            return None
        if protected:
            if sig is not None and sig.status in (
                SignatureStatus.INVALID,
                SignatureStatus.UNSIGNED,
            ):
                return make_finding(
                    CHECK,
                    key,
                    item=label,
                    location=where,
                    rules=rules,
                    path=p.path,
                    description="Ficheiro do Windows com assinatura inválida ou em falta.",
                    signals=(rules.signal("system_binary_bad_signature"),),
                    advice=(
                        "Não remover nada. Fazer a Análise offline do Microsoft Defender "
                        "e, se o problema continuar, considerar reinstalar o Windows."
                    ),
                )
            if is_microsoft_signed(sig) and scary:
                return make_finding(
                    CHECK,
                    key,
                    item=label,
                    location=where,
                    rules=rules,
                    path=p.path,
                    description="Processo normal do Windows, confirmado por assinatura e pasta.",
                    signals=(),
                    level=Level.OK,
                )
            return None
        return make_finding(
            CHECK,
            key,
            item=label,
            location=where,
            rules=rules,
            path=p.path,
            description="Tem o nome de um processo do Windows mas corre de fora da sua pasta.",
            signals=[rules.signal("system_name_wrong_location"), *signature_signals(sig, rules)],
            evidence=(p.cmdline,),
        )

    good = _known_good(p, sig, rules, ctx)
    if good is not None:
        return make_finding(
            CHECK,
            key,
            item=label,
            location=where,
            rules=rules,
            path=p.path,
            description=f"{good.label}: programa conhecido, confirmado por assinatura e pasta.",
            signals=(),
            level=Level.OK,
        )

    signals = command_signals(p.cmdline, rules)
    if _stem(p.name) in rules.miner_names:
        signals.append(rules.signal("miner_process_name"))
    elif _stem(p.name) in rules.miner_names_unverified:
        signals.append(rules.signal("miner_process_name_unverified"))
    if p.cpu_percent is not None and p.cpu_percent >= HIGH_CPU:
        signals.append(rules.signal("high_cpu"))
    if p.path and has_image:
        signals += location_signals(p.path, ctx, rules)
        signals += signature_signals(sig, rules)
    if not signals:
        return None
    finding = make_finding(
        CHECK,
        key,
        item=label,
        location=where,
        rules=rules,
        path=p.path,
        description="Programa em execução.",
        signals=signals,
        evidence=(p.cmdline,),
    )
    return finding if finding.level is not Level.OK else None
