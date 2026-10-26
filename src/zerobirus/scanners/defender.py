"""Microsoft Defender: state, threat history and exclusions.

Without administrator rights the exclusions cannot be read. That is NAO_VERIFICADO, never
"no exclusions".
"""

from __future__ import annotations

from zerobirus.core.heuristics import location_kind, mentions_writable_env
from zerobirus.core.models import CheckResult, DefenderState, Finding, Level, Signal
from zerobirus.core.rules import Rules, load_rules
from zerobirus.core.safety import SystemContext, normalize_windows_path
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import finish, make_finding, merge_gaps

CHECK = "defender"
OLD_DAYS = 7
VERY_OLD_DAYS = 30
EXECUTABLE_EXTENSIONS = frozenset({"exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "msi"})


def _state_finding(s: DefenderState, rules: Rules) -> Finding:
    signals: list[Signal] = []
    if s.realtime is False and not s.passive_mode:
        signals.append(rules.signal("defender_realtime_off"))
    if s.tamper_protection is False:
        signals.append(rules.signal("defender_tamper_off"))
    if s.signature_age_days is not None:
        if s.signature_age_days > VERY_OLD_DAYS:
            signals.append(rules.signal("defender_signatures_very_old"))
        elif s.signature_age_days > OLD_DAYS:
            signals.append(rules.signal("defender_signatures_old"))
    level = rules.level(tuple(signals))
    if level is Level.OK and s.realtime is None and not s.passive_mode:
        level = Level.NAO_VERIFICADO
    if signals:
        description = "Estado do Microsoft Defender."
    elif s.passive_mode:
        description = "Microsoft Defender em modo passivo: há outro antivírus ativo."
    else:
        description = "Proteção em tempo real ativa e assinaturas em dia."
    if s.passive_mode and signals:
        description += " Está em modo passivo (há outro antivírus ativo)."
    return make_finding(
        CHECK,
        "state",
        item="Microsoft Defender",
        location="Estado",
        rules=rules,
        description=description,
        signals=signals,
        level=level,
    )


def _exclusion_findings(s: DefenderState, ctx: SystemContext, rules: Rules) -> list[Finding]:
    out: list[Finding] = []

    def add(kind: str, value: str, code: str, text: str) -> None:
        out.append(
            make_finding(
                CHECK,
                f"{kind}:{value.lower()}",
                item=value,
                location=f"Exclusão ({kind})",
                rules=rules,
                signals=(rules.signal(code),),
                evidence=(value,),
                description=text,
                path=value if kind == "pasta" else None,
            )
        )

    for p in s.exclusion_paths or ():
        n = normalize_windows_path(p.rstrip("*\\/") or p)
        whole_drive = len(n) <= 3 and n[1:2] == ":"
        writable = location_kind(p.rstrip("*"), ctx) is not None or mentions_writable_env(p)
        code = (
            "defender_exclusion_whole_drive"
            if whole_drive
            else "defender_exclusion_path_writable"
            if writable
            else "defender_exclusion_path"
        )
        add("pasta", p, code, "O Defender não analisa esta pasta ou ficheiro.")
    for e in s.exclusion_extensions or ():
        code = "defender_exclusion_extension"
        add("extensão", e, code, "O Defender não analisa ficheiros com esta extensão.")
    for e in s.exclusion_processes or ():
        add("processo", e, "defender_exclusion_process", "O Defender não analisa este processo.")
    for e in s.exclusion_ips or ():
        add("IP", e, "defender_exclusion_ip", "O Defender não analisa este endereço.")
    return [f for f in out if f.level is not Level.OK]


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    ctx = inspector.system_context()
    observed = inspector.defender()
    gaps = merge_gaps(observed)
    if not observed.items:
        return finish(CHECK, [], gaps or ["o estado do Defender não foi lido"], 0)
    s = observed.items[0]
    findings = [_state_finding(s, rules)]
    if s.realtime is None and not s.passive_mode:
        gaps.append("proteção em tempo real do Defender não legível")
    if s.threats is None:
        gaps.append("histórico de ameaças do Defender não legível")
    elif s.threats:
        findings.append(
            make_finding(
                CHECK,
                "threats",
                item="Histórico de ameaças",
                location="Microsoft Defender",
                rules=rules,
                signals=(rules.signal("defender_threat_history"),),
                evidence=s.threats,
                description=f"O Defender registou {len(s.threats)} ameaça(s).",
            )
        )
    unreadable = [
        n
        for n, v in (
            ("pastas", s.exclusion_paths),
            ("extensões", s.exclusion_extensions),
            ("processos", s.exclusion_processes),
            ("IPs", s.exclusion_ips),
        )
        if v is None
    ]
    if unreadable:
        gaps.append(
            "exclusões do Defender não legíveis (" + ", ".join(unreadable) + "); "
            "sem administrador não é possível lê-las"
        )
    findings += _exclusion_findings(s, ctx, rules)
    inspected = 1 + sum(
        len(v)
        for v in (s.exclusion_paths, s.exclusion_extensions, s.exclusion_processes, s.exclusion_ips)
        if v
    )
    return finish(CHECK, findings, gaps, inspected)
