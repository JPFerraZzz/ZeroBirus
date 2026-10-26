"""Permanent WMI event subscriptions in root\\subscription."""

from __future__ import annotations

from zerobirus.core.heuristics import extract_executable
from zerobirus.core.models import CheckResult, Finding, Level, SignatureStatus, WmiBinding
from zerobirus.core.rules import Rules, load_rules
from zerobirus.core.safety import SignerKind
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import finish, lookup, make_finding, merge_gaps, signature_map

CHECK = "wmi_bindings"
COMMAND_CONSUMERS = frozenset({"commandlineeventconsumer", "activescripteventconsumer"})
# Present on a stock Windows install: writes to the event log.
KNOWN_DEFAULTS = frozenset({("nteventlogeventconsumer", "scm event log consumer")})


def _is_default(b: WmiBinding) -> bool:
    return (b.consumer_class.lower(), b.consumer_name.lower()) in KNOWN_DEFAULTS


def judge(b: WmiBinding, rules: Rules, vendor_known: bool) -> Finding | None:
    if _is_default(b):
        return None
    runs_commands = b.consumer_class.lower() in COMMAND_CONSUMERS
    code = "wmi_command_unknown" if runs_commands and not vendor_known else "wmi_other"
    finding = make_finding(
        CHECK,
        f"{b.filter_name}:{b.consumer_name}",
        item=b.consumer_name,
        location=f"root\\subscription ({b.consumer_class})",
        rules=rules,
        signals=(rules.signal(code),),
        subject=(
            ("kind", "wmi_subscription"),
            ("filter", b.filter_name),
            ("consumer", b.consumer_name),
            ("consumer_class", b.consumer_class),
        ),
        evidence=(b.command,),
        description=f"Assinatura WMI permanente (filtro {b.filter_name}).",
    )
    return finding if finding.level is not Level.OK else None


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    observed = inspector.wmi_bindings()
    targets = [t for b in observed.items if (t := extract_executable(b.command))]
    sigs, sig_gaps = signature_map(inspector, targets)
    findings: list[Finding] = []
    for b in observed.items:
        sig = lookup(sigs, extract_executable(b.command) if b.command else None)
        known = (
            sig is not None
            and sig.status is SignatureStatus.VALID
            and sig.kind in (SignerKind.MICROSOFT, SignerKind.ANTIVIRUS_VENDOR)
        )
        if (f := judge(b, rules, known)) is not None:
            findings.append(f)
    return finish(CHECK, findings, [*merge_gaps(observed), *sig_gaps], len(observed.items))
