"""The hosts file: lines that are not comments or the Windows defaults."""

from __future__ import annotations

from zerobirus.core.models import CheckResult, Finding, Level
from zerobirus.core.rules import load_rules
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import finish, make_finding, merge_gaps

CHECK = "hosts"


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    observed = inspector.hosts_lines()
    findings: list[Finding] = []
    effective = 0
    for raw in observed.items:
        if rules.hosts_own_marker in raw.lower():
            continue
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        effective += 1
        tokens = line.lower().split()
        if " ".join(tokens) in rules.hosts_defaults or len(tokens) < 2:
            continue
        names = tokens[1:]
        security = any(frag in n for n in names for frag in rules.hosts_security_fragments)
        signal = rules.signal("hosts_security_domain" if security else "hosts_other")
        finding = make_finding(
            CHECK,
            line.lower(),
            item=", ".join(names),
            location="hosts",
            rules=rules,
            signals=(signal,),
            evidence=(raw.strip(),),
            subject=(("kind", "hosts_line"), ("line", raw.strip())),
            description="Linha no ficheiro hosts que redireciona um nome.",
        )
        if finding.level is not Level.OK:
            findings.append(finding)
    return finish(CHECK, findings, merge_gaps(observed), effective)
