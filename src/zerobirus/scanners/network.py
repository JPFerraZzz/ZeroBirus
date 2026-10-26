"""Open connections to ports used by mining pools. No DNS, no network requests."""

from __future__ import annotations

import ipaddress

from zerobirus.core.heuristics import location_kind
from zerobirus.core.models import CheckResult, Finding, Level, ProcessInfo
from zerobirus.core.rules import load_rules
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import finish, make_finding, merge_gaps

CHECK = "network"
ACTIVE_STATES = frozenset({"ESTABLISHED", "SYN_SENT"})


def _is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True  # a name or something odd: do not assume it is local
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified)


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    ctx = inspector.system_context()
    connections = inspector.connections()
    processes = inspector.processes()
    by_pid: dict[int, ProcessInfo] = {p.pid: p for p in processes.items}
    findings: list[Finding] = []

    for c in connections.items:
        verified = c.remote_port in rules.mining_ports
        if c.status.upper() not in ACTIVE_STATES or not (
            verified or c.remote_port in rules.mining_ports_unverified
        ):
            continue
        if not _is_public(c.remote_address):
            continue
        proc = by_pid.get(c.pid) if c.pid is not None else None
        writable = bool(proc and proc.path and location_kind(proc.path, ctx))
        code = {
            (True, True): "mining_port_writable",
            (True, False): "mining_port_other",
            (False, True): "mining_port_unverified_writable",
            (False, False): "mining_port_unverified_other",
        }[(verified, writable)]
        signal = rules.signal(code)
        name = proc.name if proc else "(processo desconhecido)"
        finding = make_finding(
            CHECK,
            f"{c.pid}:{c.remote_address}:{c.remote_port}",
            item=f"{name} → {c.remote_address}:{c.remote_port}",
            location=proc.path if proc and proc.path else "(sem caminho)",
            rules=rules,
            signals=(signal,),
            path=proc.path if proc else None,
            description="Ligação a uma porta usada por pools de mineração.",
            evidence=(proc.cmdline,) if proc else (),
        )
        if finding.level is not Level.OK:
            findings.append(finding)
    return finish(CHECK, findings, merge_gaps(connections, processes), len(connections.items))
