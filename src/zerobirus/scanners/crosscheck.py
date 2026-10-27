"""Checks that need the results of other checks, run once all of them are done.

A whole-drive Defender exclusion alone is CONFERIR. Next to other signs of infection on the
same machine it makes the set SUSPEITO (it is one of the most common moves of whoever installs
a miner). This is a pure function over finished results: it asks the system nothing, so it adds
no work to the parallel scan.

Only verified indicators corroborate (the unverified signals are not in the list), and persistence
only counts when it points to AppData or Temp: a legitimate tool in ProgramData does not.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable

from zerobirus.core.heuristics import location_kind, mentions_writable_env
from zerobirus.core.models import CheckResult, Finding, Level
from zerobirus.core.rules import load_rules
from zerobirus.core.safety import SystemContext

_CORROBORATING = frozenset(
    {
        "cmdline_miner_marker",
        "cmdline_pool_domain",
        "miner_process_name",
        "mining_port_writable",
        "mining_port_other",
    }
)
_PERSISTENCE = frozenset(
    {
        "persist_writable",
        "persist_unsigned_random_writable",
        "task_from_writable",
        "task_disguised_microsoft",
        "service_from_writable",
    }
)
_AT_RISK_PLACES = frozenset({"appdata", "temp"})
_SOURCES = ("processes", "startup", "tasks", "services", "network")
MAX_EVIDENCE = 5


def corroboration(checks: Iterable[CheckResult], ctx: SystemContext) -> list[str]:
    found: list[str] = []
    for check in checks:
        if check.check not in _SOURCES:
            continue
        for f in check.findings:
            if f.level is Level.OK:
                continue
            codes = {s.code for s in f.signals}
            at_risk = (f.path is not None and location_kind(f.path, ctx) in _AT_RISK_PLACES) or any(
                mentions_writable_env(e) for e in f.evidence
            )
            if codes & _CORROBORATING or (codes & _PERSISTENCE and at_risk):
                found.append(f"{f.item} ({f.location})")
    return list(dict.fromkeys(found))


def apply_cross_checks(
    checks: tuple[CheckResult, ...], ctx: SystemContext
) -> tuple[CheckResult, ...]:
    rules = load_rules()
    defender = next((c for c in checks if c.check == "defender"), None)
    if defender is None:
        return checks
    drives = [
        f
        for f in defender.findings
        if any(s.code == "defender_exclusion_whole_drive" for s in f.signals)
    ]
    if not drives:
        return checks
    proof = corroboration(checks, ctx)
    if not proof:
        return checks

    def escalate(f: Finding) -> Finding:
        if f not in drives:
            return f
        signals = (*f.signals, rules.signal("defender_whole_drive_exclusion_with_evidence"))
        return dataclasses.replace(
            f,
            signals=signals,
            level=rules.level(signals),
            evidence=(*f.evidence, *(f"junto com: {p}" for p in proof[:MAX_EVIDENCE])),
        )

    updated = dataclasses.replace(defender, findings=tuple(escalate(f) for f in defender.findings))
    return tuple(updated if c is defender else c for c in checks)
