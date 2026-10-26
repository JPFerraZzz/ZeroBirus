"""The scan report: what is shown, saved and shared. This is where redaction happens.

Scoring runs on original strings. Only here, on the way out, every string goes through
``redact`` (secrets) and the ``Anonymizer`` (personal data). The snapshot inside the report
has the same schema the fake backend replays, so a report from a real machine becomes a
golden fixture (see docs/WINDOWS_TEST_PLAN.md).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

from zerobirus import __version__
from zerobirus.core.diagnosis import Diagnosis, diagnose
from zerobirus.core.privacy import Anonymizer
from zerobirus.core.redact import redact
from zerobirus.core.rules import load_rules
from zerobirus.core.snapshot import Snapshot, snapshot_to_dict, to_jsonable
from zerobirus.scanners import TITLES
from zerobirus.scanners.runner import ScanResult

REPORT_SCHEMA_VERSION = 1


def _items(value: Any) -> list[tuple[str, Any]]:
    return list(value.items())


def _seq(value: Any) -> list[Any]:
    return list(value)


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in _items(node):
            if k != "user":
                yield from _strings(v)
    elif isinstance(node, list):
        for v in _seq(node):
            yield from _strings(v)


def _accounts(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for k, v in _items(node):
            if k == "user" and isinstance(v, str):
                yield v
            else:
                yield from _accounts(v)
    elif isinstance(node, list):
        for v in _seq(node):
            yield from _accounts(v)


def _clean(node: Any, anon: Anonymizer) -> Any:
    if isinstance(node, str):
        return redact(anon.text(node))
    if isinstance(node, dict):
        return {
            k: (redact(anon.account(v)) if k == "user" and isinstance(v, str) else _clean(v, anon))
            for k, v in _items(node)
        }
    if isinstance(node, list):
        return [_clean(v, anon) for v in _seq(node)]
    return node


def _shareable_snapshot(snapshot: Snapshot) -> Snapshot:
    """Drop what is private and not needed to replay the findings.

    Connections: only those to mining ports are kept, because the rest is the person's
    browsing. The count of dropped ones is not recorded.
    """
    ports = load_rules().mining_ports
    return replace(
        snapshot, connections=tuple(c for c in snapshot.connections if c.remote_port in ports)
    )


def _diagnosis_dict(d: Diagnosis) -> dict[str, Any]:
    return {
        "overall": d.overall.value,
        "threats": [to_jsonable(t) for t in d.threats],
        "entry_vector": d.entry_vector,
        "normal_things": [r.finding.id for r in d.normal_things],
        "not_verified": [to_jsonable(n) for n in d.not_verified],
        "notes": list(d.notes),
        "rows": [r.finding.id for r in d.rows],
    }


def build_report(
    result: ScanResult,
    *,
    generated_at: str | None = None,
    include_snapshot: bool = True,
) -> dict[str, Any]:
    """The report as plain data, already redacted and anonymised: safe to share."""
    diagnosis = diagnose(result.checks, result.snapshot)
    raw: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "ZeroBirus", "version": __version__},
        "generated_at": generated_at,
        "elevated": result.elevated,
        "overall": diagnosis.overall.value,
        "checks": [
            {
                "check": c.check,
                "title": TITLES.get(c.check, c.check),
                "level": c.level.value,
                "verified": c.verified,
                "reason": c.reason,
                "inspected": c.inspected,
                "seconds": result.seconds.get(c.check),
                "findings": [{**to_jsonable(f), "score": f.score} for f in c.findings],
            }
            for c in result.checks
        ],
        "diagnosis": _diagnosis_dict(diagnosis),
    }
    if include_snapshot:
        raw["snapshot"] = snapshot_to_dict(_shareable_snapshot(result.snapshot))
    anon = Anonymizer(result.snapshot.system, _strings(raw), _accounts(raw))
    cleaned: dict[str, Any] = _clean(raw, anon)
    return cleaned


def render_text(report: dict[str, Any]) -> str:
    """A short human summary of a report (pt-PT). Built from the already redacted data."""
    lines = [
        f"ZeroBirus {report['tool']['version']}: verificação só de leitura (nada foi alterado)",
        f"Resultado geral: {report['overall']}",
        "",
    ]
    if not report["elevated"]:
        lines += ["Aviso: sem administrador, algumas verificações ficam incompletas.", ""]
    for check in report["checks"]:
        n = len([f for f in check["findings"] if f["level"] != "OK"])
        extra = f", {n} a rever" if n else ""
        lines.append(
            f"[{check['level']}] {check['title']} ({check['inspected']} analisados{extra})"
        )
        if not check["verified"]:
            lines.append(f"    não verificado: {check['reason']}")
    by_id = {f["id"]: f for c in report["checks"] for f in c["findings"]}
    diagnosis = report["diagnosis"]
    if diagnosis["rows"]:
        lines += ["", "O que encontrei:"]
        for fid in diagnosis["rows"]:
            f = by_id[fid]
            lines.append(f"  [{f['level']}] {f['item']} | {f['location']}")
            lines += [f"      - {s['text']}" for s in f["signals"]]
            if f["sha256"]:
                lines.append(f"      SHA-256: {f['sha256']}")
            if f["advice"]:
                lines.append(f"      Conselho: {f['advice']}")
    for threat in diagnosis["threats"]:
        if threat["note"]:
            lines += ["", f"{threat['name']}.", f"  {threat['note']}"]
        else:
            lines += ["", f"Ameaça provável: {threat['name']} (certeza {threat['certainty']})"]
    if diagnosis["entry_vector"]:
        lines += ["", f"Por onde pode ter entrado: {diagnosis['entry_vector']}"]
    if diagnosis["normal_things"]:
        lines += ["", "Coisas normais que assustam:"]
        groups: dict[tuple[str, str], int] = {}
        for i in diagnosis["normal_things"]:
            name = re.sub(r" \(PID \d+\)$", "", by_id[i]["item"])
            groups[(name, by_id[i]["description"])] = (
                groups.get((name, by_id[i]["description"]), 0) + 1
            )
        for (name, text), count in groups.items():
            times = f" (x{count})" if count > 1 else ""
            lines.append(f"  {name}{times}: {text}")
    lines += ["", *diagnosis["notes"]]
    return "\n".join(lines).rstrip() + "\n"
