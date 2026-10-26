"""From check results to a diagnosis written for people who are not technical (BRIEF 5.2).

Pure and deterministic. The level of each finding is already decided by the scorers; this
module only groups, explains and states how sure it is. It never claims to know more than
the signals support.
"""

from __future__ import annotations

from dataclasses import dataclass

from zerobirus.core.models import CheckResult, Finding, Level
from zerobirus.core.rules import load_rules
from zerobirus.core.snapshot import Snapshot

THREAT_NAMES = {
    "minerador": "Minerador de criptomoeda",
    "trojan": "Trojan ou porta dos fundos",
}
MAX_VECTOR_GAP_SECONDS = 3 * 24 * 3600
TASK_MANAGER_NOTE = (
    "Alguns mineradores param quando o Gestor de Tarefas abre. Por isso, o que liga "
    "sozinho com o Windows pesa tanto como o uso de processador."
)
UNCLASSIFIED_KIND = "nao_classificada"
UNCLASSIFIED_NAME = "Ameaça não classificada"
UNCLASSIFIED_NOTE = (
    "Há achados SUSPEITO que nenhum destes tipos explica. Esta versão só distingue mineradores "
    "e trojans ou portas dos fundos; não distingue ladrões de palavras-passe, publicidade nem "
    "outros tipos, por isso não diz de que tipo são."
)
NO_VECTOR_TEXT = "Não dá para saber só com isto."


@dataclass(frozen=True, slots=True)
class Row:
    check: str
    finding: Finding


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    kind: str
    name: str
    certainty: str
    proofs: tuple[str, ...]
    note: str = ""


@dataclass(frozen=True, slots=True)
class NotVerified:
    check: str
    reason: str


@dataclass(frozen=True, slots=True)
class Diagnosis:
    overall: Level
    rows: tuple[Row, ...]
    threats: tuple[ThreatAssessment, ...]
    normal_things: tuple[Row, ...]
    not_verified: tuple[NotVerified, ...]
    entry_vector: str
    notes: tuple[str, ...]


_ORDER = {Level.SUSPEITO: 0, Level.CONFERIR: 1, Level.NAO_VERIFICADO: 2, Level.OK: 3}


def overall_level(checks: tuple[CheckResult, ...]) -> Level:
    levels = {c.level for c in checks}
    for lvl in (Level.SUSPEITO, Level.CONFERIR, Level.NAO_VERIFICADO):
        if lvl in levels:
            return lvl
    return Level.OK


def _assess(rows: tuple[Row, ...]) -> tuple[ThreatAssessment, ...]:
    rules = load_rules()
    out: list[ThreatAssessment] = []
    for kind, name in THREAT_NAMES.items():
        strong = weak = 0
        proofs: list[str] = []
        for row in rows:
            if row.finding.level not in (Level.SUSPEITO, Level.CONFERIR):
                continue
            hit = False
            for s in row.finding.signals:
                if rules.signals[s.code].threat != kind:
                    continue
                hit = True
                if s.text not in proofs:
                    proofs.append(s.text)
            if hit:
                if any(
                    rules.is_strong(s)
                    for s in row.finding.signals
                    if rules.signals[s.code].threat == kind
                ):
                    strong += 1
                else:
                    weak += 1
        if not strong and not weak:
            continue
        if strong == 0 and weak < 3:
            continue  # one or two weak signs are not enough to name a threat
        certainty = "alta" if strong >= 2 else "média"
        out.append(ThreatAssessment(kind, name, certainty, tuple(proofs)))

    # A SUSPEITO that none of the named types explains is never forced into one of them.
    named = {t.kind for t in out}
    leftover = [
        r.finding
        for r in rows
        if r.finding.level is Level.SUSPEITO
        and not any(rules.signals[s.code].threat in named for s in r.finding.signals)
    ]
    if leftover:
        proofs_left = tuple(
            dict.fromkeys(s.text for f in leftover for s in f.signals if rules.is_strong(s))
        )
        out.append(
            ThreatAssessment(
                UNCLASSIFIED_KIND,
                UNCLASSIFIED_NAME,
                "indeterminada",
                proofs_left,
                UNCLASSIFIED_NOTE,
            )
        )
    return tuple(out)


def _entry_vector(rows: tuple[Row, ...], snapshot: Snapshot | None) -> str:
    suspects = [r.finding for r in rows if r.finding.level is Level.SUSPEITO]
    if not suspects:
        return ""
    cracks = [r.finding for r in rows if any(s.code == "crack_folder" for s in r.finding.signals)]
    if not cracks:
        return NO_VECTOR_TEXT
    where = cracks[0].location
    if snapshot is not None:
        times = {f.path: f.mtime for f in snapshot.files if f.mtime is not None}
        crack_times = [times[c.path] for c in cracks if c.path in times]
        suspect_times = [times[s.path] for s in suspects if s.path in times]
        if any(abs(a - b) <= MAX_VECTOR_GAP_SECONDS for a in crack_times for b in suspect_times):
            return (
                f"Há uma pasta de crack ou ativador ({where}) criada na mesma altura que os "
                "ficheiros suspeitos: é um caminho provável de entrada."
            )
    return (
        f"Há uma pasta de crack ou ativador ({where}). Pode ser por aí que entrou, "
        "mas não há prova de que foi."
    )


def diagnose(checks: tuple[CheckResult, ...], snapshot: Snapshot | None = None) -> Diagnosis:
    rows = tuple(
        sorted(
            (Row(c.check, f) for c in checks for f in c.findings if f.level is not Level.OK),
            key=lambda r: (_ORDER[r.finding.level], -r.finding.score, r.finding.id),
        )
    )
    normal = tuple(Row(c.check, f) for c in checks for f in c.findings if f.level is Level.OK)
    not_verified = tuple(NotVerified(c.check, c.reason) for c in checks if not c.verified)
    overall = overall_level(checks)
    notes = (TASK_MANAGER_NOTE,) if overall in (Level.SUSPEITO, Level.CONFERIR) else ()
    return Diagnosis(
        overall=overall,
        rows=rows,
        threats=_assess(rows),
        normal_things=normal,
        not_verified=not_verified,
        entry_vector=_entry_vector(rows, snapshot),
        notes=notes,
    )
