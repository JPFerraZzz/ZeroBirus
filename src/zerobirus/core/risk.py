"""The five-level risk table of the deep analysis (D-015), derived from the existing signals.

Pure and deterministic. The score and the strong signals are decided by the scorers
(``core/rules/scoring.json``); this module only maps them to a level, with the thresholds in
``core/rules/risk.json``. A weak-only score never goes above SUSPEITO: the score does not
rise because a name sounds scary. GRAVE and CRITICO need strong signals, and CRITICO needs
them confirmed by independent families of evidence (execution, persistence, network...).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from importlib import resources
from typing import Any

from zerobirus.core.models import Finding, Signal
from zerobirus.core.rules import load_rules


class Risk(StrEnum):
    INCOMUM = "INCOMUM"
    ANOMALO = "ANOMALO"
    SUSPEITO = "SUSPEITO"
    GRAVE = "GRAVE"
    CRITICO = "CRITICO"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @property
    def label(self) -> str:
        return LABELS[self]

    @property
    def preselected(self) -> bool:
        """Marked for quarantine by default. The person can always untick it."""
        return self.rank >= _RANK[Risk.GRAVE]


_RANK = {r: i for i, r in enumerate(Risk)}
LABELS = {
    Risk.INCOMUM: "Incomum",
    Risk.ANOMALO: "Anómalo",
    Risk.SUSPEITO: "Suspeito",
    Risk.GRAVE: "Grave",
    Risk.CRITICO: "Crítico",
}


@dataclass(frozen=True, slots=True)
class RiskRules:
    incomum: int
    anomalo: int
    suspeito: int
    grave_min_strong: int
    grave_min_families: int
    critico_min_strong: int
    critico_min_families: int
    families: dict[str, str]


@lru_cache(maxsize=1)
def load_risk_rules() -> RiskRules:
    text = resources.files("zerobirus.core.rules").joinpath("risk.json").read_text("utf-8")
    data: dict[str, Any] = json.loads(text)
    t = data["thresholds"]
    rules = RiskRules(
        incomum=int(t["incomum"]),
        anomalo=int(t["anomalo"]),
        suspeito=int(t["suspeito"]),
        grave_min_strong=int(data["grave_min_strong"]),
        grave_min_families=int(data["grave_min_families"]),
        critico_min_strong=int(data["critico_min_strong"]),
        critico_min_families=int(data["critico_min_families"]),
        families={str(k): str(v) for k, v in data["families"].items()},
    )
    if not 0 < rules.incomum < rules.anomalo < rules.suspeito:
        raise ValueError("risk thresholds must satisfy 0 < incomum < anomalo < suspeito")
    unknown = set(load_rules().signals) - set(rules.families)
    if unknown:
        raise ValueError(f"signals without a family in risk.json: {sorted(unknown)}")
    return rules


def risk_of_signals(signals: tuple[Signal, ...]) -> Risk | None:
    """The level of a set of signals, or ``None`` when there is nothing worth showing."""
    rules, risk = load_rules(), load_risk_rules()
    strong = {s.code for s in signals if rules.is_strong(s)}
    families = {risk.families[s.code] for s in signals if s.weight > 0}
    if strong:
        if len(strong) >= risk.critico_min_strong and len(families) >= risk.critico_min_families:
            return Risk.CRITICO
        if len(strong) >= risk.grave_min_strong or len(families) >= risk.grave_min_families:
            return Risk.GRAVE
        return Risk.SUSPEITO
    score = sum(s.weight for s in signals)
    if score >= risk.suspeito:
        return Risk.SUSPEITO
    if score >= risk.anomalo:
        return Risk.ANOMALO
    if score >= risk.incomum:
        return Risk.INCOMUM
    return None


def risk_of(finding: Finding) -> Risk | None:
    return risk_of_signals(finding.signals)
