"""Detection rules as data (BRIEF section 7): weights, thresholds and indicators in JSON.

Changing a number here changes behaviour, so ``tests/unit/test_scoring.py`` pins it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

from zerobirus.core.models import Level, Signal


@dataclass(frozen=True, slots=True)
class SignalRule:
    weight: int
    strong: bool
    threat: str | None
    text: str


@dataclass(frozen=True, slots=True)
class Indicator:
    """One mining indicator with its provenance (see docs/DETECTION.md).

    An unverified indicator (no public source found) only ever feeds weak signals, so it can
    never make something SUSPEITO on its own.
    """

    value: str
    verified: bool
    sources: tuple[str, ...]
    note: str


@dataclass(frozen=True, slots=True)
class KnownGood:
    name: str
    publisher: str
    where: str
    label: str


@dataclass(frozen=True, slots=True)
class Rules:
    conferir: int
    suspeito: int
    signals: dict[str, SignalRule]
    miner_names: frozenset[str]
    miner_names_unverified: frozenset[str]
    strong_markers: tuple[str, ...]
    strong_markers_unverified: tuple[str, ...]
    weak_markers: tuple[str, ...]
    weak_markers_needed: int
    mining_ports: frozenset[int]
    mining_ports_unverified: frozenset[int]
    pool_domains: tuple[str, ...]
    pool_domains_unverified: tuple[str, ...]
    indicators: dict[str, tuple[Indicator, ...]]
    microsoft_orgs: tuple[str, ...]
    antivirus_orgs: tuple[str, ...]
    known_good: tuple[KnownGood, ...]
    scary_system_names: frozenset[str]
    hosts_defaults: frozenset[str]
    hosts_own_marker: str
    hosts_security_fragments: tuple[str, ...]

    def signal(self, code: str) -> Signal:
        rule = self.signals[code]
        return Signal(code=code, weight=rule.weight, text=rule.text)

    def is_strong(self, signal: Signal) -> bool:
        return self.signals[signal.code].strong

    def level(self, signals: tuple[Signal, ...]) -> Level:
        """Additive, explainable score (BRIEF section 9).

        A strong signal is SUSPEITO on its own, whatever else (such as a valid signature)
        lowers the score: stolen certificates exist. Weak signals never reach SUSPEITO
        alone, which ``test_scoring`` proves for every signal in the file.
        """
        if any(self.is_strong(s) for s in signals):
            return Level.SUSPEITO
        score = sum(s.weight for s in signals)
        if score >= self.suspeito:
            return Level.SUSPEITO
        if score >= self.conferir:
            return Level.CONFERIR
        return Level.OK

    def threats(self, signals: tuple[Signal, ...]) -> dict[str, int]:
        """Threat tag to the number of signals that point to it."""
        out: dict[str, int] = {}
        for s in signals:
            tag = self.signals[s.code].threat
            if tag is not None:
                out[tag] = out.get(tag, 0) + 1
        return out


def _read(name: str) -> dict[str, Any]:
    text = resources.files(__package__).joinpath(name).read_text("utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


@lru_cache(maxsize=1)
def load_rules() -> Rules:
    scoring = _read("scoring.json")
    miners = _read("miners.json")
    pub = _read("publishers.json")
    hosts = _read("hosts.json")
    indicators = {
        kind: tuple(
            Indicator(
                str(i["value"]), bool(i["verified"]), tuple(i["sources"]), str(i.get("note", ""))
            )
            for i in miners[kind]
        )
        for kind in (
            "process_names",
            "strong_markers",
            "weak_markers",
            "ports",
            "pool_domain_fragments",
        )
    }
    signals = {
        code: SignalRule(int(v["weight"]), bool(v["strong"]), v["threat"], str(v["text"]))
        for code, v in scoring["signals"].items()
    }
    rules = Rules(
        conferir=int(scoring["thresholds"]["conferir"]),
        suspeito=int(scoring["thresholds"]["suspeito"]),
        signals=signals,
        miner_names=frozenset(_values(indicators["process_names"], verified=True)),
        miner_names_unverified=frozenset(_values(indicators["process_names"], verified=False)),
        strong_markers=tuple(_values(indicators["strong_markers"], verified=True)),
        strong_markers_unverified=tuple(_values(indicators["strong_markers"], verified=False)),
        weak_markers=tuple(_values(indicators["weak_markers"], verified=True)),
        weak_markers_needed=int(miners["weak_markers_needed"]),
        mining_ports=frozenset(int(p) for p in _values(indicators["ports"], verified=True)),
        mining_ports_unverified=frozenset(
            int(p) for p in _values(indicators["ports"], verified=False)
        ),
        pool_domains=tuple(_values(indicators["pool_domain_fragments"], verified=True)),
        pool_domains_unverified=tuple(_values(indicators["pool_domain_fragments"], verified=False)),
        indicators=indicators,
        microsoft_orgs=tuple(pub["microsoft_organisations"]),
        antivirus_orgs=tuple(pub["antivirus_organisations"]),
        known_good=tuple(KnownGood(**k) for k in pub["known_good"]),
        scary_system_names=frozenset(pub["scary_system_names"]),
        hosts_defaults=frozenset(hosts["defaults"]),
        hosts_own_marker=hosts["own_marker"],
        hosts_security_fragments=tuple(hosts["security_domain_fragments"]),
    )
    _validate(rules)
    return rules


def _values(items: tuple[Indicator, ...], *, verified: bool) -> list[str]:
    return [i.value for i in items if i.verified is verified]


def _validate(rules: Rules) -> None:
    for kind, items in rules.indicators.items():
        for i in items:
            if i.verified and not i.sources:
                raise ValueError(f"{kind}: verified indicator {i.value!r} has no source")
            if not i.verified and i.sources:
                raise ValueError(f"{kind}: unverified indicator {i.value!r} lists a source")
    if not 0 < rules.conferir < rules.suspeito:
        raise ValueError("thresholds must satisfy 0 < conferir < suspeito")
    for code, rule in rules.signals.items():
        if not rule.text.strip():
            raise ValueError(f"signal {code} has no text")
        if rule.strong and rule.weight < rules.suspeito:
            raise ValueError(f"strong signal {code} must weigh at least the SUSPEITO threshold")
        if not rule.strong and rule.weight >= rules.suspeito:
            raise ValueError(f"weak signal {code} must weigh less than the SUSPEITO threshold")
