"""Core data models. Pure data, no OS or Qt dependency."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Level(StrEnum):
    """Diagnosis level of a finding (BRIEF section 9)."""

    OK = "OK"
    CONFERIR = "CONFERIR"
    SUSPEITO = "SUSPEITO"
    NAO_VERIFICADO = "NAO_VERIFICADO"


class ActionResult(StrEnum):
    """Outcome of a remediation action (BRIEF section 5, stage 4)."""

    REMOVIDO = "REMOVIDO"
    EM_QUARENTENA = "EM_QUARENTENA"
    FALHOU = "FALHOU"
    PENDENTE_REINICIO = "PENDENTE_REINICIO"
    IGNORADO = "IGNORADO"


@dataclass(frozen=True, slots=True)
class Signal:
    """One explainable scoring signal. ``text`` is pt-PT, shown to the user."""

    code: str
    weight: int
    text: str


@dataclass(frozen=True, slots=True)
class Finding:
    """Something the inspection found, with its level and the signals behind it."""

    id: str
    item: str
    location: str
    level: Level
    description: str
    signals: tuple[Signal, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result of one check. A check that did not run is NAO_VERIFICADO, never OK."""

    check: str
    findings: tuple[Finding, ...] = ()
    verified: bool = True
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.verified and not self.reason:
            raise ValueError("an unverified check must state why")

    @property
    def level(self) -> Level:
        if not self.verified:
            return Level.NAO_VERIFICADO
        order = (Level.SUSPEITO, Level.CONFERIR, Level.NAO_VERIFICADO, Level.OK)
        present = {f.level for f in self.findings}
        return next((lvl for lvl in order if lvl in present), Level.OK)


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """A running process as reported by an Inspector. All strings are data, never commands."""

    pid: int
    name: str
    path: str | None
    cmdline: str
    user: str
    parent_pid: int | None
    signed_by_microsoft: bool
