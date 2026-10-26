"""Core data models. Pure data, no OS or Qt dependency.

Every string that comes from the machine (names, command lines, file contents) is data. It
is never executed, evaluated or obeyed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from zerobirus.core.safety import SignerKind


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
    """Something the inspection found, with its level and the signals behind it.

    ``evidence`` holds raw strings from the machine (for example the original command
    line). They are redacted only when the report is written, never before scoring.
    """

    id: str
    item: str
    location: str
    level: Level
    description: str
    signals: tuple[Signal, ...] = field(default_factory=tuple)
    evidence: tuple[str, ...] = ()
    path: str | None = None
    sha256: str | None = None
    advice: str = ""

    @property
    def score(self) -> int:
        return sum(s.weight for s in self.signals)


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result of one check. A check that did not run is NAO_VERIFICADO, never OK.

    A check that ran only partly (``verified=False`` with findings) keeps the findings it
    has, but its level is never OK: it is the worst finding, or NAO_VERIFICADO.
    """

    check: str
    findings: tuple[Finding, ...] = ()
    verified: bool = True
    reason: str = ""
    inspected: int = 0

    def __post_init__(self) -> None:
        if not self.verified and not self.reason:
            raise ValueError("an unverified check must state why")

    @property
    def level(self) -> Level:
        present = {f.level for f in self.findings}
        for lvl in (Level.SUSPEITO, Level.CONFERIR):
            if lvl in present:
                return lvl
        if not self.verified or Level.NAO_VERIFICADO in present:
            return Level.NAO_VERIFICADO
        return Level.OK


@dataclass(frozen=True, slots=True)
class Observed[T]:
    """What an Inspector method saw, plus what it could not see.

    ``gaps`` lists, in plain words, every part that could not be read (no administrator,
    timeout, access denied). A non-empty ``gaps`` makes the matching check incomplete,
    which is NAO_VERIFICADO, never OK.
    """

    items: tuple[T, ...] = ()
    gaps: tuple[str, ...] = ()

    @classmethod
    def unavailable(cls, reason: str) -> Observed[T]:
        return cls((), (reason,))


class SignatureStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNSIGNED = "unsigned"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Signature:
    """Authenticode result for one file, as established by the backend."""

    path: str
    status: SignatureStatus
    kind: SignerKind = SignerKind.OTHER
    subject: str = ""


@dataclass(frozen=True, slots=True)
class FileHash:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """A running process as reported by an Inspector. All strings are data, never commands.

    ``cpu_percent`` is the share of the whole machine's CPU over the sampling window, or
    ``None`` when it could not be measured.
    """

    pid: int
    name: str
    path: str | None
    cmdline: str
    user: str
    parent_pid: int | None
    cpu_percent: float | None = None


@dataclass(frozen=True, slots=True)
class AutorunEntry:
    """Something that starts with Windows: registry value, startup shortcut, Winlogon..."""

    source: str
    name: str
    command: str
    user: str = ""


@dataclass(frozen=True, slots=True)
class TaskAction:
    execute: str
    arguments: str = ""


@dataclass(frozen=True, slots=True)
class TaskInfo:
    folder: str
    name: str
    enabled: bool
    actions: tuple[TaskAction, ...] = ()
    triggers: tuple[str, ...] = ()
    repeat_minutes: int | None = None


@dataclass(frozen=True, slots=True)
class ServiceInfo:
    name: str
    display_name: str
    image_command: str
    start: str
    account: str = ""


@dataclass(frozen=True, slots=True)
class ConnectionInfo:
    pid: int | None
    remote_address: str
    remote_port: int
    status: str


@dataclass(frozen=True, slots=True)
class DefenderState:
    """Microsoft Defender state. ``None`` means "could not be read", never "off"."""

    realtime: bool | None = None
    tamper_protection: bool | None = None
    passive_mode: bool | None = None
    signature_age_days: int | None = None
    threats: tuple[str, ...] | None = None
    exclusion_paths: tuple[str, ...] | None = None
    exclusion_extensions: tuple[str, ...] | None = None
    exclusion_processes: tuple[str, ...] | None = None
    exclusion_ips: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class WmiBinding:
    filter_name: str
    consumer_name: str
    consumer_class: str
    command: str = ""


@dataclass(frozen=True, slots=True)
class FileCandidate:
    path: str
    size: int
    mtime: int | None = None
