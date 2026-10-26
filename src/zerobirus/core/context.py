"""Stage 0: what the person noticed (BRIEF section 5).

The answers are kept in the session and in the report, and they change the ORDER and the
emphasis of the checks. They never switch a check off: a test proves it for every combination.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from zerobirus.scanners import SCANNERS


class Symptom(StrEnum):
    SLOW = "slow"
    HOT = "hot"
    FAN = "fan"
    WINDOWS_FLASH = "windows_flash"
    ANTIVIRUS_OFF = "antivirus_off"
    PIRATED = "pirated"
    OTHER = "other"


# Which checks a symptom points at first. Order inside a list is the order they move to the front.
EMPHASIS: dict[Symptom, tuple[str, ...]] = {
    Symptom.SLOW: ("processes", "startup", "services"),
    Symptom.HOT: ("processes", "network"),
    Symptom.FAN: ("processes", "network", "startup"),
    Symptom.WINDOWS_FLASH: ("tasks", "startup", "processes"),
    Symptom.ANTIVIRUS_OFF: ("defender", "services"),
    Symptom.PIRATED: ("files", "startup", "defender"),
    Symptom.OTHER: (),
}


@dataclass(frozen=True, slots=True)
class Answers:
    """The stage 0 answers. ``other_text`` is free text from the person: data, never obeyed."""

    symptoms: frozenset[Symptom] = frozenset()
    other_text: str = ""
    extra: dict[str, str] = field(default_factory=dict[str, str])

    @property
    def pirated(self) -> bool:
        return Symptom.PIRATED in self.symptoms


def check_order(answers: Answers) -> tuple[str, ...]:
    """Every check, with the ones the symptoms point at first. Never fewer than all of them."""
    base = list(SCANNERS)
    front: list[str] = []
    for symptom in sorted(answers.symptoms, key=lambda s: s.value):
        for check in EMPHASIS[symptom]:
            if check not in front:
                front.append(check)
    rest = [c for c in base if c not in front]
    return tuple([*front, *rest])


def emphasised(answers: Answers) -> frozenset[str]:
    """Checks to highlight in the interface and report (still all run)."""
    return frozenset(c for s in answers.symptoms for c in EMPHASIS[s])
