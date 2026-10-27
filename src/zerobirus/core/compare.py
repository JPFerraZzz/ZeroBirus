"""Stage 5: what changed between the first scan and the repeated one (pure data)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

from zerobirus.core.models import CheckResult, Level
from zerobirus.core.redact import redact

_ACTIONABLE = (Level.SUSPEITO, Level.CONFERIR)


@dataclass(frozen=True, slots=True)
class Change:
    check: str
    item: str
    location: str
    level: Level


@dataclass(frozen=True, slots=True)
class ScanDiff:
    gone: tuple[Change, ...]  # in the first scan, not in the second
    remaining: tuple[Change, ...]  # in both
    came_back: tuple[Change, ...]  # not in the first, in the second (new or returned)
    still_unverified: tuple[str, ...]  # checks that could not be completed in the second scan

    @property
    def clean(self) -> bool:
        """Nothing suspicious left and nothing that could not be checked."""
        no_bad = not any(c.level is Level.SUSPEITO for c in (*self.remaining, *self.came_back))
        return no_bad and not self.still_unverified


def baseline_from_checks(checks: tuple[CheckResult, ...]) -> list[Change]:
    """The actionable findings of a scan, as the small record kept for the later comparison."""
    return [
        Change(c.check, f.item, f.location, f.level)
        for c in checks
        for f in c.findings
        if f.level in _ACTIONABLE
    ]


def _key(c: Change) -> tuple[str, str, str]:
    return (c.check, c.item.lower(), c.location.lower())


def baseline_to_json(baseline: Iterable[Change]) -> list[dict[str, str]]:
    return [
        {
            "check": c.check,
            "item": redact(c.item),
            "location": redact(c.location),
            "level": c.level.value,
        }
        for c in baseline
    ]


def baseline_from_json(data: object) -> list[Change]:
    if not isinstance(data, list):
        raise ValueError("baseline is not a list")
    rows: list[Any] = data  # pyright: ignore[reportUnknownVariableType]
    out: list[Change] = []
    for r in rows:
        if not isinstance(r, dict):
            raise ValueError("bad baseline row")
        row = cast("dict[str, Any]", r)
        out.append(
            Change(str(row["check"]), str(row["item"]), str(row["location"]), Level(row["level"]))
        )
    return out


def compare_scans(before: Iterable[Change], after: tuple[CheckResult, ...]) -> ScanDiff:
    """``before`` is the baseline (redacted the same way as the saved one, so redact both)."""
    old = {_key(c): c for c in before}
    new = {_key(c): c for c in baseline_from_checks(after)}
    gone = tuple(c for k, c in old.items() if k not in new)
    remaining = tuple(c for k, c in new.items() if k in old)
    back = tuple(c for k, c in new.items() if k not in old)
    unverified = tuple(c.check for c in after if not c.verified or c.level is Level.NAO_VERIFICADO)
    return ScanDiff(gone, remaining, back, unverified)
