"""AllUp: which apps have an update, and the authorised list of what to update (PitStop).

Pure data and rules. The listing comes from ``winget`` (run by the Windows backend, which is
the only thing that touches the network, D-016); this module parses its table and builds the
plan. The text winget prints is data: package ids are checked against a strict pattern before
they can ever become an argument, and only ids that were in the list the person saw, and that
they ticked, are accepted. Updating installs software and cannot be undone by ZeroBirus, so
the plan says so.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

# winget ids look like "Mozilla.Firefox" or "9NBLGGH4NNS1". Nothing that could be read as an
# option (leading "-"), a path or a shell character.
PACKAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_ROW = re.compile(
    r"^(?P<name>.+?)\s+(?P<id>\S+)\s+(?P<version>(?:[<>]\s*)?\S+)\s+(?P<available>\S+)"
    r"(?:\s+(?P<source>[A-Za-z0-9_-]+))?\s*$"
)
_DASHES = re.compile(r"^-{5,}\s*$")
_SPINNER = re.compile(r"^[\s\\|/-]{1,3}$")  # winget's progress spinner, alone on a line
MAX_PACKAGES = 300


@dataclass(frozen=True, slots=True)
class Upgrade:
    name: str
    id: str
    version: str
    available: str
    source: str = ""


def parse_upgrades(output: str) -> tuple[Upgrade, ...]:
    """Parse the table of ``winget upgrade``. Any language: it relies on the dashed line under
    the header, not on the header words. Rows it cannot read are left out, never guessed."""
    lines = [ln.rsplit("\r", 1)[-1].rstrip() for ln in output.splitlines()]
    lines = ["" if _SPINNER.match(ln) else ln for ln in lines]
    start = next((i for i, ln in enumerate(lines) if _DASHES.match(ln)), None)
    if start is None:
        return ()
    found: list[Upgrade] = []
    for ln in lines[start + 1 :]:
        if not ln.strip():
            break  # the table ends at the first empty line (the count line follows it)
        m = _ROW.match(ln)
        if m is None or not PACKAGE_ID.match(m["id"]):
            continue
        found.append(
            Upgrade(
                m["name"].strip(),
                m["id"],
                m["version"].replace(" ", ""),
                m["available"],
                m["source"] or "",
            )
        )
        if len(found) >= MAX_PACKAGES:
            break
    return tuple(dict.fromkeys(found))


@dataclass(frozen=True, slots=True)
class UpdatePlan:
    """What the person authorised: only ids that were listed, each one once. Immutable."""

    session_id: str
    authorised_at: str
    ids: tuple[str, ...]
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(self.ids)

    def contains(self, package_id: str) -> bool:
        return self.verify() and package_id in self.ids


def _digest(ids: Iterable[str]) -> str:
    text = json.dumps(sorted(ids), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def authorize_updates(
    listed: Sequence[Upgrade], chosen: Iterable[str], *, session_id: str, authorised_at: str
) -> UpdatePlan:
    """Build the plan from the ids the person ticked. An id that was not in the list they saw,
    or that does not look like a package id, is an error, never silently dropped."""
    known = {u.id for u in listed}
    ids = tuple(dict.fromkeys(chosen))
    bad = [i for i in ids if i not in known or not PACKAGE_ID.match(i)]
    if bad:
        raise ValueError(f"packages that are not in the list: {bad}")
    if not ids:
        raise ValueError("nothing was approved")
    return UpdatePlan(session_id, authorised_at, ids, _digest(ids))


@dataclass(frozen=True, slots=True)
class UpdateResult:
    id: str
    name: str
    confirmed: bool  # the package is no longer in the list of updates (independent re-read)
    detail: str
