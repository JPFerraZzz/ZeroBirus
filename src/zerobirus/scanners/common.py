"""Shared pieces of the scanners. Scanners read through an Inspector and never write.

Scanners score the ORIGINAL strings from the machine. They must not import
``core.redact``: redaction is for output only (a test enforces this).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from zerobirus.core.heuristics import (
    crack_word,
    location_kind,
    looks_random,
    random_component,
)
from zerobirus.core.models import (
    CheckResult,
    Finding,
    Level,
    Observed,
    Signal,
    Signature,
    SignatureStatus,
)
from zerobirus.core.rules import Rules, load_rules
from zerobirus.core.safety import SignerKind, SystemContext, is_under, normalize_windows_path
from zerobirus.platform.base import Inspector

MAX_SIGNATURE_CANDIDATES = 300


def stable_id(check: str, key: str) -> str:
    return f"{check}-{hashlib.sha256(key.encode('utf-8', 'surrogatepass')).hexdigest()[:10]}"


def make_finding(
    check: str,
    key: str,
    *,
    item: str,
    location: str,
    description: str,
    signals: Sequence[Signal],
    rules: Rules | None = None,
    level: Level | None = None,
    evidence: Iterable[str] = (),
    path: str | None = None,
    advice: str = "",
    subject: Sequence[tuple[str, str]] = (),
) -> Finding:
    rules = rules or load_rules()
    sigs = tuple(signals)
    return Finding(
        id=stable_id(check, key),
        item=item,
        location=location,
        level=level if level is not None else rules.level(sigs),
        description=description,
        signals=sigs,
        evidence=tuple(e for e in evidence if e),
        path=path,
        advice=advice,
        subject=tuple(subject),
    )


def finish(
    check: str,
    findings: Iterable[Finding],
    gaps: Iterable[str],
    inspected: int,
    *,
    keep_ok: bool = True,
) -> CheckResult:
    """Build the check result. Any gap makes the check incomplete (never OK)."""
    kept = tuple(f for f in findings if keep_ok or f.level is not Level.OK)
    reasons = list(dict.fromkeys(g for g in gaps if g))
    return CheckResult(
        check=check,
        findings=kept,
        verified=not reasons,
        reason="; ".join(reasons),
        inspected=inspected,
    )


def merge_gaps(*observed: Observed[object]) -> list[str]:
    return [g for o in observed for g in o.gaps]


def signature_map(
    inspector: Inspector, paths: Iterable[str]
) -> tuple[dict[str, Signature], tuple[str, ...]]:
    """Signatures for the candidate paths, keyed by normalised path, plus any gaps."""
    wanted = list(dict.fromkeys(p for p in paths if p))[:MAX_SIGNATURE_CANDIDATES]
    if not wanted:
        return {}, ()
    result = inspector.signatures(wanted)
    return {normalize_windows_path(s.path): s for s in result.items}, result.gaps


def lookup(sigs: dict[str, Signature], path: str | None) -> Signature | None:
    return sigs.get(normalize_windows_path(path)) if path else None


def signature_signals(sig: Signature | None, rules: Rules) -> list[Signal]:
    """Signals from an Authenticode result. Unknown means no signal, never "unsigned"."""
    if sig is None or sig.status is SignatureStatus.UNKNOWN:
        return []
    if sig.status is SignatureStatus.VALID:
        return [rules.signal("valid_signature")]
    if sig.status is SignatureStatus.INVALID:
        return [rules.signal("invalid_signature")]
    return [rules.signal("unsigned")]


def command_signals(command: str, rules: Rules) -> list[Signal]:
    """Mining markers in a command line. Always sees the original text."""
    low = command.lower()
    out: list[Signal] = []
    if any(m in low for m in rules.strong_markers):
        out.append(rules.signal("cmdline_miner_marker"))
    if any(d in low for d in rules.pool_domains):
        out.append(rules.signal("cmdline_pool_domain"))
    if not out and (
        any(m in low for m in rules.strong_markers_unverified)
        or any(d in low for d in rules.pool_domains_unverified)
    ):
        out.append(rules.signal("cmdline_miner_unverified"))
    weak = sum(m in low for m in rules.weak_markers)
    if weak >= rules.weak_markers_needed:
        out.append(rules.signal("cmdline_miner_weak"))
    return out


def is_microsoft_signed(sig: Signature | None) -> bool:
    return (
        sig is not None and sig.status is SignatureStatus.VALID and sig.kind is SignerKind.MICROSOFT
    )


def location_signals(
    path: str, ctx: SystemContext, rules: Rules, *, code: str = "writable_location"
) -> list[Signal]:
    out: list[Signal] = []
    if location_kind(path, ctx) is not None:
        out.append(rules.signal(code))
        if random_component(path, ctx) is not None:
            out.append(rules.signal("random_folder"))
    return out


def crack_signals(path: str, rules: Rules) -> list[Signal]:
    return [rules.signal("crack_folder")] if crack_word(path) else []


def stem_looks_random(path: str) -> bool:
    name = path.replace("/", "\\").rsplit("\\", 1)[-1]
    return looks_random(name.rsplit(".", 1)[0] if "." in name else name)


def under_any(path: str, roots: Iterable[str]) -> bool:
    n = normalize_windows_path(path)
    return any(is_under(n, normalize_windows_path(r)) for r in roots if r)
