"""Runs every check in parallel, each with its own timeout (BRIEF section 7).

A check that fails or runs out of time becomes NAO_VERIFICADO with the reason, never OK and
never an exception that stops the others. The checks are read-only and only see an
Inspector, so a slow one that is abandoned cannot change anything.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Mapping
from dataclasses import dataclass

from zerobirus.core.models import CheckResult, Finding, Level
from zerobirus.core.safety import normalize_windows_path
from zerobirus.core.snapshot import Snapshot
from zerobirus.platform.base import Inspector
from zerobirus.platform.recording import RecordingInspector
from zerobirus.scanners import SCANNERS, Scanner

DEFAULT_TIMEOUT = 90.0


@dataclass(frozen=True, slots=True)
class ScanResult:
    checks: tuple[CheckResult, ...]
    snapshot: Snapshot

    @property
    def elevated(self) -> bool:
        return self.snapshot.elevated


def _run_one(name: str, scanner: Scanner, inspector: Inspector, timeout: float) -> CheckResult:
    box: list[CheckResult] = []

    def target() -> None:
        try:
            box.append(scanner(inspector))
        except Exception as exc:  # a failing check must not stop the others
            reason = f"a verificação falhou ({type(exc).__name__}: {str(exc)[:200]})"
            box.append(CheckResult(check=name, verified=False, reason=reason))

    thread = threading.Thread(target=target, name=f"check-{name}", daemon=True)
    thread.start()
    thread.join(timeout)
    if box:
        return box[0]
    return CheckResult(
        check=name, verified=False, reason=f"excedeu o tempo limite de {timeout:.0f} s"
    )


def _with_hashes(
    inspector: RecordingInspector, checks: tuple[CheckResult, ...]
) -> tuple[CheckResult, ...]:
    """SHA-256 for SUSPEITO files, so the user can look them up on another device."""
    paths = [f.path for c in checks for f in c.findings if f.level is Level.SUSPEITO and f.path]
    if not paths:
        return checks
    hashes = {normalize_windows_path(h.path): h.sha256 for h in inspector.file_hashes(paths).items}

    def attach(f: Finding) -> Finding:
        if f.level is Level.SUSPEITO and f.path and normalize_windows_path(f.path) in hashes:
            return dataclasses.replace(f, sha256=hashes[normalize_windows_path(f.path)])
        return f

    return tuple(
        dataclasses.replace(c, findings=tuple(attach(f) for f in c.findings)) for c in checks
    )


def run_scan(
    inspector: Inspector,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    scanners: Mapping[str, Scanner] | None = None,
) -> ScanResult:
    recording = RecordingInspector(inspector)
    chosen = dict(scanners if scanners is not None else SCANNERS)
    results: dict[str, CheckResult] = {}
    threads: dict[str, threading.Thread] = {}

    def launch(name: str, scanner: Scanner) -> None:
        results[name] = _run_one(name, scanner, recording, timeout)

    for name, scanner in chosen.items():
        t = threading.Thread(target=launch, args=(name, scanner), daemon=True)
        threads[name] = t
        t.start()
    for t in threads.values():
        t.join()
    checks = tuple(results[name] for name in chosen)
    checks = _with_hashes(recording, checks)
    return ScanResult(checks=checks, snapshot=recording.snapshot())
