"""Executables in user-writable places, found by the backend's bounded search."""

from __future__ import annotations

from zerobirus.core.heuristics import extract_executable, paths_in_command
from zerobirus.core.models import CheckResult, FileCandidate, Finding, Level, Signal, Signature
from zerobirus.core.rules import Rules, load_rules
from zerobirus.core.safety import SystemContext, normalize_windows_path
from zerobirus.platform.base import Inspector
from zerobirus.scanners.common import (
    crack_signals,
    finish,
    location_signals,
    lookup,
    make_finding,
    merge_gaps,
    signature_map,
    signature_signals,
    under_any,
)

CHECK = "files"
MAX_FILES_TO_SIGN = 150


def persistence_targets(inspector: Inspector) -> set[str]:
    """Normalised paths that something in Windows startup, tasks or services points to."""
    commands: list[str] = [e.command for e in inspector.autoruns().items]
    for task in inspector.scheduled_tasks().items:
        commands += [f"{a.execute} {a.arguments}" for a in task.actions]
    commands += [s.image_command for s in inspector.services().items]
    out: set[str] = set()
    for command in commands:
        for p in paths_in_command(command):
            out.add(normalize_windows_path(p))
        target = extract_executable(command)
        if target:
            out.add(normalize_windows_path(target))
    return out


def _narrow_exclusions(exclusions: tuple[str, ...]) -> list[str]:
    """Absolute folder or file exclusions, without wildcards and without whole drives.

    A whole-drive exclusion is already one finding in the Defender check; counting it
    against every file on the disk would bury everything else.
    """
    out: list[str] = []
    for e in exclusions:
        n = normalize_windows_path(e.rstrip("*"))
        if e[1:3] == ":\\" and len(n) > 3 and "*" not in e.rstrip("*"):
            out.append(e.rstrip("*"))
    return out


def _excluded(path: str, exclusions: tuple[str, ...]) -> bool:
    return under_any(path, _narrow_exclusions(exclusions))


def judge(
    f: FileCandidate,
    ctx: SystemContext,
    rules: Rules,
    *,
    persisted: set[str],
    running: set[str],
    exclusions: tuple[str, ...],
    sigs: dict[str, Signature],
) -> Finding | None:
    n = normalize_windows_path(f.path)
    signals: list[Signal] = location_signals(f.path, ctx, rules, code="file_in_writable")
    if not signals:
        return None  # not in a user-writable place (for example the Defender platform folder)
    signals += crack_signals(f.path, rules)
    is_persisted = n in persisted
    is_excluded = _excluded(f.path, exclusions)
    if is_persisted:
        signals.append(rules.signal("referenced_by_persistence"))
    if n in running:
        signals.append(rules.signal("running_from_file"))
    in_writable = any(s.code == "file_in_writable" for s in signals)
    if is_excluded and is_persisted and in_writable:
        signals.append(rules.signal("defender_exclusion_and_persistence"))
    elif is_excluded:
        signals.append(rules.signal("defender_exclusion_covers"))
    signals += signature_signals(lookup(sigs, f.path), rules)
    if not signals:
        return None
    finding = make_finding(
        CHECK,
        n,
        item=f.path.replace("/", "\\").rsplit("\\", 1)[-1],
        location=f.path,
        rules=rules,
        signals=signals,
        path=f.path,
        subject=(("kind", "file"), ("path", f.path)),
        description="Executável numa pasta gravável pelo utilizador.",
    )
    return finding if finding.level is not Level.OK else None


def scan(inspector: Inspector) -> CheckResult:
    rules = load_rules()
    ctx = inspector.system_context()
    observed = inspector.candidate_files()
    persisted = persistence_targets(inspector)
    running = {normalize_windows_path(p.path) for p in inspector.processes().items if p.path}
    defender = inspector.defender().items
    exclusions = defender[0].exclusion_paths or () if defender else ()

    interesting: list[str] = []
    for f in observed.items:
        n = normalize_windows_path(f.path)
        sigs_signals = location_signals(f.path, ctx, rules, code="file_in_writable")
        if (
            n in persisted
            or n in running
            or _excluded(f.path, exclusions)
            or crack_signals(f.path, rules)
            or any(s.code == "random_folder" for s in sigs_signals)
        ):
            interesting.append(f.path)
    sigs, sig_gaps = signature_map(inspector, interesting[:MAX_FILES_TO_SIGN])

    findings = [
        x
        for f in observed.items
        if (
            x := judge(
                f,
                ctx,
                rules,
                persisted=persisted,
                running=running,
                exclusions=exclusions,
                sigs=sigs,
            )
        )
        is not None
    ]
    return finish(CHECK, findings, [*merge_gaps(observed), *sig_gaps], len(observed.items))
