"""Command line entry point: ``version``, ``selftest`` and ``scan`` (read-only)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from zerobirus import __version__
from zerobirus.core.redact import REDACTED, redact
from zerobirus.core.report import build_report, render_text
from zerobirus.core.safety import is_protected_path, is_protected_process
from zerobirus.platform.base import Inspector
from zerobirus.platform.fake import FakeInspector, fixture_names, load_snapshot_file
from zerobirus.platform.loader import BackendUnavailable, create_inspector
from zerobirus.scanners.runner import DEFAULT_TIMEOUT, run_scan


def selftest(inspector: Inspector | None = None) -> list[str]:
    """Run internal sanity checks. Returns the list of failures (empty means OK)."""
    failures: list[str] = []
    inspector = inspector or FakeInspector()
    ctx = inspector.system_context()

    if redact("miner --password=hunter2") != f"miner --password={REDACTED}":
        failures.append("redact: password argument not hidden")
    if not is_protected_path(r"C:\Windows\System32\kernel32.dll", ctx):
        failures.append("safety: System32 file not protected")
    if is_protected_path(r"C:\Users\Demo\AppData\Local\Temp\x.exe", ctx):
        failures.append("safety: temp file wrongly protected")

    procs = {p.pid: p for p in inspector.processes().items}
    if not procs:
        failures.append("inspector: no processes returned")
    for p in procs.values():
        if p.name.lower() == "svchost.exe" and not is_protected_process(p.name, p.path, ctx):
            failures.append("safety: genuine svchost not protected")
    return failures


def _inspector_for(args: argparse.Namespace) -> Inspector:
    if args.fixture:
        path = Path(args.fixture)
        return FakeInspector(load_snapshot_file(path) if path.suffix == ".json" else args.fixture)
    if args.demo:
        return FakeInspector(args.demo)
    return create_inspector()


def scan(args: argparse.Namespace) -> int:
    """Read-only scan. The only thing written is the report file, when ``--out`` is given."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
    try:
        inspector = _inspector_for(args)
    except BackendUnavailable as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 3
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Erro ao carregar a fixture: {exc}", file=sys.stderr)
        return 2
    result = run_scan(inspector, timeout=args.timeout)
    report = build_report(
        result,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        include_snapshot=not args.no_snapshot,
    )
    if args.out:
        Path(args.out).write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"Relatório escrito em {args.out} (sem segredos e sem nomes de utilizador).")
        print(render_text(report))
    elif args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render_text(report))
    return 0


def gui(args: argparse.Namespace) -> int:
    """Open the window. Qt is imported here so the other commands never need it."""
    try:
        inspector = _inspector_for(args)
    except BackendUnavailable as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 3
    from zerobirus.ui.app import run_gui

    return run_gui(inspector, demo=bool(args.demo or args.fixture))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv) if argv is not None else sys.argv[1:]
    if not arguments and getattr(sys, "frozen", False):
        arguments = ["gui"]  # a double-clicked ZeroBirus.exe opens the window
    parser = argparse.ArgumentParser(prog="zerobirus")
    parser.add_argument("--version", action="version", version=f"ZeroBirus {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("version", help="print the version")
    sub.add_parser("selftest", help="run internal sanity checks")
    scan_parser = sub.add_parser("scan", help="read-only scan of this machine")
    scan_parser.add_argument("--json", action="store_true", help="print the report as JSON")
    scan_parser.add_argument("--out", metavar="FILE", help="write the JSON report to FILE")
    scan_parser.add_argument(
        "--demo",
        nargs="?",
        const="miner_pc",
        choices=fixture_names(),
        metavar="NAME",
        help=f"use a synthetic fixture instead of this machine ({', '.join(fixture_names())})",
    )
    scan_parser.add_argument("--fixture", metavar="FILE_OR_NAME", help="replay a snapshot file")
    scan_parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    scan_parser.add_argument(
        "--no-snapshot", action="store_true", help="leave the replayable snapshot out of the report"
    )
    gui_parser = sub.add_parser("gui", help="open the window")
    gui_parser.add_argument(
        "--demo", nargs="?", const="miner_pc", choices=fixture_names(), metavar="NAME"
    )
    gui_parser.add_argument("--fixture", metavar="FILE_OR_NAME")
    args = parser.parse_args(arguments)

    if args.command == "version":
        print(f"ZeroBirus {__version__}")
        return 0
    if args.command == "selftest":
        failures = selftest()
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print("selftest: ok" if not failures else f"selftest: {len(failures)} failure(s)")
        return 1 if failures else 0
    if args.command == "scan":
        return scan(args)
    if args.command == "gui":
        return gui(args)
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
