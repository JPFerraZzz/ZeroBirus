"""Command line entry point. Phase 0: ``version`` and ``selftest`` only."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from zerobirus import __version__
from zerobirus.core.redact import REDACTED, redact
from zerobirus.core.safety import is_protected_path, is_protected_process
from zerobirus.platform.base import Inspector
from zerobirus.platform.fake import FakeInspector


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

    procs = {p.pid: p for p in inspector.list_processes()}
    if not procs:
        failures.append("inspector: no processes returned")
    for p in procs.values():
        if p.name.lower() == "svchost.exe" and not is_protected_process(p.name, p.path, ctx):
            failures.append("safety: genuine svchost not protected")
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zerobirus")
    parser.add_argument("--version", action="version", version=f"ZeroBirus {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("version", help="print the version")
    sub.add_parser("selftest", help="run internal sanity checks")
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"ZeroBirus {__version__}")
        return 0
    if args.command == "selftest":
        failures = selftest()
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print("selftest: ok" if not failures else f"selftest: {len(failures)} failure(s)")
        return 1 if failures else 0
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
