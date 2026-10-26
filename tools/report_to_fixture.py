"""Turn a shared scan report into a golden fixture for the tests.

    uv run python tools/report_to_fixture.py report.json my-pc --kind false-positive

Reads the ``snapshot`` section of a report written by ``zerobirus scan --json --out``,
checks it for leftover personal data, and writes two files into tests/fixtures/recorded/:

- ``<name>.json``           the snapshot (the same schema the fake backend replays)
- ``<name>.expected.json``  the verdicts the scan gives on it today, to be reviewed by hand

For a ``false-positive`` fixture the golden test also requires that nothing is SUSPEITO.
Review both files before committing: this tool is a safety net, not a guarantee.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from zerobirus.core.models import Level  # noqa: E402
from zerobirus.core.privacy import find_personal_leftovers  # noqa: E402
from zerobirus.core.snapshot import snapshot_from_dict  # noqa: E402
from zerobirus.platform.fake import FakeInspector  # noqa: E402
from zerobirus.scanners.runner import run_scan  # noqa: E402

DEST = REPO / "tests" / "fixtures" / "recorded"


def _strings(node: object) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in _strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v)]
    return []


def verdicts(snapshot_data: dict[str, object]) -> list[list[str]]:
    result = run_scan(FakeInspector(snapshot_from_dict(snapshot_data)))
    return sorted(
        [c.check, f.level.value, f.item]
        for c in result.checks
        for f in c.findings
        if f.level is not Level.OK
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("report", type=Path)
    parser.add_argument("name", help="short name for the fixture, e.g. gaming-pc")
    parser.add_argument("--kind", choices=("false-positive", "detection"), default="false-positive")
    parser.add_argument("--dest", type=Path, default=DEST)
    parser.add_argument(
        "--force", action="store_true", help="write even if personal data is suspected"
    )
    args = parser.parse_args(argv)

    data = json.loads(args.report.read_text("utf-8"))
    snapshot = data.get("snapshot")
    if not isinstance(snapshot, dict):
        print(
            "O relatório não tem a secção 'snapshot' (foi gerado com --no-snapshot?).",
            file=sys.stderr,
        )
        return 2
    snapshot_from_dict(snapshot)  # fails loudly if the schema does not match

    leftovers = find_personal_leftovers(_strings(snapshot))
    if leftovers:
        print("Possíveis dados pessoais por limpar:", file=sys.stderr)
        for item in leftovers:
            print(f"  - {item}", file=sys.stderr)
        if not args.force:
            print("Corrige o relatório ou repete com --force depois de o rever.", file=sys.stderr)
            return 1

    args.dest.mkdir(parents=True, exist_ok=True)
    fixture = args.dest / f"{args.name}.json"
    expected = args.dest / f"{args.name}.expected.json"
    fixture.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", "utf-8")
    expected.write_text(
        json.dumps(
            {"kind": args.kind, "verdicts": verdicts(snapshot)}, indent=2, ensure_ascii=False
        )
        + "\n",
        "utf-8",
    )
    print(f"Escrevi {fixture} e {expected}. Revê os dois ficheiros antes de fazer commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
