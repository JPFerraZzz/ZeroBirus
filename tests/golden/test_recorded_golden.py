"""Golden tests over fixtures recorded on real machines (see docs/WINDOWS_TEST_PLAN.md).

Each ``tests/fixtures/recorded/<name>.json`` (a snapshot) with a ``<name>.expected.json``
is scanned and compared. A fixture of kind ``false-positive`` must also never be SUSPEITO.
"""

import json
from pathlib import Path

import pytest

from zerobirus.core.models import Level
from zerobirus.core.snapshot import snapshot_from_dict
from zerobirus.platform.fake import FakeInspector
from zerobirus.scanners.runner import run_scan

RECORDED = Path(__file__).resolve().parents[1] / "fixtures" / "recorded"
EXPECTED = sorted(RECORDED.glob("*.expected.json"))


def test_there_are_recorded_fixtures_to_replay() -> None:
    if not EXPECTED:
        pytest.skip("no real-machine fixture recorded yet (João provides them in the manual test)")


@pytest.mark.parametrize(
    "expected_file", EXPECTED, ids=lambda p: p.name.removesuffix(".expected.json")
)
def test_recorded_machine_gives_the_recorded_verdicts(expected_file: Path) -> None:
    name = expected_file.name.removesuffix(".expected.json")
    expected = json.loads(expected_file.read_text("utf-8"))
    snapshot = snapshot_from_dict(json.loads((RECORDED / f"{name}.json").read_text("utf-8")))
    result = run_scan(FakeInspector(snapshot))
    got = sorted(
        [c.check, f.level.value, f.item]
        for c in result.checks
        for f in c.findings
        if f.level is not Level.OK
    )
    assert got == expected["verdicts"]
    if expected["kind"] == "false-positive":
        assert all(level != "SUSPEITO" for _, level, _ in got)
