"""Facts recorded on real machines, replayed on any platform.

Each ``tests/fixtures/recorded/*.json`` is a scan report (or just its snapshot) from a real
Windows machine. The kernel pseudo-processes found in them must be protected exactly as the
backend produced them.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from ctx_factory import typical_context

from zerobirus.core.safety import is_protected_process

RECORDED = sorted(
    p
    for p in (Path(__file__).resolve().parents[1] / "fixtures" / "recorded").glob("*.json")
    if not p.name.endswith(".expected.json")
)
KERNEL_PSEUDO = ("System", "Registry", "Memory Compression")


def _processes() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for file in RECORDED:
        data = json.loads(file.read_text("utf-8"))
        found.extend(data.get("snapshot", data).get("processes", []))
    return found


@pytest.mark.parametrize("name", KERNEL_PSEUDO)
def test_recorded_kernel_pseudo_processes_are_protected(name: str) -> None:
    found = [p for p in _processes() if p["name"] == name]
    if not found:
        pytest.skip(f"no recorded fixture with a real {name} process yet (see recorded/README.md)")
    ctx = typical_context()
    for p in found:
        assert is_protected_process(p["name"], p["path"], ctx, pid=p["pid"])
