import json
import subprocess
import sys
from pathlib import Path

from zerobirus.core.privacy import find_personal_leftovers
from zerobirus.core.report import build_report
from zerobirus.platform.fake import FakeInspector
from zerobirus.scanners.runner import run_scan

TOOL = Path(__file__).resolve().parents[2] / "tools" / "report_to_fixture.py"


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - our own script, fixed interpreter, no shell
        [sys.executable, str(TOOL), *args], capture_output=True, text=True, check=False
    )


def write_report(tmp_path: Path, fixture: str) -> Path:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(build_report(run_scan(FakeInspector(fixture)))), "utf-8")
    return path


def test_a_clean_report_becomes_a_fixture_with_expected_verdicts(tmp_path: Path) -> None:
    report = write_report(tmp_path, "false_positives_pc")
    dest = tmp_path / "recorded"
    done = run_tool(str(report), "demo-fp", "--dest", str(dest))
    assert done.returncode == 0, done.stderr
    expected = json.loads((dest / "demo-fp.expected.json").read_text("utf-8"))
    assert expected["kind"] == "false-positive"
    assert expected["verdicts"] == [["services", "CONFERIR", "Acme Backup"]]
    assert (dest / "demo-fp.json").is_file()


def test_a_report_with_personal_data_left_is_refused_unless_forced(tmp_path: Path) -> None:
    report = write_report(tmp_path, "miner_pc")
    data = json.loads(report.read_text("utf-8"))
    data["snapshot"]["processes"][0]["cmdline"] = (
        r"notepad C:\Users\Joaquim\notes.txt joao@example.com"
    )
    report.write_text(json.dumps(data), "utf-8")
    refused = run_tool(str(report), "x", "--dest", str(tmp_path / "d"))
    assert refused.returncode == 1
    assert "Joaquim" in refused.stderr
    assert "e-mail" in refused.stderr
    assert not (tmp_path / "d").exists()
    forced = run_tool(
        str(report), "x", "--dest", str(tmp_path / "d"), "--force", "--kind", "detection"
    )
    assert forced.returncode == 0


def test_a_report_without_snapshot_is_a_clear_error(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"checks": []}), "utf-8")
    assert run_tool(str(path), "x").returncode == 2


def test_leftover_finder_accepts_placeholders_and_catches_real_names() -> None:
    clean = [
        r"C:\Users\Utilizador1\AppData\x",
        r"C:\Users\Public\a.exe",
        r"MAQUINA\Utilizador2",
        "NT AUTHORITY\\SYSTEM",
    ]
    assert find_personal_leftovers(clean) == []
    dirty = [r"C:\Users\Maria\Desktop", "a@b.pt", r"\\NAS01\share", "DESKTOP-AB12CD"]
    assert len(find_personal_leftovers(dirty)) == 4
