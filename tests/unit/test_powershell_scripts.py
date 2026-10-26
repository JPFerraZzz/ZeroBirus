"""The PowerShell scripts are read-only by construction. Checked statically, on any OS."""

import re
from pathlib import Path

import pytest

SCRIPTS = sorted(
    (Path(__file__).resolve().parents[2] / "src/zerobirus/platform/windows/scripts").glob("*.ps1")
)
# Verbs that change state or run things. Get-*, ConvertTo-*, ConvertFrom-*, ForEach-Object and
# New-Object (only for the WScript.Shell COM object that reads shortcuts) are what scripts use.
FORBIDDEN = re.compile(
    r"\b(?:Set|Remove|Add|Start|Stop|Invoke|Clear|Move|Copy|Rename|Register|Unregister|Enable|"
    r"Disable|Install|Uninstall|Restart|Update|Out|Export|Import|Send|Write|Push|Reset|Grant|"
    r"Revoke|Block|Unblock|Suspend|Resume|Wait|Save|Edit)-[A-Za-z]+|"
    r"\bNew-(?!Object\b)[A-Za-z]+|\biex\b|\bInvoke-Expression\b|\bAdd-Type\b|Reflection\.|"
    r"\bDownloadString\b|\bWebClient\b|\bNet\.Sockets\b",
    re.IGNORECASE,
)


def test_scripts_exist() -> None:
    assert {p.stem for p in SCRIPTS} >= {"signatures", "tasks", "defender", "wmi", "shortcuts"}


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_has_no_state_changing_or_executing_commands(script: Path) -> None:
    text = script.read_text("ascii")
    assert FORBIDDEN.findall(text) == []


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_sets_result_and_reads_input_only_from_params(script: Path) -> None:
    text = script.read_text("ascii")
    assert "$result" in text
    assert "$Input" not in text
    assert "$args" not in text


@pytest.mark.parametrize(
    "line",
    [
        "Set-Content x y",
        "Remove-Item x",
        "Invoke-Expression $x",
        "iex $x",
        "New-Item x",
        "Start-Process x",
        "Out-File x",
        "Add-MpPreference -ExclusionPath x",
        "[System.Reflection.Assembly]::Load($b)",
    ],
)
def test_selftest_forbidden_detector_catches(line: str) -> None:
    assert FORBIDDEN.search(line)


@pytest.mark.parametrize(
    "line",
    [
        "Get-ScheduledTask",
        "ConvertTo-Json -InputObject @($x)",
        "New-Object -ComObject WScript.Shell",
    ],
)
def test_selftest_forbidden_detector_allows_reading(line: str) -> None:
    assert not FORBIDDEN.search(line)
