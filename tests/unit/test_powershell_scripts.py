"""The PowerShell scripts are read-only by construction. Checked statically, on any OS."""

import re
from pathlib import Path

import pytest

ALL_SCRIPTS = sorted(
    (Path(__file__).resolve().parents[2] / "src/zerobirus/platform/windows/scripts").glob("*.ps1")
)
# remediate.ps1 is the one script that changes state (stage 4). It has its own, stricter test.
SCRIPTS = [p for p in ALL_SCRIPTS if p.stem != "remediate"]
REMEDIATE = next(p for p in ALL_SCRIPTS if p.stem == "remediate")
# Every state-changing cmdlet remediate.ps1 may use, and nothing else.
REMEDIATE_ALLOWED = frozenset(
    c.lower()
    for c in (
        "Checkpoint-Computer",
        "Unregister-ScheduledTask",
        "Register-ScheduledTask",
        "Export-ScheduledTask",
        "Stop-Service",
        "Set-Service",
        "Remove-CimInstance",
        "New-CimInstance",
        "Remove-MpPreference",
        "Add-MpPreference",
        "New-NetFirewallRule",
        "Remove-NetFirewallRule",
        "Out-Result",
        "Out-Null",
        "Start-Sleep",
    )
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
    assert {p.stem for p in ALL_SCRIPTS} >= {
        "signatures",
        "tasks",
        "defender",
        "wmi",
        "shortcuts",
        "remediate",
    }


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


def test_remediate_script_uses_only_the_expected_state_changing_commands() -> None:
    text = REMEDIATE.read_text("ascii")
    used = {m.lower() for m in FORBIDDEN.findall(text)}
    assert used <= REMEDIATE_ALLOWED, used - REMEDIATE_ALLOWED


@pytest.mark.parametrize(
    "bad",
    [
        r"\biex\b",
        r"Invoke-Expression",
        r"Invoke-Command",
        r"Invoke-WebRequest",
        r"Start-Process",
        r"Add-Type",
        r"Remove-Item",
        r"Set-Content",
        r"Set-ItemProperty",
        r"Reflection\.",
        r"-EncodedCommand",
        r"\$Input",
        r"\$args",
        r"\[scriptblock\]",
        r"\.Invoke\(",
    ],
)
def test_remediate_script_never_evaluates_data_or_touches_files(bad: str) -> None:
    assert not re.search(bad, REMEDIATE.read_text("ascii"), re.IGNORECASE)


def test_remediate_script_picks_its_action_from_a_fixed_list() -> None:
    text = REMEDIATE.read_text("ascii")
    assert "default { throw 'unknown action' }" in text
    assert "$result" in text
