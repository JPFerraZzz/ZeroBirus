import pytest

from zerobirus.core.psenv import PATHEXT, build_child_env

HOSTILE = {
    "PATH": r"C:\evil",
    "PATHEXT": ".EVIL",
    "COMSPEC": r"C:\evil\cmd.exe",
    "PSModulePath": r"C:\evil\Modules",
    "PSExecutionPolicyPreference": "Bypass",
    "POWERSHELL_TELEMETRY_OPTOUT": "1",
    "SystemRoot": r"C:\evil",
    "windir": r"C:\evil",
    "TEMP": r"C:\Users\Ana\AppData\Local\Temp",
    "USERNAME": "Ana",
    "RANDOM_THING": "x",
    "PROGRAMDATA": r"C:\ProgramData",
}


def test_nothing_that_chooses_what_runs_is_inherited() -> None:
    env = build_child_env("C:\\Windows", HOSTILE)
    assert env["SystemRoot"] == env["windir"] == "C:\\Windows"
    assert env["PATH"].startswith("C:\\Windows\\System32;")
    assert "evil" not in " ".join(env.values()).lower()
    assert env["PATHEXT"] == PATHEXT
    assert env["COMSPEC"] == "C:\\Windows\\System32\\cmd.exe"
    assert env["PSModulePath"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules"


def test_no_ps_variables_and_no_unknown_ones_get_through() -> None:
    env = build_child_env("C:\\Windows", HOSTILE)
    assert not [k for k in env if k.upper().startswith("PS") and k != "PSModulePath"]
    assert "POWERSHELL_TELEMETRY_OPTOUT" not in env
    assert "RANDOM_THING" not in env


def test_plain_user_variables_are_copied() -> None:
    env = build_child_env("C:\\Windows", HOSTILE)
    assert env["TEMP"] == r"C:\Users\Ana\AppData\Local\Temp"
    assert env["USERNAME"] == "Ana"
    assert env["PROGRAMDATA"] == r"C:\ProgramData"


@pytest.mark.parametrize("root", ["C:\\Windows", "C:\\Windows\\", "D:\\WINNT"])
def test_system_root_comes_from_the_argument_in_any_spelling(root: str) -> None:
    env = build_child_env(root, {})
    assert env["SystemRoot"] == root.rstrip("\\")
    assert env["SystemDrive"] == root[:2]
