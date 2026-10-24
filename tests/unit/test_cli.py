import pytest

from zerobirus import __version__
from zerobirus.cli import main


def test_version_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_selftest_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["selftest"]) == 0
    assert "selftest: ok" in capsys.readouterr().out


def test_no_command_prints_help() -> None:
    assert main([]) == 2
