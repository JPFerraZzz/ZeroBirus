import pytest

from zerobirus.core.models import CheckResult, Finding, Level


def _finding(level: Level) -> Finding:
    return Finding(id="f", item="x", location="y", level=level, description="d")


def test_unverified_check_is_never_ok() -> None:
    result = CheckResult(check="wmi", verified=False, reason="sem administrador")
    assert result.level is Level.NAO_VERIFICADO


def test_unverified_check_must_state_reason() -> None:
    with pytest.raises(ValueError, match="why"):
        CheckResult(check="wmi", verified=False)


def test_empty_verified_check_is_ok() -> None:
    assert CheckResult(check="hosts").level is Level.OK


def test_level_is_worst_finding() -> None:
    result = CheckResult(
        check="run",
        findings=(_finding(Level.OK), _finding(Level.SUSPEITO), _finding(Level.CONFERIR)),
    )
    assert result.level is Level.SUSPEITO
