"""The five-level risk table (D-015): thresholds, ordering and the guard rails."""

import pytest

from zerobirus.core.models import Signal
from zerobirus.core.risk import Risk, load_risk_rules, risk_of_signals
from zerobirus.core.rules import load_rules

RULES = load_rules()


def sig(*codes: str) -> tuple[Signal, ...]:
    return tuple(RULES.signal(c) for c in codes)


def test_every_signal_has_a_family() -> None:
    assert set(RULES.signals) <= set(load_risk_rules().families)


def test_levels_are_ordered_and_only_the_top_two_are_preselected() -> None:
    assert [r.rank for r in Risk] == [0, 1, 2, 3, 4]
    assert [r.label for r in Risk] == ["Incomum", "Anómalo", "Suspeito", "Grave", "Crítico"]
    assert [r for r in Risk if r.preselected] == [Risk.GRAVE, Risk.CRITICO]


@pytest.mark.parametrize(
    ("codes", "expected"),
    [
        ((), None),
        (("task_frequent",), Risk.INCOMUM),  # 10
        (("unsigned",), Risk.INCOMUM),  # 15
        (("writable_location", "unsigned"), Risk.ANOMALO),  # 35
        (("cmdline_miner_weak",), Risk.ANOMALO),  # 30
        (("task_from_writable",), Risk.SUSPEITO),  # 60
        (("cmdline_pool_domain",), Risk.SUSPEITO),  # one strong signal, one family
        (("cmdline_pool_domain", "writable_location"), Risk.GRAVE),  # strong + a second family
        (("cmdline_miner_marker", "cmdline_pool_domain"), Risk.GRAVE),  # two strong, 2 families
        (
            ("cmdline_miner_marker", "cmdline_pool_domain", "persist_writable"),
            Risk.CRITICO,
        ),  # two strong, three families
    ],
)
def test_golden_levels(codes: tuple[str, ...], expected: Risk | None) -> None:
    got = risk_of_signals(sig(*codes))
    assert got is expected


def test_a_valid_signature_lowers_a_weak_score_but_never_hides_a_strong_signal() -> None:
    assert risk_of_signals(sig("unsigned", "valid_signature")) is None
    strong = risk_of_signals(sig("cmdline_miner_marker", "valid_signature"))
    assert strong is not None
    assert strong.rank >= Risk.SUSPEITO.rank


def test_weak_signals_alone_never_pass_suspeito() -> None:
    weak = [c for c, r in RULES.signals.items() if not r.strong and r.weight > 0]
    risk = risk_of_signals(sig(*weak))
    assert risk is Risk.SUSPEITO


def test_every_strong_signal_alone_is_at_least_suspeito() -> None:
    for code, rule in RULES.signals.items():
        if rule.strong:
            risk = risk_of_signals(sig(code))
            assert risk is not None, code
            assert risk.rank >= Risk.SUSPEITO.rank, code


def test_golden_distribution_of_the_synthetic_miner_machine() -> None:
    from collections import Counter

    from zerobirus.core.models import Level
    from zerobirus.core.risk import risk_of
    from zerobirus.platform.fake import FakeInspector
    from zerobirus.scanners.runner import run_scan

    result = run_scan(FakeInspector("miner_pc"))
    counts = Counter(
        risk_of(f) for c in result.checks for f in c.findings if f.level is not Level.OK
    )
    assert counts == {Risk.CRITICO: 1, Risk.GRAVE: 4, Risk.SUSPEITO: 3, Risk.ANOMALO: 3}
