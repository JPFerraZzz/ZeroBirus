"""The scoring configuration is pinned: changing a weight must be a visible test change."""

import pytest

from zerobirus.core.models import Level
from zerobirus.core.rules import load_rules

RULES = load_rules()


def test_thresholds_are_pinned() -> None:
    assert (RULES.conferir, RULES.suspeito) == (30, 100)


@pytest.mark.parametrize("code", sorted(RULES.signals))
def test_a_single_weak_signal_never_produces_suspeito(code: str) -> None:
    level = RULES.level((RULES.signal(code),))
    if RULES.signals[code].strong:
        assert level is Level.SUSPEITO
    else:
        assert level is not Level.SUSPEITO


@pytest.mark.parametrize("code", sorted(RULES.signals))
def test_every_signal_has_pt_pt_text_and_a_sane_weight(code: str) -> None:
    rule = RULES.signals[code]
    assert rule.text.endswith(".")
    assert -100 <= rule.weight <= 200


def test_signals_add_up_and_cross_thresholds_in_order() -> None:
    sig = RULES.signal
    assert RULES.level(()) is Level.OK
    assert RULES.level((sig("unsigned"),)) is Level.OK
    assert RULES.level((sig("unsigned"), sig("task_frequent"))) is Level.OK
    assert RULES.level((sig("writable_location"), sig("random_folder"))) is Level.CONFERIR
    many = tuple(
        sig(c)
        for c in (
            "persist_writable",
            "random_folder",
            "unsigned",
            "writable_location",
            "task_from_writable",
        )
    )
    assert sum(s.weight for s in many) >= RULES.suspeito
    assert RULES.level(many) is Level.SUSPEITO


def test_valid_signature_lowers_the_score_but_not_strong_evidence() -> None:
    sig = RULES.signal
    weak = (sig("writable_location"), sig("random_folder"), sig("valid_signature"))
    assert RULES.level(weak) is Level.OK
    strong = (sig("cmdline_miner_marker"), sig("valid_signature"), sig("valid_signature"))
    assert RULES.level(strong) is Level.SUSPEITO


def test_threat_tags_are_counted() -> None:
    sig = RULES.signal
    got = RULES.threats((sig("cmdline_miner_marker"), sig("high_cpu"), sig("unsigned")))
    assert got == {"minerador": 2}


def test_miner_indicators_are_lowercase() -> None:
    for item in (
        *RULES.strong_markers,
        *RULES.weak_markers,
        *RULES.pool_domains,
        *RULES.miner_names,
    ):
        assert item == item.lower()
