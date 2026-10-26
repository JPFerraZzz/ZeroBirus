"""Every mining indicator carries its provenance, and an unverified one can never make
something SUSPEITO on its own (BRIEF: no source means "não verificado" and weighs less)."""

import re

import pytest

from zerobirus.core.models import Level
from zerobirus.core.rules import load_rules
from zerobirus.scanners.common import command_signals

RULES = load_rules()
ALL = [(kind, i) for kind, items in RULES.indicators.items() for i in items]
URL = re.compile(r"^https://[^\s]+$")


@pytest.mark.parametrize(("kind", "item"), ALL, ids=lambda v: str(getattr(v, "value", v)))
def test_every_verified_indicator_names_public_https_sources(kind: str, item: object) -> None:
    from zerobirus.core.rules import Indicator

    assert isinstance(item, Indicator)
    if item.verified:
        assert item.sources
        assert all(URL.match(s) for s in item.sources)
    else:
        assert item.sources == ()
        assert item.note


def test_the_indicator_lists_are_not_empty_and_the_unverified_ones_are_known() -> None:
    assert RULES.mining_ports == {3333}
    assert RULES.mining_ports_unverified >= {4444, 5555, 7777, 14444}
    assert "supportxmr.com" in RULES.pool_domains_unverified
    assert "nanopool.org" in RULES.pool_domains
    assert {"xmrig", "nbminer", "t-rex"} <= RULES.miner_names
    assert "phoenixminer" in RULES.miner_names_unverified
    assert "randomx" in RULES.strong_markers_unverified
    assert "stratum+tcp://" in RULES.strong_markers


@pytest.mark.parametrize("marker", sorted(RULES.strong_markers_unverified))
def test_an_unverified_command_line_marker_is_never_suspect_alone(marker: str) -> None:
    signals = tuple(command_signals(f"tool.exe {marker}", RULES))
    assert signals
    assert RULES.level(signals) is not Level.SUSPEITO
    assert not any(RULES.is_strong(s) for s in signals)


@pytest.mark.parametrize("domain", sorted(RULES.pool_domains_unverified))
def test_an_unverified_pool_domain_is_never_suspect_alone(domain: str) -> None:
    signals = tuple(command_signals(f"tool.exe -o {domain}:443", RULES))
    assert signals
    assert RULES.level(signals) is not Level.SUSPEITO


@pytest.mark.parametrize("domain", sorted(RULES.pool_domains))
def test_a_verified_pool_domain_in_a_command_line_is_strong(domain: str) -> None:
    signals = tuple(command_signals(f"tool.exe -o {domain}:443", RULES))
    assert RULES.level(signals) is Level.SUSPEITO


def test_unverified_signals_are_all_weak() -> None:
    for code in (
        "cmdline_miner_unverified",
        "miner_process_name_unverified",
        "mining_port_unverified_writable",
        "mining_port_unverified_other",
    ):
        assert not RULES.signals[code].strong
        assert RULES.signals[code].weight < RULES.suspeito
