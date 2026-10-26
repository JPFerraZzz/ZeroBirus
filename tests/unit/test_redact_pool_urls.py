"""One policy for URLs: attacker data that helps an investigation stays visible, anything
that may belong to the victim is hidden."""

import time

import pytest

from zerobirus.core.redact import REDACTED, redact

# A well-formed Monero main address shape (95 chars, starts with 4); synthetic.
WALLET = "4" + "A" * 94
SCHEMES = [
    "stratum+tcp",
    "stratum+ssl",
    "stratum+tls",
    "stratum+udp",
    "stratum2+tcp",
    "STRATUM+TCP",
]


@pytest.mark.parametrize("scheme", SCHEMES)
def test_stratum_user_and_host_stay_visible_and_the_password_is_hidden(scheme: str) -> None:
    out = redact(f"x.exe -o {scheme}://walletuser:s3cr3tpw@pool.exemplo:3333 --y")
    assert f"{scheme}://walletuser:{REDACTED}@pool.exemplo:3333" in out
    assert "s3cr3tpw" not in out


@pytest.mark.parametrize("scheme", SCHEMES)
def test_a_monero_wallet_as_stratum_user_stays_visible(scheme: str) -> None:
    out = redact(f"x.exe -o {scheme}://{WALLET}:x@pool.exemplo:3333")
    assert WALLET in out
    assert f":{REDACTED}@pool.exemplo:3333" in out


def test_wallet_with_worker_name_and_no_password_stays_visible() -> None:
    assert redact(f"stratum+tcp://{WALLET}.rig01@pool.exemplo:3333") == (
        f"stratum+tcp://{WALLET}.rig01@pool.exemplo:3333"
    )


def test_the_same_wallet_outside_a_stratum_url_is_still_hidden() -> None:
    assert WALLET not in redact(f"tool.exe --address {WALLET}")
    assert WALLET not in redact(f"https://{WALLET}:x@pool.exemplo/")
    assert WALLET not in redact(f"-u {WALLET}")


def test_non_stratum_urls_hide_user_and_password() -> None:
    out = redact("curl https://alice:hunter2@example.invalid:8443/p")
    assert "alice" not in out
    assert "hunter2" not in out
    assert "example.invalid:8443" in out


@pytest.mark.parametrize("scheme", ["http", "ftp", "ssh", "wss", "socks5"])
def test_every_other_scheme_hides_the_user_even_without_a_password(scheme: str) -> None:
    assert "alice" not in redact(f"{scheme}://alice@h.invalid/")


def test_a_stratum_user_that_is_not_plain_text_is_hidden() -> None:
    out = redact("stratum+tcp://a%20b:x@pool.exemplo:3333")
    assert out == f"stratum+tcp://{REDACTED}:{REDACTED}@pool.exemplo:3333"


def test_a_stratum_user_that_looks_like_a_token_is_not_trusted_just_for_the_scheme() -> None:
    out = redact("stratum+tcp://ghp_" + "a" * 36 + ":x@pool.exemplo:3333")
    assert "ghp_" in out  # plain characters, kept as a possible wallet or worker name
    assert f":{REDACTED}@" in out


def test_stratum_url_without_credentials_is_untouched() -> None:
    assert redact("stratum+tcp://pool.exemplo:3333") == "stratum+tcp://pool.exemplo:3333"


def test_idempotent_and_private_use_characters_in_the_input_cannot_forge_a_restore() -> None:
    once = redact(f"stratum+tcp://{WALLET}:x@p.exemplo:1")
    assert redact(once) == once
    forged = "0 password=hunter2"
    out = redact(forged)
    assert "hunter2" not in out
    assert "" not in out


def test_other_secrets_next_to_a_stratum_url_are_still_hidden() -> None:
    out = redact(f"x.exe -o stratum+tcp://{WALLET}:x@p.exemplo:3333 --password hunter2 -p s3cr3t")
    assert "hunter2" not in out
    assert "s3cr3t" not in out
    assert WALLET in out


def test_stratum_pattern_is_linear_on_hostile_input() -> None:
    hostile = [
        "stratum+tcp://" + "a:" * 100_000,
        "stratum+tcp://" + "a" * 200_000,
        "stratum+tcp://:" * 20_000,
    ]
    started = time.perf_counter()
    for text in hostile:
        redact(text)
    assert time.perf_counter() - started < 5
