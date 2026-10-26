"""Indicators of compromise taken from original (unredacted) strings.

Only what the redaction policy deliberately keeps visible: the pool address and the user or
wallet of a stratum URL. Passwords are never read here. The values are validated against a
strict character set, so nothing else can ride along.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

_STRATUM = re.compile(
    r"(?<![A-Za-z0-9+.-])(?P<scheme>stratum\d*\+(?:tcp|ssl|tls|udp))://"
    r"(?:(?P<user>[A-Za-z0-9._-]{1,256})(?::[^\s/@]*)?@)?"
    r"(?P<host>[A-Za-z0-9._-]{1,253})(?::(?P<port>\d{1,5}))?",
    re.IGNORECASE,
)
_WALLET_LIKE = re.compile(r"[A-Za-z0-9]{26,}")


@dataclass(frozen=True, slots=True)
class Indicator:
    kind: str
    value: str
    scheme: str


def extract_pool_indicators(texts: Iterable[str]) -> list[Indicator]:
    """Pool addresses and pool users or wallets from stratum URLs, without duplicates."""
    found: dict[tuple[str, str], Indicator] = {}
    for text in texts:
        for m in _STRATUM.finditer(text):
            scheme = m.group("scheme").lower()
            host = m.group("host").lower()
            port = m.group("port")
            address = f"{host}:{port}" if port and 0 < int(port) < 65536 else host
            found.setdefault(("pool", address), Indicator("pool", address, scheme))
            user = m.group("user")
            if user:
                base = user.split(".", 1)[0]
                kind = "wallet" if _WALLET_LIKE.fullmatch(base) else "pool_user"
                found.setdefault((kind, user), Indicator(kind, user, scheme))
    return list(found.values())
