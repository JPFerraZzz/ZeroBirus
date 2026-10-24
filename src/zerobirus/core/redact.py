"""Secret redaction. Applied before any output, log or report."""

from __future__ import annotations

import re

REDACTED = "[oculto]"

_PATTERNS: tuple[re.Pattern[str], ...] = (
    # URL credentials: scheme://user:pass@host
    re.compile(r"(?P<pre>[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]*:)[^\s/@]+(?P<post>@)"),
    # Authorization header values
    re.compile(
        r"(?P<pre>\bauthorization\s*[:=]\s*(?:bearer|basic|token)?\s*)[^\s\"']+",
        re.IGNORECASE,
    ),
    # --password=x, --password x, /password:x, pass=, pwd=, token=, secret=, api-key=, ...
    re.compile(
        r"(?P<pre>(?:--?|/)?(?:password|passwd|pass|pwd|token|secret|api[-_]?key|apikey|auth)"
        r"(?:\s*[=:]\s*|\s+))(?:\"[^\"]*\"|'[^']*'|[^\s\"']+)",
        re.IGNORECASE,
    ),
    # Short -p <value> (miners and tools commonly use -p for the pool password)
    re.compile(r"(?P<pre>(?<![\w-])-p\s+)(?:\"[^\"]*\"|'[^']*'|[^\s\"']+)"),
    # -u wallet.worker style user argument
    re.compile(r"(?P<pre>(?<![\w-])-u\s+)(?:\"[^\"]*\"|'[^']*'|[^\s\"']+)"),
    # Monero (95 chars, starts with 4 or 8) and similar long base58 wallet addresses
    re.compile(r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b"),
    # Bitcoin / Ethereum style addresses
    re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|0x[0-9a-fA-F]{40})\b"),
    # Long hex blobs (keys, hashes used as tokens): 40+ hex chars
    re.compile(r"\b[0-9a-fA-F]{40,}\b"),
    # Long base64 blobs: 40+ chars of the base64 alphabet
    re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/])"),
)


_HASH_RE = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")


def _blob(match: re.Match[str]) -> str:
    # File hashes (MD5, SHA-1, SHA-256) are shown in reports so the user can look them up.
    return match.group(0) if _HASH_RE.fullmatch(match.group(0)) else REDACTED


def redact(text: str) -> str:
    """Return ``text`` with secrets replaced by ``[oculto]``."""
    for pattern in _PATTERNS:
        if "pre" in pattern.groupindex:
            post = r"\g<post>" if "post" in pattern.groupindex else ""
            text = pattern.sub(rf"\g<pre>{REDACTED}{post}", text)
        else:
            text = pattern.sub(_blob, text)
    return text
