"""Secret redaction. Applied before any output, log or report.

Every pattern is written to run in linear time on hostile input: unbounded runs are
anchored with look-behinds so the engine cannot restart inside them, and nothing nests a
quantifier inside another. ``tests/unit/test_redact_adversarial.py`` measures this.

Principle: over-redacting a flag value is acceptable, leaking a secret is not. Two things
are deliberately kept visible: file hashes (32, 40 and 64 hex digits, which reports must
show) and path components (a random 40+ character folder name in AppData is exactly the
kind of evidence that must survive).
"""

from __future__ import annotations

import re
from collections.abc import Callable

REDACTED = "[oculto]"

# A value: quoted (with escapes), unterminated quote up to end of line, or a bare run.
_VALUE = r"""(?:"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)*'|"[^"\r\n]*|'[^'\r\n]*|[^\s"']+)"""
_SEP = r"""["']?[ \t]*[=:][ \t]*"""
# A header value: quoted string (JSON) or the rest of the line up to a quote.
_HEADER_VALUE = r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n"']*)"""

# Names that are secret wherever they appear in an identifier (db_password, mypassword).
_LONG_KEYS = (
    r"(?:password|passwd|passphrase|secret|token|api[-_]?key|credentials?|"
    r"private[-_]?key|access[-_]?key|bearer)"
)
# Short names: only as a whole word or after an underscore/dash/dot (MYSQL_PWD, --pass).
_SHORT_KEYS = r"(?:pass|pwd|pw|auth)"

_FLAG_KEYS = rf"(?:{_LONG_KEYS}|{_SHORT_KEYS})"


def _sub_value(m: re.Match[str]) -> str:
    return m.group("pre") + REDACTED


def _sub_url(m: re.Match[str]) -> str:
    return m.group("pre") + REDACTED + m.group("post")


def _sub_all(_: re.Match[str]) -> str:
    return REDACTED


_HASH_RE = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")


def _sub_hex_blob(m: re.Match[str]) -> str:
    # File hashes (MD5, SHA-1, SHA-256) are shown in reports so the user can look them up.
    return m.group(0) if _HASH_RE.fullmatch(m.group(0)) else REDACTED


def _sub_b64_blob(m: re.Match[str]) -> str:
    text = m.group(0)
    if _HASH_RE.fullmatch(text):
        return text
    # Random base64 of this length has a digit with near certainty. A slash-separated run
    # with no digit or '+' is a path-like name, not a token.
    if "/" in text and not any(c.isdigit() or c == "+" for c in text):
        return text
    return REDACTED


_PATTERNS: tuple[tuple[re.Pattern[str], Callable[[re.Match[str]], str]], ...] = (
    # PEM private keys, complete or truncated (then up to the end of the text).
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)"
        ),
        _sub_all,
    ),
    # URL credentials: scheme://user:pass@host (start anchored to the scheme's first letter).
    (
        re.compile(
            r"(?<![A-Za-z0-9+.-])(?P<pre>[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]*:)"
            r"[^\s/@]+(?P<post>@)"
        ),
        _sub_url,
    ),
    # Authorization-style headers: the rest of the line (or up to a quote).
    (
        re.compile(
            r"(?P<pre>(?<![A-Za-z0-9])(?:proxy-)?authorization[\"']?[ \t]*[=:][ \t]*)"
            + _HEADER_VALUE,
            re.IGNORECASE,
        ),
        _sub_value,
    ),
    (
        re.compile(
            r"(?P<pre>(?<![A-Za-z0-9])(?:set-)?cookie[\"']?[ \t]*:[ \t]*)" + _HEADER_VALUE,
            re.IGNORECASE,
        ),
        _sub_value,
    ),
    # A bare bearer credential.
    (
        re.compile(r"(?P<pre>(?<![A-Za-z0-9])bearer[ \t]+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
        _sub_value,
    ),
    # PowerShell secure strings: the plain text sits in the argument, not behind a flag.
    (
        re.compile(
            r"(?P<pre>(?<![A-Za-z0-9])convertto-securestring[ \t]+(?:-string[ \t]+)?)" + _VALUE,
            re.IGNORECASE,
        ),
        _sub_value,
    ),
    # schtasks /RP password
    (re.compile(r"(?P<pre>(?<![\w-])[-/]rp[ \t]+)(?!-)" + _VALUE, re.IGNORECASE), _sub_value),
    # Flags: --password x, -pass x, /pwd:x (whitespace separator only after a flag marker).
    (
        re.compile(
            rf"(?P<pre>(?<![A-Za-z0-9])(?:--?|/){_FLAG_KEYS}(?:{_SEP}|[ \t]+))" + _VALUE,
            re.IGNORECASE,
        ),
        _sub_value,
    ),
    # Assignments, with an optional identifier prefix: db_password=x, "api_key":"x".
    (
        re.compile(
            rf"(?P<pre>(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]*?{_LONG_KEYS}{_SEP})" + _VALUE,
            re.IGNORECASE,
        ),
        _sub_value,
    ),
    (
        re.compile(
            rf"(?P<pre>(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9]+[_.-])*{_SHORT_KEYS}{_SEP})" + _VALUE,
            re.IGNORECASE,
        ),
        _sub_value,
    ),
    # /p:x
    (re.compile(rf"(?P<pre>(?<![\w/])/p{_SEP})" + _VALUE, re.IGNORECASE), _sub_value),
    # Short flags: -p x / -u x (value must not look like another flag), and glued -pSECRET.
    (re.compile(r"(?P<pre>(?<![\w-])-[pu][ \t]+)(?!-)" + _VALUE), _sub_value),
    (re.compile(r"(?P<pre>(?<![\w-])-p)(?=[^\s-]{3})" + _VALUE), _sub_value),
    # Well-known token formats.
    (
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
            r"|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}"
            r"|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}"
            r"|sk-[A-Za-z0-9_-]{20,}|[sr]k_live_[A-Za-z0-9]{16,}"
            r"|npm_[A-Za-z0-9]{30,}|hf_[A-Za-z0-9]{30,}"
            r"|eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*)"
        ),
        _sub_all,
    ),
    # Monero (standard 95 chars, integrated 106) and other long base58 wallet addresses.
    (
        re.compile(
            r"(?<![A-Za-z0-9])[48](?:[1-9A-HJ-NP-Za-km-z]{94}|[1-9A-HJ-NP-Za-km-z]{105})"
            r"(?![A-Za-z0-9])"
        ),
        _sub_all,
    ),
    # Bitcoin and Ethereum style addresses.
    (
        re.compile(
            r"(?<![A-Za-z0-9\\/._-])(?:bc1[a-z0-9]{25,60}|[13][1-9A-HJ-NP-Za-km-z]{25,34}"
            r"|0x[0-9a-fA-F]{40})(?![A-Za-z0-9\\/_-])"
        ),
        _sub_all,
    ),
    # Long hex blobs (keys): 40+ hex digits, except exact hash lengths.
    (re.compile(r"(?<![A-Za-z0-9\\/._-])[0-9a-fA-F]{40,}(?![A-Za-z0-9\\/_-])"), _sub_hex_blob),
    # Long base64-like blobs, never when part of a path (no path character on either side).
    (
        re.compile(r"(?<![A-Za-z0-9+/_.:\\=-])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/_\\-])"),
        _sub_b64_blob,
    ),
)


def redact(text: str) -> str:
    """Return ``text`` with secrets replaced by ``[oculto]``."""
    for pattern, handler in _PATTERNS:
        text = pattern.sub(handler, text)
    return text
