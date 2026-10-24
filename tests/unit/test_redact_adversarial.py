"""Adversarial tests for core/redact (Phase 0 audit)."""

import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zerobirus.core.redact import REDACTED, redact

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
MONERO = "4" + "A" * 94
INTEGRATED = "4" + "B" * 105
PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "-----END OPENSSH PRIVATE KEY-----"
)

_HEADERS = (
    "GET / HTTP/1.1\r\nAuthorization: Bearer SECRET1\r\n"
    "X-Api-Key: SECRET2\r\nCookie: sid=SECRET3\r\n"
)

HIDDEN = [
    # Command-line flags
    ("tool --password x --other", "x"),
    ("tool --password=hunter2", "hunter2"),
    ("tool --password 'a b c' --z", "a b c"),
    ('tool --password "hunter 2" --z', "hunter 2"),
    ('tool --password "unterminated secret', "unterminated"),
    ("tool -password=S3CRET", "S3CRET"),
    ("tool /password:S3CRET", "S3CRET"),
    ("tool /pass:S3CRET", "S3CRET"),
    ("tool /pwd=S3CRET", "S3CRET"),
    ("tool /p:S3CRET", "S3CRET"),
    ("tool --pass=S3CRET", "S3CRET"),
    ("7z a x.7z -pS3CRETPW", "S3CRETPW"),
    ('7z a x.7z -p"S3 CRET"', "S3 CRET"),
    ("xmrig -u wallet123 -p x1y2", "x1y2"),
    ("xmrig -u WALLETNAME.worker -p x", "WALLETNAME"),
    # Assignments and environment
    ("MYSQL_PWD=abc123", "abc123"),
    ("set DB_PASSWORD=abc123", "abc123"),
    ("mypassword=abc123", "abc123"),
    ("PASSWORD: abc123", "abc123"),
    ("client_secret=abc123", "abc123"),
    ("access_token=abc123", "abc123"),
    ("https://x.invalid/?token=abc123&x=1", "abc123"),
    ("api-key=abc123", "abc123"),
    # Headers, one or many lines
    ("Authorization: Bearer abc.def-ghi", "abc.def-ghi"),
    ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ("authorization=Bearer xyz123", "xyz123"),
    ("Proxy-Authorization: Basic Zm9vOmJhcg==", "Zm9vOmJhcg=="),
    (
        _HEADERS,
        "SECRET1",
    ),
    (
        _HEADERS,
        "SECRET2",
    ),
    (
        _HEADERS,
        "SECRET3",
    ),
    ("curl -H 'Authorization: Bearer abc123token' host", "abc123token"),
    ("sent bearer abcdefgh12345678 to host", "abcdefgh12345678"),
    # URLs with credentials
    ("https://user:s3cr3t@host.invalid/x", "s3cr3t"),
    ("ftp://u:p4ss@h.invalid", "p4ss"),
    ("postgres://admin:s3cr3t@db.invalid/x", "s3cr3t"),
    ("stratum+tcp://wallet:pw9@pool.invalid:3333", "pw9"),
    # JSON
    ('{"password":"s3cr3t"}', "s3cr3t"),
    ('{"password": "s3 cr3t"}', "s3 cr3t"),
    ("{'password': 's3cr3t'}", "s3cr3t"),
    ('{"api_key":"abc123"}', "abc123"),
    ('{"client_secret":"abc123"}', "abc123"),
    ('{"password":"a\\"b-SECRETTAIL"}', "SECRETTAIL"),
    ('{"token":"abc123","user":"x"}', "abc123"),
    # Known token formats
    ("ghp_" + "a1B2" * 9, "a1B2a1B2"),
    ("github_pat_" + "A1b2C3" * 8, "A1b2C3A1b2C3"),
    ("glpat-" + "x1Y2z3W4" * 3, "x1Y2z3W4"),
    ("xoxb-1234567890-abcdefghij", "1234567890-abcdefghij"),
    ("key AKIAIOSFODNN7EXAMPLE end", "AKIAIOSFODNN7EXAMPLE"),
    ("AIza" + "Sy" + "A" * 33, "SyAAAAAAAA"),
    ("sk-" + "proj1234567890abcdef12345", "proj1234567890abcdef12345"),
    ("npm_" + "A1b2C3d4" * 5, "A1b2C3d4A1b2C3d4"),
    (f"jwt {JWT} end", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
    # Second round: quoted header values, PowerShell secure strings, schtasks
    ('{"Authorization":"Basic dXNlcjpwYXNz"}', "dXNlcjpwYXNz"),
    ('{"Authorization": "Bearer abc"}', "abc"),
    ("{'Authorization': 'Basic Zm9vOmJhcg=='}", "Zm9vOmJhcg=="),
    ('{"Cookie":"sid=SECRET9; other=1"}', "SECRET9"),
    ('powershell -Password (ConvertTo-SecureString "plainPW1" -AsPlainText -Force)', "plainPW1"),
    ("ConvertTo-SecureString 'plainPW2' -AsPlainText -Force", "plainPW2"),
    ("ConvertTo-SecureString plainPW3 -AsPlainText -Force", "plainPW3"),
    ("schtasks /create /tn x /tr y /ru bob /rp rpSECRET", "rpSECRET"),
    # PEM
    (PEM, "b3BlbnNzaC1rZXktdjE"),
    ("x " + PEM.split("\n")[0] + "\nAAAAB3NzaC1yc2EAAAADAQABAAABgQC\n", "AAAAB3NzaC1yc2EAAAADAQAB"),
    # Wallets and blobs
    (f"xmrig -o pool -u {MONERO}", MONERO),
    (f"pay {INTEGRATED} now", INTEGRATED),
    ("btc 1BoatSLRHtKNngkdXEeobR76b53LETtpyT now", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
    (
        "btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq now",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    ),
    ("eth 0x" + "ab12" * 10, "ab12ab12ab12"),
    (
        "blob QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5 end",
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5",
    ),
    ("key " + "0123456789abcdef" * 5, "0123456789abcdef0123456789abcdef"),
]

KEPT = [
    f"sha256 {SHA256}",
    f"SHA256: {SHA256}",
    f"sha1={SHA1} md5={MD5}",
    f"hash:{SHA256}.",
    r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule",
    r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p",
    r"C:\Users\Ana\AppData\Local\Temp\kzqpxabcdefghijklmnopqrstuvwxyz0123456789\svc.exe",
    r"C:\Users\Ana\AppData\Roaming\Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8L9z0X1c2\run.dll",
    "C:/Users/Ana/AppData/Local/Temp/kzqpxabcdefghijklmnopqrstuvwxyz0123456789/svc.exe",
    r"C:\Program Files\Windows Defender\MsMpEng.exe",
    r"C:\Program Files\WindowsApps\Microsoft.WindowsStore_22308.1401.12.0_x64__8wekyb3d8bbwe\x.exe",
    "powershell -ExecutionPolicy Bypass -File x.ps1",
    "the token expired yesterday",
    "password reset required for the account",
    "the secret to success is passing tests",
    "compass=north bypass=1",
    "http://example.invalid/path/page.html",
    "{01234567-89ab-cdef-0123-456789abcdef}",
    "xmrig --donate-level 1 -o pool.invalid:3333 --threads=4",
    "[oculto]",
    "",
]


@pytest.mark.parametrize(("text", "secret"), HIDDEN, ids=lambda v: repr(v)[:50])
def test_secret_is_hidden(text: str, secret: str) -> None:
    out = redact(text)
    assert secret not in out, out
    assert REDACTED in out


@pytest.mark.parametrize("text", KEPT, ids=lambda v: repr(v)[:50])
def test_useful_information_survives(text: str) -> None:
    assert redact(text) == text


def test_context_is_kept_around_a_secret() -> None:
    assert redact("GET / HTTP/1.1\r\nAuthorization: Bearer S\r\nHost: x") == (
        "GET / HTTP/1.1\r\nAuthorization: " + REDACTED + "\r\nHost: x"
    )
    assert redact(r"C:\x\miner.exe --password=hunter2 --threads=4") == (
        r"C:\x\miner.exe --password=" + REDACTED + " --threads=4"
    )
    assert redact("https://u:pw@host.invalid/x") == f"https://u:{REDACTED}@host.invalid/x"


def test_pem_block_is_removed_completely() -> None:
    out = redact(f"before\n{PEM}\nafter")
    assert out == f"before\n{REDACTED}\nafter"


# ReDoS ---------------------------------------------------------------------------------

N = 200_000
SLOW = {
    "letters": "a" * N,
    "letters-then-scheme": "a" * N + "://",
    "scheme-like": "http" + "a" * N,
    "dash-p": "-p " * (N // 3),
    "dash-p-glued": "-pa" * (N // 3),
    "password-ws": "--password " * (N // 11),
    "password-eq": "password=" * (N // 9),
    "long-key-prefix": "a" * N + "password=x",
    "long-key-no-sep": "a" * N + "password",
    "spaces": " " * N,
    "colons": "x:" * (N // 2),
    "b64": "A1" * (N // 2),
    "b64-then-bang": "A1" * (N // 2) + "!",
    "b64-then-backslash": "A1" * (N // 2) + "\\",
    "hex": "0" * N,
    "hex-then-g": "0" * N + "g",
    "monero-ish": "4" + "1" * N,
    "authorization": "Authorization:" * (N // 14),
    "authorization-long": "Authorization: " + "x" * N,
    "pem-open": "-----BEGIN PRIVATE KEY-----" * (N // 27),
    "pem-long": "-----BEGIN PRIVATE KEY-----" + "A" * N,
    "url-user": "http://" + "u:" * (N // 2),
    "url-many": "a://b:" * (N // 6),
    "at": "a" * N + "@",
    "json": '"password":' * (N // 11),
    "backslashes": "\\" * N,
    "quotes": '-p "' * (N // 4),
    "bearer": "bearer " * (N // 7),
    "newlines": "\n" * N,
    "unicode": "\uff10" * N,
}


@pytest.mark.parametrize("name", list(SLOW))
def test_linear_time_on_adversarial_input(name: str) -> None:
    text = SLOW[name]
    start = time.perf_counter()
    redact(text)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.5, f"{name}: {elapsed:.2f}s for {len(text)} chars"


@given(st.text())
def test_redact_never_raises_and_is_idempotent(text: str) -> None:
    once = redact(text)
    assert redact(once) == once


@given(
    st.sampled_from(["--password ", "--password=", "/pwd:", "password=", '"password":"']),
    st.text(alphabet="XYZ0123456789!@#$%^&*()_+-=", min_size=1, max_size=30),
)
def test_generated_secrets_never_survive(prefix: str, secret: str) -> None:
    # The secret may share characters with the key name, so look only after the key.
    out = redact(f"tool {prefix}{secret}")
    tail = out[len("tool ") + len(prefix.rstrip('"')) :]
    assert secret not in tail
    assert REDACTED in tail


# Killers for surviving mutants (mutmut audit) -----------------------------------------

PATH_LIKE = "see Users/Ana/AppDataLocalTempkzqpxabcdefghijklmnopqrstuvwxyz/svc end"
SLASH_AND_DIGIT = "tok Ab/cdefghijklmnopqrstuvwxyzABCDEFGH1JKLMNOPQRSTUV end"
SLASH_AND_PLUS = "tok abcdefghij/klmnopqrst+uvwxyzABCDEFGHIJKLMNOPQRSTUV end"
DIGIT_NO_SLASH = "tok abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV1 end"
LETTERS_ONLY = "tok abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ end"


def test_slash_separated_name_without_digit_or_plus_is_kept() -> None:
    assert redact(PATH_LIKE) == PATH_LIKE


@pytest.mark.parametrize(
    "text", [SLASH_AND_DIGIT, SLASH_AND_PLUS, DIGIT_NO_SLASH, LETTERS_ONLY], ids=lambda t: t[4:24]
)
def test_token_like_blobs_are_hidden(text: str) -> None:
    assert redact(text) == "tok " + REDACTED + " end"
