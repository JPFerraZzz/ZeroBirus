import pytest

from zerobirus.core.redact import REDACTED, redact

MONERO = "4" + "A" * 94
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("miner.exe --password=hunter2", "hunter2"),
        ("miner.exe --password hunter2 --threads 2", "hunter2"),
        ('tool.exe /password:"my secret"', "my secret"),
        ("xmrig -o pool.example.invalid:3333 -u wallet1 -p x", "wallet1"),
        ("curl -H 'Authorization: Bearer abc123token' host", "abc123token"),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("git clone https://user:s3cr3t@host.invalid/repo", "s3cr3t"),
        ("tool --token=ghp_abcdef123456", "ghp_abcdef123456"),
        ("tool --api-key=KEY123", "KEY123"),
        (f"xmrig -u {MONERO}", MONERO),
        ("send 0x" + "ab" * 20, "ab" * 20),
        ("key=" + "0123456789abcdef" * 4 + "ff", "0123456789abcdef" * 4),
        ("blob " + "QUJD" * 20, "QUJD" * 20),
    ],
)
def test_secrets_are_hidden(raw: str, secret: str) -> None:
    out = redact(raw)
    assert secret not in out
    assert REDACTED in out


def test_non_stratum_url_hides_user_and_password_and_keeps_host() -> None:
    assert (
        redact("https://user:pw@host.invalid/x") == f"https://{REDACTED}:{REDACTED}@host.invalid/x"
    )
    assert redact("ssh://git@host.invalid/x") == f"ssh://{REDACTED}@host.invalid/x"


def test_plain_text_untouched() -> None:
    text = r"C:\Windows\System32\svchost.exe -k netsvcs"
    assert redact(text) == text


def test_file_hash_is_kept() -> None:
    assert redact(f"sha256 {SHA256}") == f"sha256 {SHA256}"


def test_redact_is_idempotent() -> None:
    once = redact("miner --password=hunter2 https://u:p@h/")
    assert redact(once) == once
