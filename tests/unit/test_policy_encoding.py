"""PowerShell scripts must be pure ASCII or UTF-8 with BOM (see .gitattributes)."""

import subprocess
from pathlib import Path

BOM = b"\xef\xbb\xbf"
ROOT = Path(__file__).resolve().parents[2]


def ps1_encoding_problem(data: bytes) -> str | None:
    """Return a description of the problem, or None if the file is acceptable."""
    if data.startswith(BOM):
        try:
            data[len(BOM) :].decode("utf-8")
        except UnicodeDecodeError:
            return "BOM present but content is not valid UTF-8"
        return None
    if data.isascii():
        return None
    return "non-ASCII bytes without UTF-8 BOM"


def test_ascii_passes() -> None:
    assert ps1_encoding_problem(b"Write-Output 'ok'\n") is None


def test_utf8_with_bom_passes() -> None:
    assert ps1_encoding_problem(BOM + "Write-Output 'ação'\n".encode()) is None


def test_utf8_without_bom_fails() -> None:
    assert ps1_encoding_problem("Write-Output 'ação'\n".encode()) is not None


def test_latin1_without_bom_fails() -> None:
    assert ps1_encoding_problem("Write-Output 'ação'\n".encode("latin-1")) is not None


def test_bom_with_invalid_utf8_fails() -> None:
    assert ps1_encoding_problem(BOM + b"\xff\xfe") is not None


def test_all_repository_ps1_files_are_valid() -> None:
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "*.ps1"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    problems = {}
    for rel in filter(None, listed.decode().split("\0")):
        problem = ps1_encoding_problem((ROOT / rel).read_bytes())
        if problem:
            problems[rel] = problem
    assert not problems
