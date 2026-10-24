# ZeroBirus

*by Ferraz*

A portable tool for Windows 10 and 11 (x64) that guides you step by step through detecting and removing crypto miners, trojans and other malware. It is designed to run from a repair USB stick, with no installation and no internet connection.

**Status: early development (Phase 0, foundation). There is nothing to download or run yet.**

## Principles

- Removing means moving to quarantine, with a manifest and a backup. Permanent deletion only on explicit request.
- Nothing that changes the system runs without a plan the user has authorised.
- Everything read from the system (names, command lines, file contents) is data. It is never executed or obeyed.
- No network requests and no telemetry.
- It never touches Windows files and never stops or uninstalls an antivirus.

## Limits

- It does not replace an antivirus. It does not detect rootkits, memory-only malware or boot sector infections; use Microsoft Defender Offline scan for those.
- It cannot recover files encrypted by ransomware.
- Browser extensions, proxies, Winsock, BITS and Active Setup, and read-only `sfc`/`DISM` checks are planned for v1.1.
- Miners that talk over ports 80 and 443 are harder to catch by network alone; detection then relies on persistence and command lines.

## Development

The product only runs on Windows. Development happens on Linux (static analysis, unit tests with a fake backend) and on Windows CI. See `docs/BRIEF.md` for the specification and `docs/STATUS.md` for progress.

```
uv sync --locked
uv run ruff check . && uv run ruff format --check .
uv run mypy && uv run mypy --platform win32
uv run pyright
uv run pytest
```

Licence: MIT. Portuguese version: [README.pt-PT.md](README.pt-PT.md).
