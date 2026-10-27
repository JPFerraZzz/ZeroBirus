# ZeroBirus

*by Ferraz*

A portable tool for Windows 10 and 11 (x64) that guides you step by step through detecting and removing crypto miners, trojans and other malware. It is designed to run from a repair USB stick, with no installation and no internet connection.

**Status: Alpha 1.0, the first official release. All seven stages work. It was tested on a Windows CI runner and by one manual run on a real Windows PC (Temp cleaning: quarantine, undo, permanent delete). The firewall block, the Defender scan and the post-restart check have not been tried on real Windows. Next: a simpler cleaning and optimisation mode for gamers, see `docs/ROADMAP.md`.**

## How it works

1. **Context**: what did you notice? (only reorders the checks)
2. **Scan** (read-only): processes, startup entries, scheduled tasks, services, executables in writable folders, network connections, Microsoft Defender, hosts file, WMI subscriptions.
3. **Diagnosis**: every finding is OK, CONFERIR, SUSPEITO or NAO_VERIFICADO, with the reasons. A check that could not run is never OK.
4. **Authorisation**: you pick exactly what may change. The plan is saved on the Desktop before anything happens.
5. **Removal**: restore point, undo records, then only the authorised items, each one verified by re-reading the system. Removing means moving to quarantine; every item can be undone. Optional: move old Temp files to quarantine too.
6. **Confirmation**: repeat the scan and see the difference; follow a Microsoft Defender full scan (end detected from Defender events); restart check.
7. **After**: password and reformat advice, final report, optional cleanup of the work folder.

Run the built version from a ZIP (see `LEIA-ME.txt` inside it), or from source: `uv sync --locked`, `uv run zerobirus gui` (window), `uv run zerobirus scan --demo` (synthetic data, works on Linux).

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

## Read-only scan (Phase 1)

`zerobirus scan` inspects the machine and changes nothing: processes, startup entries, scheduled tasks, services, executables in user-writable folders, miner-pool connections, Microsoft Defender, the hosts file and WMI subscriptions. Every check ends as OK, CONFERIR (check), SUSPEITO (suspicious) or NAO_VERIFICADO (not verified); a check that could not run is never reported as OK. `--json --out FILE` writes a report with secrets redacted and user names replaced, safe to share after you read it. See `docs/DETECTION.md` and `docs/WINDOWS_TEST_PLAN.md`.

```
uv run zerobirus scan --demo            # synthetic data, works on Linux
uv run zerobirus scan --json --out report.json   # Windows only
```

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
