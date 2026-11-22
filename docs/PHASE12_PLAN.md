# Phase 12 plan: release 1.1 (draft, not started)

Source: ROADMAP row 12 and BRIEF section on false positives. Nothing here is implemented or
verified. Starts only after the manual Windows test of phases 6 to 11 and the João's OK.

## Scope

1. **Optional installer.** Per-user or per-machine install, uninstall entry, no auto-update, no network.
   Decided: MSI built with WiX (D-023, 2026-11-18). Per-user vs per-machine still open.
2. **Code signing.** SignPath Foundation (free for open source). Eligibility and onboarding
   requirements are **not confirmed**; check the programme's current terms before relying on it.
   Signing must happen in CI from a tagged release, never with a key on a developer machine.
3. **Microsoft false-positive submission.** Submit the signed ZIP and installer through
   Microsoft's security intelligence submission form after each release. This is a manual
   step done by the João; the repository only documents it in `docs/RELEASING.md`.
4. **D-021 follow-up.** Optionally replace `ZeroBirus-FirstSetup.cmd` with a signed `.exe`
   built from a fixed template, with the app list as data. Only if signing works.

## Work breakdown

| Step | Output | Verified by |
| --- | --- | --- |
| A. Installer technology | decided: MSI with WiX, D-023 | João (done) |
| B. Installer definition and build job | installer artefact in CI | windows-latest run (install, launch, uninstall in a throwaway runner) |
| C. Signing in `release.yml` | signed ZIP and installer, provenance attestation | CI log; `Get-AuthenticodeSignature` on the artefact |
| D. `docs/RELEASING.md` | checklist incl. Microsoft submission | review |
| E. Windows test plan update | install/uninstall cases | João on real Windows or VM |

## Constraints carried over from CLAUDE.md

- The product still makes zero network requests; the installer must not either.
- Never claim "tested on Windows" without a green Windows CI run or the João's confirmation.
- Installer must not touch Windows files or antivirus settings.

## Decisions needed from the João

- ~~Installer technology (step A)~~: decided, MSI with WiX (D-023).
- Whether to apply to SignPath now or after the manual test.
- Per-user vs per-machine install (ZeroBirus needs admin to run, so per-machine is likely, but this is his call).
