"""Build small inspectors for scanner tests without writing JSON."""

from __future__ import annotations

from typing import Any

from ctx_factory import typical_context

from zerobirus.core.models import CheckResult, Finding, Level, Signature, SignatureStatus
from zerobirus.core.safety import SignerKind
from zerobirus.core.snapshot import Snapshot
from zerobirus.platform.fake import FakeInspector

MS_SUBJECT = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"


def inspector(
    *, elevated: bool = True, gaps: dict[str, tuple[str, ...]] | None = None, **sections: Any
) -> FakeInspector:
    return FakeInspector(
        Snapshot(elevated=elevated, system=typical_context(), gaps=gaps or {}, **sections)
    )


def valid(
    path: str, subject: str = MS_SUBJECT, kind: SignerKind = SignerKind.MICROSOFT
) -> Signature:
    return Signature(path, SignatureStatus.VALID, kind, subject)


def unsigned(path: str) -> Signature:
    return Signature(path, SignatureStatus.UNSIGNED, SignerKind.UNSIGNED, "")


def unknown(path: str) -> Signature:
    return Signature(path, SignatureStatus.UNKNOWN, SignerKind.OTHER, "")


def levels(result: CheckResult) -> dict[str, Level]:
    return {f.item: f.level for f in result.findings}


def only(result: CheckResult) -> Finding:
    assert len(result.findings) == 1, result.findings
    return result.findings[0]


def codes(finding: Finding) -> set[str]:
    return {s.code for s in finding.signals}
