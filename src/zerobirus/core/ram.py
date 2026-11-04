"""RAM Lover: a simple reading of the memory, and which programs could be closed.

Pure data and rules, no OS access. A backend (``MemoryProbe``) hands over a snapshot; this
module judges the pressure in plain words and offers only programs that ``core.safety`` does
not protect. Closing a program is the engine's ``KILL_PROCESS``: it needs an authorised plan,
is checked again against the live process, and cannot be undone (a program that was closed
does not come back by itself; unsaved work in it is lost).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from zerobirus.core.models import Level, Signature, SignatureStatus
from zerobirus.core.plan import ActionType, PlanItem, item_id
from zerobirus.core.safety import (
    SignerKind,
    SystemContext,
    is_no_image_process_name,
    is_protected_path,
    is_protected_process,
    normalize_windows_path,
)

MIN_CLOSABLE_BYTES = 50 * 1024 * 1024  # smaller programs are not worth listing
MAX_LISTED = 15
MEGA = 1024 * 1024


class Pressure(StrEnum):
    BAIXA = "BAIXA"
    MEDIA = "MEDIA"
    ALTA = "ALTA"


@dataclass(frozen=True, slots=True)
class MemoryProcess:
    pid: int
    name: str
    path: str | None
    rss: int  # bytes of RAM in use


@dataclass(frozen=True, slots=True)
class MemorySnapshot:
    total: int
    available: int
    processes: tuple[MemoryProcess, ...]

    @property
    def used(self) -> int:
        return max(self.total - self.available, 0)

    @property
    def percent(self) -> int:
        return round(100 * self.used / self.total) if self.total > 0 else 0


@dataclass(frozen=True, slots=True)
class RamReport:
    total: int
    used: int
    available: int
    percent: int
    pressure: Pressure
    advice: str
    top: tuple[MemoryProcess, ...]


ADVICE = {
    Pressure.BAIXA: "A RAM está folgada. Não há nada que valha a pena fechar.",
    Pressure.MEDIA: "A RAM está a meio. Se o jogo ou o PC ficam lentos, fecha o que não usas.",
    Pressure.ALTA: (
        "A RAM está quase cheia: o Windows passa a usar o disco como memória, e isso notam-se "
        "quebras no jogo. Fecha o que não usas."
    ),
}


def pressure_of(percent: int) -> Pressure:
    if percent >= 85:
        return Pressure.ALTA
    if percent >= 60:
        return Pressure.MEDIA
    return Pressure.BAIXA


def megabytes(n: int) -> str:
    return f"{n / MEGA:,.0f} MB".replace(",", " ")


def diagnose(snapshot: MemorySnapshot, *, top: int = 5) -> RamReport:
    pressure = pressure_of(snapshot.percent)
    ranked = tuple(sorted(snapshot.processes, key=lambda p: -p.rss)[:top])
    return RamReport(
        snapshot.total,
        snapshot.used,
        snapshot.available,
        snapshot.percent,
        pressure,
        ADVICE[pressure],
        ranked,
    )


def candidates(snapshot: MemorySnapshot, ctx: SystemContext) -> tuple[MemoryProcess, ...]:
    """Programs worth a look: big enough, with a known image, not an obviously protected one.

    Under Program Files the answer also depends on who signed the file, so these are only
    candidates until ``closable`` has the signatures.
    """
    out: list[MemoryProcess] = []
    for p in sorted(snapshot.processes, key=lambda x: -x.rss):
        if p.rss < MIN_CLOSABLE_BYTES or not p.path or is_no_image_process_name(p.name):
            continue
        if is_protected_process(p.name, p.path, ctx, pid=p.pid):
            continue
        if is_protected_path(p.path, ctx, signer=SignerKind.OTHER):
            continue
        out.append(p)
    return tuple(out[: MAX_LISTED * 2])


def closable(
    snapshot: MemorySnapshot, ctx: SystemContext, signers: Mapping[str, SignerKind]
) -> tuple[MemoryProcess, ...]:
    """What may be offered for closing. ``signers`` maps a normalised path to the signer that was
    actually checked; a path with no entry has an unknown signer and stays protected (fail closed),
    so an antivirus under Program Files is never listed."""
    out: list[MemoryProcess] = []
    for p in candidates(snapshot, ctx):
        signer = signers.get(normalize_windows_path(p.path or ""))
        if is_protected_path(p.path or "", ctx, signer=signer):
            continue
        out.append(p)
        if len(out) >= MAX_LISTED:
            break
    return tuple(out)


def signers_of(signatures: Iterable[Signature]) -> dict[str, SignerKind]:
    """Signer per path, from signatures that were really checked (UNKNOWN is left out)."""
    return {
        normalize_windows_path(s.path): s.kind
        for s in signatures
        if s.status is not SignatureStatus.UNKNOWN
    }


def close_item(p: MemoryProcess) -> PlanItem:
    """The plan item that closes one program. The engine re-checks the live process."""
    params = tuple(sorted({"pid": str(p.pid), "name": p.name, "path": p.path or ""}.items()))
    return PlanItem(
        id=item_id(ActionType.KILL_PROCESS, params),
        action=ActionType.KILL_PROCESS,
        target=f"{p.name} (PID {p.pid})",
        params=params,
        level=Level.OK,
        why=(
            f"Usa {megabytes(p.rss)} de RAM. Fechar liberta essa memória; o trabalho não "
            "guardado perde-se."
        ),
        finding_id=f"ram:{p.pid}",
        default_selected=False,
    )
