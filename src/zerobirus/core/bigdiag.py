"""BigDiag: a complete, read-only health report of the PC, in plain words (PitStop).

Pure data and rules. A backend (``DiagProbe``) hands over what it could read as a plain
dictionary; this module turns it into sections with a status each. Anything the backend could
not read is "não foi possível ler", never "tudo bem". Every string that comes from the machine
(disk names, driver names, log lines) is data: shown as text, never run, and redacted before
it leaves the program in an exported file.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from zerobirus.core.models import DefenderState
from zerobirus.core.ram import MemorySnapshot, diagnose, megabytes
from zerobirus.core.redact import redact

GIB = 1024**3
STATUS_WORD = {
    "OK": "Bom",
    "ATENCAO": "Atenção",
    "PROBLEMA": "Problema",
    "NAO_LIDO": "Não foi possível ler",
}


class Status(StrEnum):
    OK = "OK"
    ATENCAO = "ATENCAO"
    PROBLEMA = "PROBLEMA"
    NAO_LIDO = "NAO_LIDO"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Status.OK: 0, Status.NAO_LIDO: 1, Status.ATENCAO: 2, Status.PROBLEMA: 3}


@dataclass(frozen=True, slots=True)
class Line:
    label: str
    value: str
    status: Status = Status.OK


@dataclass(frozen=True, slots=True)
class Section:
    title: str
    lines: tuple[Line, ...]
    note: str = ""

    @property
    def status(self) -> Status:
        return worst(line.status for line in self.lines)


@dataclass(frozen=True, slots=True)
class DiagReport:
    sections: tuple[Section, ...]
    generated_at: str

    @property
    def status(self) -> Status:
        return worst(s.status for s in self.sections)


def worst(statuses: Sequence[Status] | Any) -> Status:
    out = Status.OK
    for s in statuses:
        if s.rank > out.rank:
            out = s
    return out


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _text(value: Any, default: str = "") -> str:
    return value.strip() if isinstance(value, str) and value.strip() else default


def _list(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]  # PowerShell turns a one-item array into the item itself
    if isinstance(value, list):
        return [x for x in value if isinstance(x, Mapping)]  # pyright: ignore[reportUnknownVariableType]
    return []


def _unread(title: str, what: str) -> Section:
    return Section(title, (Line(what, "não foi possível ler", Status.NAO_LIDO),))


def _gib(n: float) -> str:
    return f"{n / GIB:.0f} GB" if n >= 10 * GIB else f"{n / GIB:.1f} GB"


# Sections -------------------------------------------------------------------------------


def system_section(raw: Mapping[str, Any]) -> Section:
    osr = raw.get("os")
    if not isinstance(osr, Mapping):
        return _unread("Sistema", "Windows")
    osm: Mapping[str, Any] = osr  # pyright: ignore[reportUnknownVariableType]
    lines = [
        Line(
            "Windows",
            f"{_text(osm.get('caption'), '?')} (compilação {_text(osm.get('build'), '?')})",
        )
    ]
    days = _num(osm.get("uptime_days"))
    if days is not None:
        long_up = days >= 14
        lines.append(
            Line(
                "Ligado há",
                f"{days:.0f} dias sem reiniciar" if days >= 1 else "menos de um dia",
                Status.ATENCAO if long_up else Status.OK,
            )
        )
    hotfix = _text(osm.get("last_update"))
    if hotfix:
        lines.append(Line("Última atualização instalada", hotfix))
    return Section("Sistema", tuple(lines))


def cpu_section(raw: Mapping[str, Any]) -> Section:
    cpus = _list(raw.get("cpu"))
    if not cpus:
        return _unread("Processador", "processador")
    c = cpus[0]
    cores, threads = _num(c.get("cores")), _num(c.get("threads"))
    detail = _text(c.get("name"), "?")
    if cores and threads:
        detail += f" ({cores:.0f} núcleos, {threads:.0f} threads)"
    lines = [Line("Modelo", detail)]
    temp = _num(raw.get("cpu_temp_c"))
    if temp is None:
        lines.append(Line("Temperatura", "o Windows não a dá neste PC", Status.NAO_LIDO))
    else:
        status = Status.PROBLEMA if temp >= 90 else Status.ATENCAO if temp >= 80 else Status.OK
        lines.append(Line("Temperatura", f"{temp:.0f} °C", status))
    return Section("Processador", tuple(lines))


def ram_section(raw: Mapping[str, Any], memory: MemorySnapshot | None) -> Section:
    if memory is None:
        return _unread("Memória RAM", "memória")
    report = diagnose(memory)
    status = {"BAIXA": Status.OK, "MEDIA": Status.OK, "ALTA": Status.ATENCAO}[report.pressure.value]
    lines = [
        Line("Total", megabytes(report.total)),
        Line("Em uso", f"{megabytes(report.used)} ({report.percent}%)", status),
    ]
    modules = _list(raw.get("ram_modules"))
    if modules:
        speeds = sorted({int(s) for m in modules if (s := _num(m.get("speed_mhz")))})
        speed = f", {'/'.join(str(s) for s in speeds)} MHz" if speeds else ""
        lines.append(Line("Pentes", f"{len(modules)}{speed}"))
    return Section("Memória RAM", tuple(lines), note=report.advice)


def disks_section(raw: Mapping[str, Any]) -> Section:
    disks = _list(raw.get("disks"))
    if not disks:
        return _unread("Discos", "discos")
    lines: list[Line] = []
    for i, d in enumerate(disks, start=1):
        name = _text(d.get("name"), f"Disco {i}")
        kind = _text(d.get("media"), "tipo desconhecido")
        size = _num(d.get("size"))
        title = f"{name} ({kind}{', ' + _gib(size) if size else ''})"
        health = _text(d.get("health")).lower()
        if health == "healthy":
            lines.append(Line(title, "estado de saúde bom"))
        elif health in ("warning", "unhealthy"):
            lines.append(
                Line(
                    title,
                    f"o disco diz que está em estado {health}: faz cópia dos teus dados",
                    Status.PROBLEMA if health == "unhealthy" else Status.ATENCAO,
                )
            )
        else:
            lines.append(Line(title, "estado de saúde não lido", Status.NAO_LIDO))
        lines.extend(_smart_lines(d))
    return Section("Discos", tuple(lines))


def _smart_lines(d: Mapping[str, Any]) -> list[Line]:
    out: list[Line] = []
    wear = _num(d.get("wear_percent"))
    if wear is not None:
        status = Status.PROBLEMA if wear >= 90 else Status.ATENCAO if wear >= 70 else Status.OK
        out.append(Line("  Desgaste", f"{wear:.0f}% da vida usada", status))
    temp = _num(d.get("temperature_c"))
    if temp is not None:
        status = Status.PROBLEMA if temp >= 70 else Status.ATENCAO if temp >= 55 else Status.OK
        out.append(Line("  Temperatura", f"{temp:.0f} °C", status))
    errors = (_num(d.get("read_errors")) or 0) + (_num(d.get("write_errors")) or 0)
    if errors > 0:
        out.append(Line("  Erros de leitura e escrita", f"{errors:.0f}", Status.ATENCAO))
    hours = _num(d.get("power_on_hours"))
    if hours is not None:
        out.append(Line("  Horas ligado", f"{hours:,.0f} h".replace(",", " ")))
    return out


def space_section(raw: Mapping[str, Any]) -> Section:
    volumes = _list(raw.get("volumes"))
    if not volumes:
        return _unread("Espaço livre", "volumes")
    lines: list[Line] = []
    for v in volumes:
        size, free = _num(v.get("size")), _num(v.get("free"))
        letter = _text(v.get("letter"), "?")
        if not size or free is None:
            lines.append(Line(f"{letter}:", "não foi possível ler", Status.NAO_LIDO))
            continue
        pct = 100 * free / size
        status = Status.PROBLEMA if pct < 10 else Status.ATENCAO if pct < 20 else Status.OK
        lines.append(
            Line(f"{letter}:", f"{_gib(free)} livres de {_gib(size)} ({pct:.0f}%)", status)
        )
    return Section("Espaço livre", tuple(lines))


def gpu_section(raw: Mapping[str, Any]) -> Section:
    gpus = _list(raw.get("gpus"))
    if not gpus:
        return _unread("Placa gráfica", "placa gráfica")
    lines = [
        Line(
            _text(g.get("name"), "Placa gráfica"),
            f"driver {_text(g.get('driver_version'), '?')} de {_text(g.get('driver_date'), '?')}",
        )
        for g in gpus
    ]
    return Section("Placa gráfica", tuple(lines))


def mrt_section(raw: Mapping[str, Any]) -> Section:
    mrt = raw.get("mrt")
    if not isinstance(mrt, Mapping):
        return _unread("Ferramenta de remoção de software malicioso (MRT)", "MRT")
    m: Mapping[str, Any] = mrt  # pyright: ignore[reportUnknownVariableType]
    lines = [Line("Versão", _text(m.get("version"), "não instalada"))]
    last = _text(m.get("last_run"))
    if not last:
        lines.append(
            Line(
                "Última execução",
                "sem registo (nunca correu ou o log foi apagado)",
                Status.NAO_LIDO,
            )
        )
    else:
        lines.append(Line("Última execução", last))
        outcome = _text(m.get("outcome"))
        if outcome == "clean":
            lines.append(Line("Resultado", "nenhuma infeção encontrada"))
        elif outcome == "threats":
            lines.append(
                Line("Resultado", "encontrou ameaças: vê o relatório do MRT", Status.PROBLEMA)
            )
        else:
            lines.append(Line("Resultado", "o log não diz o resultado", Status.NAO_LIDO))
    return Section(
        "Ferramenta de remoção de software malicioso (MRT)",
        tuple(lines),
        note="O MRT corre sozinho com o Windows Update. Isto só lê o que ele registou.",
    )


def defender_section(state: DefenderState | None) -> Section:
    if state is None:
        return _unread("Microsoft Defender", "Defender")
    lines: list[Line] = []
    if state.realtime is None:
        lines.append(Line("Proteção em tempo real", "não foi possível ler", Status.NAO_LIDO))
    else:
        lines.append(
            Line(
                "Proteção em tempo real",
                "ligada" if state.realtime else "desligada",
                Status.OK if state.realtime else Status.ATENCAO,
            )
        )
    age = state.signature_age_days
    if age is None:
        lines.append(Line("Definições de vírus", "idade não lida", Status.NAO_LIDO))
    else:
        status = Status.PROBLEMA if age > 14 else Status.ATENCAO if age > 3 else Status.OK
        lines.append(Line("Definições de vírus", f"com {age} dias", status))
    if state.threats:
        lines.append(
            Line("Histórico de ameaças", f"{len(state.threats)} registadas", Status.ATENCAO)
        )
    note = (
        "O Defender pode estar em modo passivo por haver outro antivírus: isso não é um problema."
        if state.passive_mode
        else ""
    )
    return Section("Microsoft Defender", tuple(lines), note=note)


def failures_section(raw: Mapping[str, Any]) -> Section:
    f = raw.get("failures")
    if not isinstance(f, Mapping):
        return _unread("Falhas nos últimos 30 dias", "falhas")
    fm: Mapping[str, Any] = f  # pyright: ignore[reportUnknownVariableType]
    rows = (
        ("unexpected_shutdowns", "Desligamentos inesperados", 1, 3),
        ("bugchecks", "Ecrãs azuis", 1, 3),
        ("app_crashes", "Programas que falharam", 10, 40),
        ("disk_errors", "Erros de disco", 1, 5),
    )
    lines: list[Line] = []
    for key, label, warn, bad in rows:
        n = _num(fm.get(key))
        if n is None:
            lines.append(Line(label, "não foi possível ler", Status.NAO_LIDO))
            continue
        status = Status.PROBLEMA if n >= bad else Status.ATENCAO if n >= warn else Status.OK
        lines.append(Line(label, f"{n:.0f}", status))
    return Section("Falhas nos últimos 30 dias", tuple(lines))


def build_report(
    raw: Mapping[str, Any],
    *,
    memory: MemorySnapshot | None,
    defender: DefenderState | None,
    generated_at: str,
) -> DiagReport:
    return DiagReport(
        (
            system_section(raw),
            cpu_section(raw),
            ram_section(raw, memory),
            disks_section(raw),
            space_section(raw),
            gpu_section(raw),
            mrt_section(raw),
            defender_section(defender),
            failures_section(raw),
        ),
        generated_at,
    )


def render_text(report: DiagReport, *, version: str) -> str:
    """The report as a plain text file (pt-PT). Passed through the redactor as a whole."""
    lines = [
        f"ZeroBirus {version}: BigDiag, relatório de diagnóstico",
        f"Gerado em: {report.generated_at}",
        f"Resumo: {STATUS_WORD[report.status.value]}",
        "",
        "Este relatório é só de leitura: nada no PC foi alterado. Não inclui nomes de pessoas,",
        "do PC nem caminhos de pastas pessoais.",
        "",
    ]
    for s in report.sections:
        lines.append(f"{s.title} [{STATUS_WORD[s.status.value]}]")
        lines.extend(
            f"  {line.label}: {line.value} [{STATUS_WORD[line.status.value]}]" for line in s.lines
        )
        if s.note:
            lines.append(f"  Nota: {s.note}")
        lines.append("")
    return redact("\n".join(lines)) + "\n"
