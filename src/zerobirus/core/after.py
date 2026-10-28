"""Stage 6: what to do after the cleaning, chosen from the diagnosis (pure text, pt-PT)."""

from __future__ import annotations

from collections.abc import Iterable

from zerobirus.core.diagnosis import Diagnosis
from zerobirus.core.models import ActionResult

PASSWORDS = (
    "Troca as palavras-passe a partir de OUTRO aparelho (telemóvel ou outro PC), começando pelo "
    "e-mail e pelo banco, e liga a verificação em dois passos."
)
REFORMAT = (
    "Vale a pena formatar e reinstalar o Windows se apareceu uma porta dos fundos que "
    "descarregava comandos, vírus dentro de ficheiros do Windows, ou alterações que a limpeza "
    "não conseguiu desfazer."
)
PREVENT = (
    'Para a próxima vez: cracks, ativadores, jogos pirateados e "programas grátis" são o '
    "caminho mais comum. Instala só de sites oficiais."
)
SECOND_OPINION = (
    "Segunda opinião: faz também a Análise offline do Microsoft Defender (reinicia o PC) e uma "
    "análise com o Malwarebytes gratuito. O ZeroBirus não descarrega nada: faz isto tu."
)
CLEAN_WORK_FOLDER = (
    "Podes apagar a pasta de trabalho do ZeroBirus neste PC. Os relatórios ficam guardados."
)


def advice(
    diagnosis: Diagnosis | None,
    results: Iterable[ActionResult] = (),
    *,
    anything_failed: bool = False,
) -> list[str]:
    """Passwords only for trojans; the "when to reformat" rule is always told, first if
    something could not be removed."""
    kinds: set[str] = {t.kind for t in diagnosis.threats} if diagnosis else set()
    failed = anything_failed or ActionResult.FALHOU in set(results)
    out: list[str] = []
    if failed:
        out.append(REFORMAT)
    if "trojan" in kinds:
        out.append(PASSWORDS)
    if not failed:
        out.append(REFORMAT)
    out += [SECOND_OPINION, PREVENT, CLEAN_WORK_FOLDER]
    return out


def render_final_report(
    *,
    version: str,
    session_id: str,
    overall: str,
    results: Iterable[tuple[str, str, str]],
    diff_lines: Iterable[str],
    defender_text: str,
    advice_lines: Iterable[str],
) -> str:
    """Plain-text final report (pt-PT). ``results`` rows are (target, result, detail); every
    string is redacted by the caller before it gets here."""
    lines = [
        f"ZeroBirus {version}: relatório final",
        f"Sessão: {session_id}",
        f"Resultado da primeira verificação: {overall}",
        "",
        "O que foi feito:",
    ]
    rows = list(results)
    lines += [f"  - {target}: {result}. {detail}" for target, result, detail in rows] or [
        "  (nada foi alterado)"
    ]
    lines += ["", "Depois da limpeza (verificação repetida):"]
    lines += [f"  - {x}" for x in diff_lines] or ["  (a verificação repetida não foi feita)"]
    lines += ["", f"Análise do Microsoft Defender: {defender_text}", "", "O que fazer a seguir:"]
    lines += [f"  - {x}" for x in advice_lines]
    return "\n".join(lines) + "\n"
