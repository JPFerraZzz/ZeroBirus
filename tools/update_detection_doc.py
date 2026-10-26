"""Regenerate the generated blocks of docs/DETECTION.md from the rules files.

    uv run python tools/update_detection_doc.py          # rewrite the blocks
    uv run python tools/update_detection_doc.py --check  # exit 1 if the file is out of date

Blocks sit between ``<!-- generated:NAME:start -->`` and ``<!-- generated:NAME:end -->``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from zerobirus.core.rules import Indicator, load_rules  # noqa: E402

DOC = REPO / "docs" / "DETECTION.md"
CHECKED_ON = "2026-10-26"


def signals_block() -> str:
    rules = load_rules()
    rows = [
        "| Código | Peso | Forte | Ameaça | Texto mostrado |",
        "| --- | --- | --- | --- | --- |",
    ]
    for code, r in rules.signals.items():
        strong = "sim" if r.strong else "não"
        rows.append(f"| `{code}` | {r.weight} | {strong} | {r.threat or ''} | {r.text} |")
    return "\n".join(rows)


def _row(i: Indicator) -> str:
    status = "verificado" if i.verified else "**não verificado**"
    sources = "<br>".join(f"<{s}>" for s in i.sources) or "nenhuma fonte encontrada"
    return f"| `{i.value}` | {status} | {sources} | {i.note} |"


def indicators_block() -> str:
    rules = load_rules()
    titles = {
        "process_names": "Nomes de programas (sem `.exe`)",
        "strong_markers": "Marcas fortes na linha de comando",
        "weak_markers": "Marcas fracas (precisam de duas ou mais)",
        "ports": "Portas de pools",
        "pool_domain_fragments": "Domínios de pools",
    }
    out: list[str] = []
    for kind, title in titles.items():
        out += [
            f"#### {title}",
            "",
            "| Indicador | Estado | Fonte (consultada em " + CHECKED_ON + ") | Nota |",
            "| --- | --- | --- | --- |",
        ]
        out += [_row(i) for i in rules.indicators[kind]]
        out.append("")
    return "\n".join(out).rstrip()


BLOCKS = {"signals": signals_block, "indicators": indicators_block}


def render(text: str) -> str:
    for name, build in BLOCKS.items():
        pattern = re.compile(
            rf"(<!-- generated:{name}:start -->\n)(.*?)(\n<!-- generated:{name}:end -->)", re.DOTALL
        )
        if not pattern.search(text):
            raise SystemExit(f"missing block {name} in {DOC}")
        text = pattern.sub(lambda m, b=build: m.group(1) + b() + m.group(3), text)
    return text


def main(argv: list[str]) -> int:
    current = DOC.read_text("utf-8")
    updated = render(current)
    if "--check" in argv:
        return 0 if updated == current else 1
    DOC.write_text(updated, "utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
