"""Regenerate the token table in docs/DESIGN.md from ``ui/theme.py``.

uv run python tools/update_design_doc.py          # rewrite
uv run python tools/update_design_doc.py --check  # exit 1 if out of date
"""

from __future__ import annotations

import dataclasses
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from zerobirus.ui.theme import NON_TEXT_PAIRS, TEXT_PAIRS, TOKENS, contrast  # noqa: E402

DOC = REPO / "docs" / "DESIGN.md"


def tokens_block() -> str:
    t = dataclasses.asdict(TOKENS)
    rows = ["| Token | Valor |", "| --- | --- |"]
    rows += [f"| `{name}` | `{value}` |" for name, value in t.items()]
    rows += ["", "Contrastes (WCAG, mínimo 4.5:1 para texto e 3:1 para elementos sem texto):", ""]
    rows += ["| Par | Rácio | Onde |", "| --- | --- | --- |"]
    for fg, bg, where in (*TEXT_PAIRS, *NON_TEXT_PAIRS):
        ratio = contrast(t[fg], t[bg])
        rows.append(f"| `{fg}` sobre `{bg}` | {ratio:.2f} | {where} |")
    return "\n".join(rows)


def render(text: str) -> str:
    pattern = re.compile(
        r"(<!-- generated:tokens:start -->\n)(.*?)(\n<!-- generated:tokens:end -->)", re.DOTALL
    )
    if not pattern.search(text):
        raise SystemExit("missing generated block in docs/DESIGN.md")
    return pattern.sub(lambda m: m.group(1) + tokens_block() + m.group(3), text)


def main(argv: list[str]) -> int:
    current = DOC.read_text("utf-8")
    updated = render(current)
    if "--check" in argv:
        return 0 if updated == current else 1
    DOC.write_text(updated, "utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
