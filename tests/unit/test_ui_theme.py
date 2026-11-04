import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from zerobirus.core.models import Level
from zerobirus.ui.theme import (
    MIN_WINDOW,
    NON_TEXT_PAIRS,
    TEXT_PAIRS,
    TOKENS,
    contrast,
    level_style,
    stylesheet,
)

T = asdict(TOKENS)
REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(("fg", "bg", "where"), TEXT_PAIRS, ids=lambda v: str(v))
def test_every_text_pair_reaches_wcag_aa(fg: str, bg: str, where: str) -> None:
    assert contrast(T[fg], T[bg]) >= 4.5, f"{fg} on {bg} ({where})"


@pytest.mark.parametrize(("fg", "bg", "where"), NON_TEXT_PAIRS, ids=lambda v: str(v))
def test_non_text_pairs_reach_3_to_1(fg: str, bg: str, where: str) -> None:
    assert contrast(T[fg], T[bg]) >= 3.0, f"{fg} on {bg} ({where})"


def test_each_level_has_its_own_shape_and_always_a_word() -> None:
    styles = [level_style(lv) for lv in Level]
    assert len({s.shape for s in styles}) == 4
    assert all(s.label.strip() for s in styles)
    assert len({s.color for s in styles}) == 4


def test_no_gradients_shadows_or_transparency_in_the_style_sheet() -> None:
    css = stylesheet().lower()
    for banned in ("gradient", "shadow", "rgba(", "opacity", "blur"):
        assert banned not in css


def test_text_is_never_below_nine_points_and_corners_are_nearly_square() -> None:
    assert TOKENS.font_small_pt >= 9.0
    assert TOKENS.radius <= 2  # buttons and inputs
    assert TOKENS.radius_card <= 10  # soft, not a bubble
    assert TOKENS.row_height >= 36


def test_the_smallest_supported_window_is_1280x720_at_150_percent() -> None:
    assert MIN_WINDOW[0] <= 1280 / 1.5
    assert MIN_WINDOW[1] <= 720 / 1.5


def test_design_doc_token_table_is_current() -> None:
    done = subprocess.run(  # noqa: S603 - our own script, fixed interpreter, no shell
        [sys.executable, str(REPO / "tools" / "update_design_doc.py"), "--check"], check=False
    )
    assert done.returncode == 0, "run: uv run python tools/update_design_doc.py"


def test_each_risk_level_has_its_own_shape_and_always_a_word() -> None:
    from zerobirus.core.risk import Risk
    from zerobirus.ui.theme import risk_style

    styles = [risk_style(r) for r in Risk]
    assert len({s.shape for s in styles}) == 5
    assert [s.label for s in styles] == ["INCOMUM", "ANÓMALO", "SUSPEITO", "GRAVE", "CRÍTICO"]
    for s in styles:
        assert contrast(s.color, TOKENS.paper) >= 4.5
        assert contrast(s.color, s.background) >= 4.5
