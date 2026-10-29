"""The one place where the look of the interface is defined (docs/DESIGN.md).

Tokens first, then a stylesheet built from them. Nothing else in ``ui/`` hard-codes a colour,
a font or a spacing. ``tests/unit/test_ui_theme.py`` checks the contrast of every text pair and
that the generated table in docs/DESIGN.md is current.
"""

from __future__ import annotations

from dataclasses import dataclass

from zerobirus.core.models import Level
from zerobirus.core.risk import Risk


@dataclass(frozen=True, slots=True)
class Tokens:
    # surfaces and ink (dark, a cold near-black; the white of a light theme glares in a dark room)
    paper: str = "#0E1218"  # page background
    surface: str = "#151B24"  # tables and text areas
    card: str = "#182030"  # the cards of the home menu and the collapsible groups
    card_hover: str = "#1F2A3D"
    ink: str = "#E8ECF1"  # primary text
    ink_muted: str = "#9DA7B5"  # secondary text
    rule: str = "#6B7788"  # borders that must be seen (inputs, table frame)
    rule_soft: str = "#273040"  # hairlines between rows
    selection: str = "#1D2B3A"  # selected row background
    # the one action colour: a mint-cyan, used for the main button, the focus ring and numbers
    accent: str = "#2BD9B4"
    accent_hover: str = "#55E6C6"
    on_accent: str = "#04211B"
    # levels: text colour and soft background, never alone (a shape and a word go with them)
    suspeito: str = "#FF8F86"
    suspeito_bg: str = "#3A1C20"
    conferir: str = "#F0C050"
    conferir_bg: str = "#34290F"
    ok: str = "#62D890"
    ok_bg: str = "#14301F"
    nao_verificado: str = "#A9B2BF"
    nao_verificado_bg: str = "#232A34"
    danger: str = "#C23B3B"
    on_danger: str = "#FFFFFF"
    disabled: str = "#8591A3"
    # type (points; the system font keeps ClearType and the accents right)
    font_body_pt: float = 10.0
    font_small_pt: float = 9.0
    font_title_pt: float = 16.0
    font_subtitle_pt: float = 12.0
    font_metric_pt: float = 22.0  # the big numbers ("6,4 GB")
    font_family: str = (
        '"Segoe UI Variable Text", "Segoe UI", "Noto Sans", "DejaVu Sans", sans-serif'
    )
    font_mono: str = '"Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace'
    # space (px, a grid of 4: short inside groups, long between them)
    space_1: int = 4
    space_2: int = 8
    space_3: int = 12
    space_4: int = 16
    space_5: int = 24
    space_6: int = 32
    row_height: int = 36
    radius: int = 2
    radius_card: int = 8  # only cards and groups; buttons and inputs stay nearly square
    focus_width: int = 2


TOKENS = Tokens()
MIN_WINDOW = (840, 460)  # logical points: 1280x720 at 150% is about 853x480
NARROW_BELOW = 1000  # logical width under which the stage rail shows only numbers

# Every pair of text and background that appears on screen, for the contrast test (AA, 4.5:1).
TEXT_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("ink", "paper", "body text on the page"),
    ("ink", "surface", "table and text areas"),
    ("ink_muted", "paper", "secondary text on the page"),
    ("ink_muted", "surface", "secondary text in tables"),
    ("ink", "card", "text on a card"),
    ("ink_muted", "card", "secondary text on a card"),
    ("accent", "card", "accent text on a card"),
    ("ink", "card_hover", "text on a hovered card"),
    ("ink_muted", "card_hover", "secondary text on a hovered card"),
    ("ink", "selection", "selected row"),
    ("on_accent", "accent", "primary button"),
    ("on_accent", "accent_hover", "primary button hovered"),
    ("accent", "paper", "links and accent text"),
    ("on_danger", "danger", "destructive button"),
    ("suspeito", "paper", "level text"),
    ("suspeito", "suspeito_bg", "level text on its tint"),
    ("conferir", "paper", "level text"),
    ("conferir", "conferir_bg", "level text on its tint"),
    ("ok", "paper", "level text"),
    ("ok", "ok_bg", "level text on its tint"),
    ("nao_verificado", "paper", "level text"),
    ("nao_verificado", "nao_verificado_bg", "level text on its tint"),
    ("disabled", "paper", "disabled text"),
)
# Pairs of non-text UI that must reach 3:1 (WCAG 1.4.11): input borders against the page.
NON_TEXT_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("rule", "paper", "borders of inputs and tables"),
    ("accent", "paper", "focus ring"),
    ("rule", "card", "borders of cards"),
)


@dataclass(frozen=True, slots=True)
class LevelStyle:
    level: Level
    color: str
    background: str
    shape: str  # drawn in widgets.paint_level_glyph
    label: str  # the word, always shown next to the shape


def level_style(level: Level, t: Tokens = TOKENS) -> LevelStyle:
    return {
        Level.SUSPEITO: LevelStyle(level, t.suspeito, t.suspeito_bg, "diamond", "SUSPEITO"),
        Level.CONFERIR: LevelStyle(level, t.conferir, t.conferir_bg, "triangle", "CONFERIR"),
        Level.OK: LevelStyle(level, t.ok, t.ok_bg, "circle", "OK"),
        Level.NAO_VERIFICADO: LevelStyle(
            level, t.nao_verificado, t.nao_verificado_bg, "dashed-square", "NÃO VERIFICADO"
        ),
    }[level]


@dataclass(frozen=True, slots=True)
class RiskStyle:
    risk: Risk
    color: str
    background: str
    shape: str  # drawn in widgets.paint_risk_glyph
    label: str  # the word, always shown next to the shape


def risk_style(risk: Risk, t: Tokens = TOKENS) -> RiskStyle:
    """Five levels, five shapes; the colours are the existing level colours (no new accent)."""
    grey = (t.nao_verificado, t.nao_verificado_bg)
    amber = (t.conferir, t.conferir_bg)
    coral = (t.suspeito, t.suspeito_bg)
    shape, (color, background) = {
        Risk.INCOMUM: ("ring", grey),
        Risk.ANOMALO: ("target", amber),
        Risk.SUSPEITO: ("triangle", amber),
        Risk.GRAVE: ("diamond", coral),
        Risk.CRITICO: ("double-diamond", coral),
    }[risk]
    return RiskStyle(risk, color, background, shape, risk.label.upper())


def luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    rgb = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def stylesheet(t: Tokens = TOKENS) -> str:
    """The Qt style sheet. Flat, square-ish, no shadows, no gradients."""
    fw = t.focus_width
    return f"""
* {{ font-family: {t.font_family}; font-size: {t.font_body_pt}pt; color: {t.ink}; }}
QMainWindow, QWidget#page, QWidget#root, QDialog {{ background: {t.paper}; }}
QLabel {{ background: transparent; }}
QLabel[role="title"] {{ font-size: {t.font_title_pt}pt; font-weight: 600; }}
QLabel[role="subtitle"] {{ font-size: {t.font_subtitle_pt}pt; font-weight: 600; }}
QLabel[role="lead"] {{ color: {t.ink_muted}; }}
QLabel[role="small"] {{ color: {t.ink_muted}; font-size: {t.font_small_pt}pt; }}
QLabel[role="mono"], QPlainTextEdit[role="mono"] {{ font-family: {t.font_mono}; }}
QLabel[role="metric"] {{ font-family: {t.font_mono}; font-size: {t.font_metric_pt}pt; color: {t.accent}; }}
QLabel[role="signature"] {{ color: {t.ink_muted}; font-size: {t.font_small_pt}pt; }}

QPushButton {{
    background: {t.surface}; color: {t.ink}; border: {fw}px solid {t.rule};
    border-radius: {t.radius}px; padding: {t.space_2}px {t.space_4}px; min-height: 20px;
}}
QPushButton:hover {{ background: {t.selection}; }}
QPushButton:focus {{ border: {fw}px solid {t.accent}; }}
QPushButton:disabled {{ color: {t.disabled}; border-color: {t.rule_soft}; background: {t.paper}; }}
QPushButton[role="primary"] {{
    background: {t.accent}; color: {t.on_accent}; border: {fw}px solid {t.accent}; font-weight: 600;
}}
QPushButton[role="primary"]:hover {{ background: {t.accent_hover}; border-color: {t.accent_hover}; }}
QPushButton[role="primary"]:focus {{ border: {fw}px solid {t.ink}; }}
QPushButton[role="primary"]:disabled {{
    background: {t.rule_soft}; color: {t.disabled}; border-color: {t.rule_soft};
}}
QPushButton[role="danger"] {{
    background: {t.danger}; color: {t.on_danger}; border: {fw}px solid {t.danger}; font-weight: 600;
}}
QPushButton[role="danger"]:focus {{ border: {fw}px solid {t.ink}; }}
QPushButton[role="danger"]:disabled {{
    background: {t.rule_soft}; color: {t.disabled}; border-color: {t.rule_soft};
}}
QPushButton[role="link"] {{
    background: transparent; border: {fw}px solid transparent; color: {t.accent};
    text-decoration: underline; padding: {t.space_1}px {t.space_2}px;
}}
QPushButton[role="link"]:focus {{ border: {fw}px solid {t.accent}; }}

QPushButton[role="card"] {{
    background: {t.card}; border: 1px solid {t.rule_soft}; border-radius: {t.radius_card}px;
    padding: 0; text-align: left;
}}
QPushButton[role="card"]:hover {{ background: {t.card_hover}; border-color: {t.rule}; }}
QPushButton[role="card"]:focus {{ border: {fw}px solid {t.accent}; }}
QPushButton[role="card"][deep="true"] {{ background: {t.surface}; border: 1px solid {t.accent}; }}
QPushButton[role="card"][deep="true"]:hover {{ background: {t.card_hover}; }}
QPushButton[role="group"] {{
    background: {t.card}; border: 1px solid {t.rule_soft}; border-radius: {t.radius_card}px;
    padding: {t.space_2}px {t.space_4}px; text-align: left; font-weight: 600; min-height: 24px;
}}
QPushButton[role="group"]:hover {{ background: {t.card_hover}; }}
QPushButton[role="group"]:focus {{ border: {fw}px solid {t.accent}; }}
QFrame[role="groupbody"] {{
    background: transparent; border-left: 2px solid {t.rule_soft}; margin-left: {t.space_3}px;
}}

QCheckBox, QRadioButton {{ spacing: {t.space_2}px; background: transparent; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 18px; height: 18px; border: {fw}px solid {t.rule}; background: {t.surface};
    border-radius: {t.radius}px;
}}
QRadioButton::indicator {{ border-radius: 10px; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background: {t.accent}; border-color: {t.accent};
}}
QCheckBox:focus, QRadioButton:focus {{ outline: none; }}
QCheckBox::indicator:focus, QRadioButton::indicator:focus {{ border-color: {t.ink}; }}

QLineEdit, QPlainTextEdit, QTextBrowser, QTableView, QTreeView, QListView {{
    background: {t.surface}; border: 1px solid {t.rule}; border-radius: {t.radius}px;
    selection-background-color: {t.selection}; selection-color: {t.ink};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextBrowser:focus, QTableView:focus, QTreeView:focus,
QListView:focus {{ border: {fw}px solid {t.accent}; }}
QTableView {{ gridline-color: {t.rule_soft}; alternate-background-color: {t.surface}; outline: 0; }}
QTableView::item:focus {{ border: none; outline: none; }}
QTableView::item {{ padding: {t.space_1}px {t.space_2}px; border-bottom: 1px solid {t.rule_soft}; }}
QTableView::item:selected, QTreeView::item:selected {{ background: {t.selection}; color: {t.ink}; }}
QHeaderView::section {{
    background: {t.paper}; color: {t.ink}; font-weight: 600; border: none;
    border-bottom: {fw}px solid {t.ink}; padding: {t.space_2}px {t.space_2}px;
}}

QListWidget#rail {{ background: transparent; border: none; border-right: 1px solid {t.rule}; }}
QListWidget#rail::item {{ padding: {t.space_2}px {t.space_3}px; border-left: 3px solid transparent; }}
QListWidget#rail::item:selected {{ background: {t.selection}; border-left: 3px solid {t.accent}; }}
QListWidget#rail:focus {{ border-right: {fw}px solid {t.accent}; }}

QProgressBar {{
    border: 1px solid {t.rule}; border-radius: {t.radius}px; background: {t.surface};
    text-align: center; min-height: 20px;
}}
QProgressBar::chunk {{ background: {t.accent}; }}

QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QTabWidget::pane {{ border: 1px solid {t.rule}; background: {t.surface}; top: -1px; }}
QTabBar::tab {{ background: {t.paper}; border: 1px solid {t.rule}; padding: {t.space_2}px {t.space_4}px; margin-right: 2px; }}
QTabBar::tab:selected {{ background: {t.surface}; border-bottom-color: {t.surface}; font-weight: 600; }}
QTabBar::tab:focus {{ border: {t.focus_width}px solid {t.accent}; }}
QFrame[role="rule"] {{ background: {t.rule}; max-height: 1px; min-height: 1px; border: none; }}
QSplitter::handle {{ background: {t.rule_soft}; }}
QSplitter::handle:hover {{ background: {t.rule}; }}
QScrollBar:vertical {{ width: 14px; background: {t.paper}; }}
QScrollBar::handle:vertical {{ background: {t.rule}; min-height: 28px; border-radius: {t.radius}px; }}
QScrollBar:horizontal {{ height: 14px; background: {t.paper}; }}
QScrollBar::handle:horizontal {{ background: {t.rule}; min-width: 28px; border-radius: {t.radius}px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QToolTip {{ background: {t.ink}; color: {t.paper}; border: none; padding: {t.space_1}px {t.space_2}px; }}
"""
