"""Small reusable widgets. Everything that shows text from the machine is plain text only."""

from __future__ import annotations

from PySide6.QtCore import (
    QModelIndex,
    QPersistentModelIndex,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen, QPolygonF, QResizeEvent, QTextOption
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QLayout,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QVBoxLayout,
    QWidget,
)

from zerobirus.core.models import Level
from zerobirus.core.risk import Risk
from zerobirus.ui import catalog
from zerobirus.ui.theme import TOKENS, level_style, risk_style

LEVEL_ROLE = Qt.ItemDataRole.UserRole + 1
GLYPH = 12  # logical pixels


def make_label(text: str, role: str = "", *, wrap: bool = True, name: str = "") -> QLabel:
    """A label that never interprets its text: ``PlainText``, no links, no rich text."""
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    label.setWordWrap(wrap)
    if role:
        label.setProperty("role", role)
    if name:
        label.setAccessibleName(name)
    return label


class WrapText(QPlainTextEdit):
    """Read-only plain text that wraps ANYWHERE, so a long path never forces the layout wider.

    A QLabel only breaks at spaces and a registry key or path has none. The text is shown and
    copied exactly as given (no zero-width spaces), never interpreted as HTML.
    """

    def __init__(self, text: str = "", role: str = "", name: str = "") -> None:
        super().__init__()
        self._fitting = False
        self.setReadOnly(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.setStyleSheet("QPlainTextEdit { background: transparent; border: none; }")
        self.document().setDocumentMargin(0)
        if role:
            self.setProperty("role", role)
        if name:
            self.setAccessibleName(name)
        self.setPlainText(text)
        self.document().documentLayout().documentSizeChanged.connect(self._fit)
        self._fit()

    def set_text(self, text: str) -> None:
        self.setPlainText(text)
        self._fit()

    def text(self) -> str:
        return self.toPlainText()

    def _fit(self) -> None:
        if self._fitting:
            return
        self._fitting = True
        try:
            self.document().setTextWidth(max(self.viewport().width(), 1))
            # QPlainTextDocumentLayout reports its size in lines (wrapped ones included).
            lines = max(1.0, self.document().documentLayout().documentSize().height())
            height = int(lines * self.fontMetrics().lineSpacing()) + 4
            if self.height() != height:
                self.setFixedHeight(height)
        finally:
            self._fitting = False

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._fit()

    def minimumSizeHint(self) -> QSize:
        return QSize(40, self.height())

    def sizeHint(self) -> QSize:
        return QSize(200, self.height())


def clear_layout(layout: QLayout) -> None:
    """Remove and schedule deletion of everything in a layout."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget() if item is not None else None
        if widget is not None:
            widget.hide()
            widget.setParent(None)  # leave at once, so a rebuilt list never overlaps the old one
            widget.deleteLater()


def make_rule() -> QFrame:
    line = QFrame()
    line.setProperty("role", "rule")
    line.setFrameShape(QFrame.Shape.NoFrame)
    line.setFixedHeight(1)
    return line


def paint_level_glyph(painter: QPainter, rect: QRectF, level: Level) -> None:
    """The shape that goes with each level, so colour is never the only signal."""
    style = level_style(level)
    colour = QColor(style.color)
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    pen = QPen(colour)
    pen.setWidthF(1.6)
    painter.setPen(pen)
    cx, cy = rect.center().x(), rect.center().y()
    r = min(rect.width(), rect.height()) / 2 - 0.5
    if style.shape == "diamond":
        painter.setBrush(colour)
        painter.drawPolygon(
            QPolygonF([_pt(cx, cy - r), _pt(cx + r, cy), _pt(cx, cy + r), _pt(cx - r, cy)])
        )
    elif style.shape == "triangle":
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolygon(
            QPolygonF([_pt(cx, cy - r), _pt(cx + r, cy + r * 0.85), _pt(cx - r, cy + r * 0.85)])
        )
    elif style.shape == "circle":
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(_pt(cx, cy), r, r)
        path = QPainterPath()
        path.moveTo(cx - r * 0.45, cy)
        path.lineTo(cx - r * 0.1, cy + r * 0.4)
        path.lineTo(cx + r * 0.5, cy - r * 0.35)
        painter.drawPath(path)
    else:  # dashed-square
        pen.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(QRectF(cx - r, cy - r, 2 * r, 2 * r))
    painter.restore()


def paint_risk_glyph(painter: QPainter, rect: QRectF, risk: Risk) -> None:
    """One distinct shape per risk level, so colour is never the only signal."""
    style = risk_style(risk)
    colour = QColor(style.color)
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    pen = QPen(colour)
    pen.setWidthF(1.6)
    painter.setPen(pen)
    cx, cy = rect.center().x(), rect.center().y()
    r = min(rect.width(), rect.height()) / 2 - 0.5

    def diamond(k: float, filled: bool) -> None:
        painter.setBrush(colour if filled else Qt.BrushStyle.NoBrush)
        painter.drawPolygon(
            QPolygonF(
                [_pt(cx, cy - r * k), _pt(cx + r * k, cy), _pt(cx, cy + r * k), _pt(cx - r * k, cy)]
            )
        )

    if style.shape == "ring":
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(_pt(cx, cy), r, r)
    elif style.shape == "target":
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(_pt(cx, cy), r, r)
        painter.setBrush(colour)
        painter.drawEllipse(_pt(cx, cy), r * 0.35, r * 0.35)
    elif style.shape == "triangle":
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolygon(
            QPolygonF([_pt(cx, cy - r), _pt(cx + r, cy + r * 0.85), _pt(cx - r, cy + r * 0.85)])
        )
    elif style.shape == "diamond":
        diamond(1.0, True)
    else:  # double-diamond
        diamond(1.0, False)
        diamond(0.5, True)
    painter.restore()


def _pt(x: float, y: float) -> QPointF:
    return QPointF(x, y)


class LevelDelegate(QStyledItemDelegate):
    """Draws the glyph and the level word in the Level column."""

    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> None:
        # A StrEnum goes through Qt's model machinery as a plain string, so read it back.
        raw = index.data(LEVEL_ROLE)
        try:
            level = Level(raw)
        except ValueError:
            super().paint(painter, option, index)
            return
        style = level_style(level)
        painter.save()
        rect = option.rect
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(rect, QColor(TOKENS.selection))
        painter.fillRect(QRect(rect.left(), rect.top(), 3, rect.height()), QColor(style.color))
        glyph = QRectF(rect.left() + 10, rect.center().y() - GLYPH / 2, GLYPH, GLYPH)
        paint_level_glyph(painter, glyph, level)
        painter.setPen(QColor(style.color))
        font = option.font
        font.setWeight(font.Weight.DemiBold)
        painter.setFont(font)
        text_rect = rect.adjusted(10 + GLYPH + 8, 0, -4, 0)
        painter.drawText(text_rect, int(Qt.AlignmentFlag.AlignVCenter), style.label)
        painter.restore()

    def sizeHint(
        self, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex
    ) -> QSize:
        base = super().sizeHint(option, index)
        return QSize(max(base.width(), 150), max(base.height(), TOKENS.row_height))


class LevelBadge(QWidget):
    """Glyph plus word, for the detail panel."""

    def __init__(self, level: Level = Level.OK, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._level = level
        self.setAccessibleName("Nível")
        self.setMinimumHeight(24)

    def set_level(self, level: Level) -> None:
        self._level = level
        self.setAccessibleDescription(level_style(level).label)
        self.update()

    def level(self) -> Level:
        return self._level

    def sizeHint(self) -> QSize:
        return QSize(160, 24)

    def paintEvent(self, event: object) -> None:
        style = level_style(self._level)
        painter = QPainter(self)
        paint_level_glyph(
            painter, QRectF(2, (self.height() - GLYPH) / 2, GLYPH, GLYPH), self._level
        )
        painter.setPen(QColor(style.color))
        font = self.font()
        font.setWeight(font.Weight.DemiBold)
        painter.setFont(font)
        painter.drawText(
            QRect(GLYPH + 10, 0, self.width() - GLYPH - 10, self.height()),
            int(Qt.AlignmentFlag.AlignVCenter),
            style.label,
        )


class RiskBadge(QWidget):
    """Shape plus word for a risk level (docs/DESIGN.md 3.12)."""

    def __init__(self, risk: Risk, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._risk = risk
        self.setAccessibleName("Nível de risco")
        self.setAccessibleDescription(risk.label)
        self.setMinimumHeight(24)

    def risk(self) -> Risk:
        return self._risk

    def sizeHint(self) -> QSize:
        return QSize(120, 24)

    def paintEvent(self, event: object) -> None:
        style = risk_style(self._risk)
        painter = QPainter(self)
        paint_risk_glyph(painter, QRectF(2, (self.height() - GLYPH) / 2, GLYPH, GLYPH), self._risk)
        painter.setPen(QColor(style.color))
        font = self.font()
        font.setWeight(font.Weight.DemiBold)
        painter.setFont(font)
        painter.drawText(
            QRect(GLYPH + 10, 0, self.width() - GLYPH - 10, self.height()),
            int(Qt.AlignmentFlag.AlignVCenter),
            self._risk.label,
        )


class HomeCard(QPushButton):
    """One entry of the home menu: a single button (keyboard, accessible name = title + lead)."""

    def __init__(self, title: str, lead: str, *, soon: bool = False, deep: bool = False) -> None:
        super().__init__()
        self.setProperty("role", "card")
        if deep:
            self.setProperty("deep", "true")
        self.setAutoDefault(False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(96 if not deep else 120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setAccessibleName(f"{title}. {lead}" + (f" {catalog.HOME_SOON}." if soon else ""))
        lay = QVBoxLayout(self)
        lay.setContentsMargins(TOKENS.space_4, TOKENS.space_3, TOKENS.space_4, TOKENS.space_3)
        lay.setSpacing(TOKENS.space_1)
        self.title_label = make_label(title, "subtitle", wrap=False)
        self.lead_label = make_label(lead, "lead")
        lay.addWidget(self.title_label)
        lay.addWidget(self.lead_label)
        if soon:
            lay.addWidget(make_label(catalog.HOME_SOON, "small", wrap=False))
        lay.addStretch(1)
        for label in self.findChildren(QLabel):
            label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)


class CollapsibleGroup(QWidget):
    """A header button that opens and closes its content. The arrow and the words say the state."""

    toggled = Signal(bool)

    def __init__(self, title: str, *, expanded: bool) -> None:
        super().__init__()
        self._title = title
        self._count = 0
        self._marked = 0
        self.header = QPushButton()
        self.header.setProperty("role", "group")
        self.header.setAutoDefault(False)
        self.header.setCheckable(True)
        self.header.setChecked(expanded)
        self.header.toggled.connect(self._on_toggled)
        self.content = QFrame()
        self.content.setProperty("role", "groupbody")
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(TOKENS.space_3, TOKENS.space_2, 0, TOKENS.space_2)
        self.content_layout.setSpacing(0)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(TOKENS.space_1)
        lay.addWidget(self.header)
        lay.addWidget(self.content)
        self.content.setVisible(expanded)
        self._refresh()

    def set_counts(self, count: int, marked: int) -> None:
        self._count, self._marked = count, marked
        self._refresh()

    def is_expanded(self) -> bool:
        return self.header.isChecked()

    def set_expanded(self, expanded: bool) -> None:
        self.header.setChecked(expanded)

    def _on_toggled(self, expanded: bool) -> None:
        self.content.setVisible(expanded)
        self._refresh()
        self.toggled.emit(expanded)

    def _refresh(self) -> None:
        expanded = self.header.isChecked()
        text = catalog.GROUP_HEADER.format(
            arrow="▾" if expanded else "▸",
            title=self._title,
            n=self._count,
            itens="item" if self._count == 1 else "itens",
            k=self._marked,
        )
        self.header.setText(text)
        self.header.setAccessibleName(
            f"{self._title}, {'aberto' if expanded else 'fechado'}: {self._count} "
            f"{'item' if self._count == 1 else 'itens'}, {self._marked} para remover"
        )
