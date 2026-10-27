"""The common frame of every page: title, a plain sentence about what happens, content, actions."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import make_label, make_rule


def button(text: str, role: str = "", *, name: str = "") -> QPushButton:
    b = QPushButton(text)
    if role:
        b.setProperty("role", role)
    b.setAccessibleName(name or text.replace("&", ""))
    b.setAutoDefault(False)
    return b


class Page(QWidget):
    """Title, lead sentence, body and a bottom action bar (safe action left, main action right)."""

    def __init__(self, title: str, lead: str, *, scroll_body: bool = False) -> None:
        super().__init__()
        self.setObjectName("page")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        outer = QVBoxLayout(self)
        t = TOKENS
        self.outer = outer
        outer.setContentsMargins(t.space_6, t.space_5, t.space_6, t.space_4)
        outer.setSpacing(t.space_2)
        self._spacers: list[int] = []
        self.title_label = make_label(title, "title", wrap=False, name="Título da página")
        self.lead_label = make_label(lead, "lead", name="O que vai acontecer")
        outer.addWidget(self.title_label)
        outer.addWidget(self.lead_label)
        self._gap(outer, t.space_3)
        outer.addWidget(make_rule())
        self._gap(outer, t.space_3)
        self.body = QVBoxLayout()
        self.body.setSpacing(t.space_3)
        if scroll_body:
            # Pages made of a simple column scroll instead of squeezing on small windows.
            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setFrameShape(QScrollArea.Shape.NoFrame)
            host = QWidget()
            host.setObjectName("page")
            self.body.setContentsMargins(0, 0, t.space_3, 0)
            host.setLayout(self.body)
            area.setWidget(host)
            area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            outer.addWidget(area, 1)
        else:
            outer.addLayout(self.body, 1)
        self._gap(outer, t.space_3)
        outer.addWidget(make_rule())
        self._gap(outer, t.space_3)
        self.action_bar = QHBoxLayout()
        self.action_bar.setSpacing(t.space_3)
        self.left_actions = QHBoxLayout()
        self.right_actions = QHBoxLayout()
        self.left_actions.setSpacing(t.space_2)
        self.right_actions.setSpacing(t.space_2)
        self.action_bar.addLayout(self.left_actions)
        self.action_bar.addStretch(1)
        self.action_bar.addLayout(self.right_actions)
        outer.addLayout(self.action_bar)

    def _gap(self, layout: QVBoxLayout, size: int) -> None:
        self._spacers.append(layout.count())
        layout.addSpacing(size)

    def set_compact(self, compact: bool) -> None:
        """Small windows (1280x720 at 150% is about 853x480 points): tighter margins and gaps."""
        t = TOKENS
        if compact:
            self.outer.setContentsMargins(t.space_4, t.space_2, t.space_4, t.space_2)
            gap = t.space_1
        else:
            self.outer.setContentsMargins(t.space_6, t.space_5, t.space_6, t.space_4)
            gap = t.space_3
        for index in self._spacers:
            item = self.outer.itemAt(index)
            if isinstance(item, QSpacerItem):
                item.changeSize(0, gap, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self.outer.invalidate()

    def set_lead(self, text: str) -> None:
        self.lead_label.setText(text)

    def on_enter(self) -> None:
        """Called when the page becomes the current one."""
