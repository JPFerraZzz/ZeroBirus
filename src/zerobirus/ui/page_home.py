"""The home menu: clickable cards, the deep analysis last, at the bottom (docs/DESIGN.md 3.11)."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import QGridLayout, QWidget

from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import HomeCard, make_label

WIDE = 760  # logical points: three columns from here, two below it, one below NARROW
NARROW = 460


class HomePage(Page):
    chosen = Signal(str)  # the key of the card

    def __init__(self) -> None:
        super().__init__(catalog.HOME_TITLE, catalog.HOME_LEAD, scroll_body=True)
        self.cards: dict[str, HomeCard] = {}
        self.grid_host = QWidget()
        self.grid_host.setObjectName("page")
        self.grid = QGridLayout(self.grid_host)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(TOKENS.space_4)
        self.grid.setVerticalSpacing(TOKENS.space_4)
        for key, title, lead, available in catalog.HOME_CARDS:
            card = HomeCard(title, lead, soon=not available)
            card.clicked.connect(lambda _=False, k=key: self._on_card(k))
            self.cards[key] = card
        self.deep = HomeCard(catalog.HOME_DEEP_TITLE, catalog.HOME_DEEP_LEAD, deep=True)
        self.deep.clicked.connect(lambda: self._on_card(catalog.HOME_DEEP))
        self.cards[catalog.HOME_DEEP] = self.deep
        self.note = make_label("", "lead", name="Aviso")
        self.body.addWidget(self.grid_host)
        self.body.addWidget(self.note)
        self.body.addStretch(1)
        self._columns = 0
        self._layout_cards(3)

    def _on_card(self, key: str) -> None:
        if key == catalog.HOME_DEEP:
            self.note.setText("")
            self.chosen.emit(key)
            return
        available = {k: ok for k, _t, _l, ok in catalog.HOME_CARDS}
        if available.get(key, False):
            self.note.setText("")
            self.chosen.emit(key)
        else:
            self.note.setText(catalog.HOME_SOON_NOTE)

    def _layout_cards(self, columns: int) -> None:
        if columns == self._columns:
            return
        self._columns = columns
        while self.grid.count():
            self.grid.takeAt(0)
        small = [self.cards[k] for k, *_ in catalog.HOME_CARDS]
        for i, card in enumerate(small):
            self.grid.addWidget(card, i // columns, i % columns)
        last_row = (len(small) + columns - 1) // columns
        # The deep analysis: last, on its own row, as wide as the menu.
        self.grid.addWidget(self.deep, last_row, 0, 1, columns)
        for c in range(columns):
            self.grid.setColumnStretch(c, 1)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        width = self.width()
        self._layout_cards(3 if width >= WIDE else 2 if width >= NARROW else 1)

    def on_enter(self) -> None:
        self.cards[catalog.HOME_CARDS[0][0]].setFocus()
