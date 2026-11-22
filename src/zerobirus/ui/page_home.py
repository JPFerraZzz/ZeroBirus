"""The main menu: three cards, each opening its own screen (docs/DESIGN.md 3.11)."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import QGridLayout, QWidget

from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import HomeCard, make_label

WIDE = 760  # logical points: three columns from here, one below it


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
        for key, title, lead in catalog.HOME_CARDS:
            card = HomeCard(title, lead, deep=key == catalog.HOME_DEEP)
            card.clicked.connect(lambda _=False, k=key: self.chosen.emit(k))
            self.cards[key] = card
        self.deep = self.cards[catalog.HOME_DEEP]
        self.body.addWidget(self.grid_host)
        self.body.addStretch(1)
        self._columns = 0
        self._layout_cards(3)

    def _layout_cards(self, columns: int) -> None:
        if columns == self._columns:
            return
        self._columns = columns
        while self.grid.count():
            self.grid.takeAt(0)
        for i, card in enumerate(self.cards.values()):
            self.grid.addWidget(card, i // columns, i % columns)
        for c in range(3):
            self.grid.setColumnStretch(c, 1 if c < columns else 0)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._layout_cards(3 if self.width() >= WIDE else 1)

    def on_enter(self) -> None:
        self.cards[catalog.HOME_CARDS[0][0]].setFocus()


class HubPage(Page):
    """The screen of one module group (Modo Jogo, PitStop): its modules as cards, all skeleton."""

    back_requested = Signal()
    opened = Signal(str)  # the key of a module that exists

    def __init__(self, key: str) -> None:
        title, lead, modules = catalog.HUBS[key]
        super().__init__(title, lead, scroll_body=True)
        self.key = key
        self.cards: dict[str, HomeCard] = {}
        self.note = make_label("", "lead", name="Aviso")
        self.grid_host = QWidget()
        self.grid_host.setObjectName("page")
        self.grid = QGridLayout(self.grid_host)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(TOKENS.space_4)
        self.grid.setVerticalSpacing(TOKENS.space_4)
        for i, (mkey, mtitle, mlead, _submenu) in enumerate(modules):
            card = HomeCard(mtitle, mlead, soon=True)
            card.clicked.connect(lambda _=False, t=mtitle: self.note.setText(self._note(t)))
            self.cards[mkey] = card
            self.grid.addWidget(card, i // 2, i % 2)
        for c in range(2):
            self.grid.setColumnStretch(c, 1)
        self.body.addWidget(self.grid_host)
        self.body.addWidget(self.note)
        self.body.addStretch(1)
        self.back_button = button(catalog.HUB_BACK)
        self.back_button.clicked.connect(self.back_requested)
        self.back_button.setDefault(True)
        self.left_actions.addWidget(self.back_button)

    @staticmethod
    def _note(title: str) -> str:
        return catalog.MODULE_SOON_NOTE.format(title=title)

    def on_enter(self) -> None:
        self.note.setText("")
        self.back_button.setFocus()
