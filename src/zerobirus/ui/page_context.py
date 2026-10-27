"""Stage 0: what did the person notice, and are we running as administrator."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QCheckBox, QLineEdit

from zerobirus.core.context import Answers, Symptom
from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import make_label


class ContextPage(Page):
    done = Signal(object)  # Answers

    def __init__(
        self, *, elevated: bool, demo: bool, relaunch: Callable[[], bool] | None = None
    ) -> None:
        super().__init__("Contexto", catalog.STAGE_LEAD["context"], scroll_body=True)
        self._relaunch = relaunch
        self.body.addWidget(make_label("O que notaste no PC?", "subtitle", wrap=False))
        self.boxes: dict[Symptom, QCheckBox] = {}
        for symptom in Symptom:
            box = QCheckBox(catalog.SYMPTOM_LABELS[symptom])
            self.boxes[symptom] = box
            self.body.addWidget(box)
        self.other = QLineEdit()
        self.other.setPlaceholderText("Descreve com as tuas palavras")
        self.other.setAccessibleName("Outra coisa que notaste")
        self.other.setEnabled(False)
        self.other.setMaxLength(300)
        self.boxes[Symptom.OTHER].toggled.connect(self.other.setEnabled)
        self.body.addWidget(self.other)
        self.body.addSpacing(TOKENS.space_4)

        self.admin_label = make_label(
            catalog.ADMIN_OK if elevated else catalog.ADMIN_MISSING, name="Estado de administrador"
        )
        self.body.addWidget(self.admin_label)
        self.restart = button(catalog.ADMIN_RESTART, "link")
        self.restart.setVisible(not elevated)
        self.restart.setEnabled(not demo)
        if demo and not elevated:
            self.restart.setToolTip(catalog.ADMIN_RESTART_DISABLED_DEMO)
        self.restart.clicked.connect(self._on_restart)
        self.body.addWidget(self.restart)
        self.body.addStretch(1)

        self.next_button = button(catalog.BTN_NEXT, "primary")
        self.next_button.clicked.connect(self._on_next)
        self.right_actions.addWidget(self.next_button)

    def answers(self) -> Answers:
        chosen = frozenset(s for s, box in self.boxes.items() if box.isChecked())
        text = self.other.text() if Symptom.OTHER in chosen else ""
        return Answers(chosen, text)

    def _on_next(self) -> None:
        self.done.emit(self.answers())

    def _on_restart(self) -> None:
        if self._relaunch is not None and self._relaunch():
            from PySide6.QtWidgets import QApplication

            QApplication.quit()
