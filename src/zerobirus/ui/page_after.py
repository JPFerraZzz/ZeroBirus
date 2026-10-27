"""Stage 6: what to do next, the final report, and freeing the work folder."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtWidgets import QMessageBox

from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.widgets import make_label


class AfterPage(Page):
    def __init__(self) -> None:
        super().__init__("Depois", catalog.STAGE_LEAD["after"], scroll_body=True)
        self.note = make_label("", "lead")
        self.body.addWidget(self.note)
        self.advice_labels: list[str] = []
        self.advice_box = make_label("", name="Conselhos")
        self.body.addWidget(self.advice_box)
        self.status = make_label("", name="Estado")
        self.body.addWidget(self.status)
        self.body.addStretch(1)
        self._save: Callable[[], Path | None] | None = None
        self._purge: Callable[[], list[str]] | None = None
        self.save_button = button(catalog.BTN_SAVE_FINAL, "primary")
        self.save_button.clicked.connect(self._on_save)
        self.clean_button = button(catalog.BTN_CLEAN_WORK)
        self.clean_button.clicked.connect(self._on_clean)
        self.left_actions.addWidget(self.clean_button)
        self.right_actions.addWidget(self.save_button)

    def set_note(self, text: str) -> None:
        self.note.setText(text)

    def configure(
        self,
        advice: list[str],
        save: Callable[[], Path | None] | None,
        purge: Callable[[], list[str]] | None,
    ) -> None:
        self.advice_labels = advice
        self.advice_box.setText("\n\n".join(advice))
        self._save, self._purge = save, purge
        self.save_button.setEnabled(save is not None)
        self.clean_button.setEnabled(purge is not None)

    def _on_save(self) -> None:
        if self._save is None:
            return
        try:
            path = self._save()
        except OSError as exc:
            self.status.setText(f"Não foi possível guardar o relatório: {exc.strerror or exc}")
            return
        self.status.setText(f"Relatório guardado em {path}")

    def _on_clean(self) -> None:
        if self._purge is None:
            return
        ask = QMessageBox.question(
            self,
            "Apagar a pasta de trabalho",
            catalog.CLEAN_WORK_ASK,
            QMessageBox.StandardButton.No | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.No,
        )
        if ask != QMessageBox.StandardButton.Yes:
            return
        try:
            done = self._purge()
        except OSError as exc:
            self.status.setText(f"Não foi possível apagar: {exc.strerror or exc}")
            return
        self.status.setText(
            "Pasta de trabalho apagada; os relatórios ficaram."
            if done
            else "Não havia nada para apagar."
        )
