"""Stage 4: carry out the authorised plan, show what happened item by item, and undo."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from zerobirus.core.models import ActionResult
from zerobirus.core.plan import ActionType, AuthorizedPlan
from zerobirus.remediation.engine import (
    ItemResult,
    Outcome,
    Remediation,
    RestorePointFailed,
    UndoResult,
)
from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import clear_layout, make_label, make_rule

_UNDOABLE = (ActionResult.REMOVIDO, ActionResult.EM_QUARENTENA)
_NO_UNDO = frozenset({ActionType.KILL_PROCESS})


def _undo_results(value: object) -> list[UndoResult]:
    if not isinstance(value, list):
        return []
    rows: list[Any] = value  # pyright: ignore[reportUnknownVariableType]
    return [u for u in rows if isinstance(u, UndoResult)]


class CallWorker(QThread):
    """Runs one function off the interface thread and hands back its result or its error."""

    done = Signal(object)

    def __init__(self, fn: Callable[[], Any]) -> None:
        super().__init__()
        self._fn = fn
        self.result: object = None  # set before ``done`` fires, so a waiter can read it too

    def run(self) -> None:
        try:
            self.result = self._fn()
        except Exception as exc:
            self.result = exc
        self.done.emit(self.result)


class ResultRow(QWidget):
    def __init__(self, result: ItemResult, undo: QPushButton | None) -> None:
        super().__init__()
        self.item_id = result.item_id
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, TOKENS.space_2, 0, TOKENS.space_2)
        lay.setSpacing(TOKENS.space_1)
        self.head = make_label(
            f"{catalog.RESULT_LABEL[result.result.value]}: {result.target}",
            "subtitle",
            wrap=True,
            name=f"Resultado de {result.target}",
        )
        self.detail = make_label(result.detail, "small")
        lay.addWidget(self.head)
        lay.addWidget(self.detail)
        self.undo = undo
        if undo is not None:
            lay.addWidget(undo)


class RemovalPage(Page):
    proceed = Signal()

    def __init__(self) -> None:
        super().__init__("Remoção", catalog.STAGE_LEAD["removal"])
        self._plan: AuthorizedPlan | None = None
        self._remediation: Remediation | None = None
        self._worker: CallWorker | None = None
        self._results: dict[str, ItemResult] = {}
        self._rows: dict[str, ResultRow] = {}
        self.outcome: Outcome | None = None

        self.status = make_label("", name="Estado da remoção")
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setAccessibleName("A remover")
        self.progress.setVisible(False)
        self.scroller = QScrollArea()
        self.scroller.setWidgetResizable(True)
        self.scroller.setFrameShape(QScrollArea.Shape.NoFrame)
        self.host = QWidget()
        self.host.setObjectName("page")
        self.list_layout = QVBoxLayout(self.host)
        self.list_layout.setContentsMargins(0, 0, TOKENS.space_3, 0)
        self.scroller.setWidget(self.host)
        for w in (self.status, self.progress):
            self.body.addWidget(w)
        self.body.addWidget(self.scroller, 1)

        self.stop_button = button(catalog.BTN_STOP_NOTHING_CHANGED)
        self.stop_button.clicked.connect(self._stop)
        self.go_on_button = button(catalog.BTN_GO_ON_WITHOUT_RESTORE, "danger")
        self.go_on_button.clicked.connect(lambda: self._run(proceed=True))
        self.undo_all_button = button(catalog.BTN_UNDO_ALL)
        self.undo_all_button.clicked.connect(self._undo_all)
        self.delete_button = button(catalog.BTN_DELETE_QUARANTINE, "link")
        self.delete_button.clicked.connect(self._delete_quarantine)
        self.continue_button = button(catalog.BTN_CONTINUE_CONFIRM, "primary")
        self.continue_button.clicked.connect(self.proceed)
        for b in (self.stop_button, self.undo_all_button, self.delete_button):
            self.left_actions.addWidget(b)
        for b in (self.go_on_button, self.continue_button):
            self.right_actions.addWidget(b)
        self._buttons(restore_choice=False, finished=False)

    # control --------------------------------------------------------------------------

    def start(self, plan: AuthorizedPlan, remediation: Remediation) -> None:
        self._plan = plan
        self._remediation = remediation
        self._run(proceed=False)

    def wait(self) -> None:
        if self._worker is not None:
            self._worker.wait()

    def _buttons(self, *, restore_choice: bool, finished: bool) -> None:
        self.stop_button.setVisible(restore_choice)
        self.go_on_button.setVisible(restore_choice)
        self.undo_all_button.setVisible(finished)
        self.delete_button.setVisible(finished)
        self.continue_button.setVisible(finished)
        self.stop_button.setEnabled(restore_choice)
        self.go_on_button.setEnabled(restore_choice)

    def _start_worker(self, fn: Callable[[], Any], then: Callable[[Any], None]) -> None:
        self.wait()
        worker = CallWorker(fn)
        worker.done.connect(then)
        self._worker = worker
        worker.start()

    def _run(self, *, proceed: bool) -> None:
        if self._plan is None or self._remediation is None:
            return
        plan, remediation = self._plan, self._remediation
        self._buttons(restore_choice=False, finished=False)
        self.status.setText(catalog.REMOVAL_RUNNING)
        self.progress.setVisible(True)
        self._start_worker(
            lambda: remediation.run(plan, proceed_without_restore_point=proceed), self._on_run
        )

    def _on_run(self, value: object) -> None:
        self.progress.setVisible(False)
        if isinstance(value, RestorePointFailed):
            self.status.setText(catalog.REMOVAL_NO_RESTORE.format(reason=value.reason))
            self._buttons(restore_choice=True, finished=False)
            self.stop_button.setFocus()
        elif isinstance(value, Outcome):
            self._show(value)
        else:
            self.status.setText(catalog.REMOVAL_FAILED.format(reason=str(value)[:200]))

    def _stop(self) -> None:
        self.status.setText("Parado. Nada foi alterado.")
        self._buttons(restore_choice=False, finished=False)

    # results --------------------------------------------------------------------------

    def _show(self, outcome: Outcome) -> None:
        self.outcome = outcome
        self._results = {r.item_id: r for r in outcome.results}
        clear_layout(self.list_layout)
        self._rows = {}
        for r in outcome.results:
            undo: QPushButton | None = None
            if r.result in _UNDOABLE and r.action not in _NO_UNDO:
                undo = button(catalog.BTN_UNDO_ITEM, name=f"Desfazer {r.target}")
                undo.clicked.connect(lambda _=False, i=r.item_id: self._undo_one(i))
            row = ResultRow(r, undo)
            self._rows[r.item_id] = row
            self.list_layout.addWidget(row)
            self.list_layout.addWidget(make_rule())
        self.list_layout.addStretch(1)
        done = sum(r.result in _UNDOABLE for r in outcome.results)
        failed = sum(r.result is ActionResult.FALHOU for r in outcome.results)
        self.status.setText(
            catalog.REMOVAL_SUMMARY.format(
                done=done,
                failed=failed,
                ignored=len(outcome.results) - done - failed,
                restore=outcome.restore_point,
            )
        )
        self._buttons(restore_choice=False, finished=True)
        self.undo_all_button.setEnabled(done > 0)
        self.delete_button.setEnabled(
            any(r.result is ActionResult.EM_QUARENTENA for r in outcome.results)
        )
        self.continue_button.setFocus()

    def _apply_undo(self, undone: list[UndoResult]) -> None:
        for u in undone:
            row = self._rows.get(u.item_id)
            if row is None:
                continue
            row.detail.setText(u.detail)
            if u.ok:
                row.head.setText(f"Desfeito: {self._results[u.item_id].target}")
                if row.undo is not None:
                    row.undo.setEnabled(False)
        self.status.setText(
            "Desfeito." if all(u.ok for u in undone) else "Alguns itens não puderam ser desfeitos."
        )

    def _undo_one(self, item_id: str) -> None:
        remediation = self._remediation
        if remediation is None:
            return
        self._start_worker(
            lambda: [remediation.undo_item(item_id)],
            lambda v: self._apply_undo(_undo_results(v)),
        )

    def _undo_all(self) -> None:
        remediation = self._remediation
        if remediation is None:
            return
        self.undo_all_button.setEnabled(False)
        self._start_worker(
            remediation.undo_session,
            lambda v: self._apply_undo(_undo_results(v)),
        )

    def _delete_quarantine(self) -> None:
        remediation = self._remediation
        if remediation is None or self.outcome is None:
            return
        ask = QMessageBox.question(
            self,
            "Apagar a quarentena",
            catalog.DELETE_QUARANTINE_ASK,
            QMessageBox.StandardButton.No | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.No,
        )
        if ask != QMessageBox.StandardButton.Yes:
            return
        ids = [r.item_id for r in self.outcome.results if r.result is ActionResult.EM_QUARENTENA]
        self._start_worker(
            lambda: remediation.delete_quarantined(ids),
            lambda v: self._after_delete(_undo_results(v)),
        )

    def _after_delete(self, value: list[UndoResult]) -> None:
        for u in value:
            row = self._rows.get(u.item_id)
            if row is not None and u.ok:
                row.detail.setText(u.detail)
                if row.undo is not None:
                    row.undo.setEnabled(False)
        self.status.setText("Quarentena apagada de vez.")
