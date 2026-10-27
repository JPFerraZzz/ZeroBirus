"""Stage 1: the read-only scan, with a sentence before each check and a determinate progress bar."""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import QHBoxLayout, QProgressBar, QScrollArea, QVBoxLayout, QWidget

from zerobirus.core.context import Answers, check_order
from zerobirus.core.models import CheckResult, Level
from zerobirus.platform.base import Inspector
from zerobirus.scanners.runner import ScanCancelled, ScanResult, run_scan
from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import LevelBadge, clear_layout, make_label


class ScanWorker(QThread):
    check_done = Signal(str, object)
    finished_ok = Signal(object)
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, inspector: Inspector) -> None:
        super().__init__()
        self._inspector = inspector
        self.cancel_event = threading.Event()

    def run(self) -> None:
        try:
            result = run_scan(
                self._inspector,
                on_check_done=lambda name, res: self.check_done.emit(name, res),
                cancel=self.cancel_event,
            )
        except ScanCancelled:
            self.cancelled.emit()
        except Exception as exc:  # shown to the person; the scan itself never raises for data
            self.failed.emit(f"{type(exc).__name__}: {str(exc)[:200]}")
        else:
            self.finished_ok.emit(result)


class CheckRow(QWidget):
    def __init__(self, check: str, emphasised: bool) -> None:
        super().__init__()
        self.check = check
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, TOKENS.space_2, 0, TOKENS.space_2)
        lay.setSpacing(TOKENS.space_1)
        head = QHBoxLayout()
        title = catalog.CHECK_TITLE[check] + ("  (em destaque)" if emphasised else "")
        self.title = make_label(title, "subtitle", wrap=False, name=f"Verificação {check}")
        self.status = make_label("A aguardar", "small", wrap=False)
        self.badge = LevelBadge(Level.OK)
        self.badge.setVisible(False)
        head.addWidget(self.title)
        head.addStretch(1)
        head.addWidget(self.badge)
        head.addWidget(self.status)
        lay.addLayout(head)
        lay.addWidget(make_label(catalog.CHECK_SIMPLE[check], "lead"))
        self.tech = make_label(catalog.CHECK_TECH[check], "mono")
        self.tech.setVisible(False)
        lay.addWidget(self.tech)

    def set_result(self, result: CheckResult) -> None:
        self.badge.set_level(result.level)
        self.badge.setVisible(True)
        self.status.setText(
            "incompleta: " + result.reason if not result.verified else f"{result.inspected} vistos"
        )
        self.status.setToolTip(result.reason)

    def set_running(self) -> None:
        self.status.setText("A verificar")


class ScanPage(Page):
    scan_finished = Signal(object)  # ScanResult

    def __init__(self, inspector: Inspector, *, animations: bool = True) -> None:
        super().__init__("Verificação", catalog.STAGE_LEAD["verify"])
        self._inspector = inspector
        self._animations = animations
        self._worker: ScanWorker | None = None
        self._total = len(check_order(Answers()))
        self._done = 0
        self._rows: dict[str, CheckRow] = {}
        self.result: ScanResult | None = None

        self.scroller = QScrollArea()
        self.scroller.setWidgetResizable(True)
        self.scroller.setFrameShape(QScrollArea.Shape.NoFrame)
        self.list_host = QWidget()
        self.list_host.setObjectName("page")
        self.scroller.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.scroller.setWidget(self.list_host)
        self.body.addWidget(self.scroller, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, self._total)
        self.progress.setFormat("%v/%m")
        self.progress.setAccessibleName("Progresso da verificação")
        self.progress_text = make_label("", "small", wrap=False)
        self.status = make_label("", name="Estado da verificação")
        self.body.addWidget(self.progress)
        self.body.addWidget(self.progress_text)
        self.body.addWidget(self.status)

        self.cancel_button = button(catalog.BTN_CANCEL_SCAN)
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel)
        self.tech_button = button(catalog.BTN_SHOW_DETAIL, "link")
        self.tech_button.setCheckable(True)
        self.tech_button.toggled.connect(self._toggle_tech)
        self.start_button = button(catalog.BTN_START_SCAN, "primary")
        self.start_button.clicked.connect(self.start)
        self.next_button = button(catalog.BTN_SEE_DIAGNOSIS, "primary")
        self.next_button.setVisible(False)
        self.left_actions.addWidget(self.cancel_button)
        self.left_actions.addWidget(self.tech_button)
        self.right_actions.addWidget(self.start_button)
        self.right_actions.addWidget(self.next_button)
        self.set_order(check_order(Answers()), frozenset())

    def set_order(self, order: tuple[str, ...], emphasised: frozenset[str]) -> None:
        clear_layout(self.list_layout)
        self._rows.clear()
        for check in order:
            row = CheckRow(check, check in emphasised)
            row.tech.setVisible(self.tech_button.isChecked())
            self._rows[check] = row
            self.list_layout.addWidget(row)
        self.list_layout.addStretch(1)

    def rows(self) -> dict[str, CheckRow]:
        return self._rows

    def _toggle_tech(self, shown: bool) -> None:
        self.tech_button.setText(catalog.BTN_HIDE_DETAIL if shown else catalog.BTN_SHOW_DETAIL)
        for row in self._rows.values():
            row.tech.setVisible(shown)

    def start(self) -> None:
        if self._worker is not None:
            return
        self._done = 0
        self.progress.setValue(0)
        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status.setText("" if self._animations else catalog.PROGRESS_NO_ANIMATION)
        self._update_progress_text()
        for row in self._rows.values():
            row.set_running()
        worker = ScanWorker(self._inspector)
        self._worker = worker
        worker.check_done.connect(self._on_check)
        worker.finished_ok.connect(self._on_finished)
        worker.cancelled.connect(self._on_cancelled)
        worker.failed.connect(self._on_failed)
        worker.start()

    def cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel_event.set()
            self.cancel_button.setEnabled(False)

    def wait(self, timeout_ms: int = 60_000) -> None:
        worker = self._worker
        if worker is not None:
            worker.wait(timeout_ms)

    def _update_progress_text(self) -> None:
        self.progress_text.setText(catalog.PROGRESS_TEXT.format(done=self._done, total=self._total))

    def _on_check(self, name: str, result: object) -> None:
        self._done += 1
        self.progress.setValue(self._done)
        self._update_progress_text()
        row = self._rows.get(name)
        if row is not None and isinstance(result, CheckResult):
            row.set_result(result)

    def _finish_thread(self) -> None:
        worker, self._worker = self._worker, None
        if worker is not None:
            worker.wait(5000)
            worker.deleteLater()
        self.cancel_button.setEnabled(False)

    def _on_finished(self, result: object) -> None:
        self._finish_thread()
        if not isinstance(result, ScanResult):
            return
        self.result = result
        self.status.setText(catalog.SCAN_DONE)
        self.start_button.setVisible(False)
        self.next_button.setVisible(True)
        self.next_button.setFocus()
        self.scan_finished.emit(result)

    def _on_cancelled(self) -> None:
        self._finish_thread()
        self.status.setText(catalog.SCAN_CANCELLED)
        self.start_button.setEnabled(True)
        self.progress.setValue(0)
        for row in self._rows.values():
            row.status.setText("A aguardar")
            row.badge.setVisible(False)

    def _on_failed(self, reason: str) -> None:
        self._finish_thread()
        self.status.setText(catalog.SCAN_FAILED.format(reason=reason))
        self.start_button.setEnabled(True)
