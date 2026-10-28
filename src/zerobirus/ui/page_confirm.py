"""Stage 5: repeat the scan and show the difference, follow a Defender scan, ask for a restart."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, cast

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QMessageBox, QScrollArea, QVBoxLayout, QWidget

from zerobirus.core.compare import (
    Change,
    ScanDiff,
    baseline_from_checks,
    baseline_to_json,
    compare_scans,
)
from zerobirus.core.defender_scan import ScanState, ScanStatus
from zerobirus.core.redact import redact
from zerobirus.core.session import Session, update_session
from zerobirus.platform.base import DefenderScanner, Inspector
from zerobirus.scanners.runner import ScanResult, run_scan
from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.page_removal import CallWorker
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import clear_layout, make_label, make_rule

_TERMINAL = frozenset({ScanState.COMPLETED, ScanState.STOPPED, ScanState.FAILED, ScanState.UNKNOWN})
SCAN_FILE = "defender_scan.json"


class ConfirmPage(Page):
    proceed = Signal()

    def __init__(
        self,
        inspector: Inspector,
        scanner: Callable[[], DefenderScanner] | None,
        restart: Callable[[], None] | None,
        *,
        poll_ms: int = 15_000,
    ) -> None:
        super().__init__("Confirmação", catalog.STAGE_LEAD["confirm"])
        self._inspector = inspector
        self._scanner_factory = scanner
        self._scanner: DefenderScanner | None = None
        self._restart = restart
        self._worker: CallWorker | None = None
        self._status_worker: CallWorker | None = None
        self.session: Session | None = None
        self.baseline: list[Change] = []
        self.diff: ScanDiff | None = None
        self.second: ScanResult | None = None
        self.defender_status: ScanStatus | None = None

        self.summary = make_label("", name="Resultado da verificação repetida")
        self.scroller = QScrollArea()
        self.scroller.setWidgetResizable(True)
        self.scroller.setFrameShape(QScrollArea.Shape.NoFrame)
        self.host = QWidget()
        self.host.setObjectName("page")
        self.list_layout = QVBoxLayout(self.host)
        self.list_layout.setContentsMargins(0, 0, TOKENS.space_3, 0)
        self.scroller.setWidget(self.host)
        self.defender_label = make_label(catalog.CONFIRM_DEFENDER_NOTE, "small")
        self.offline_label = make_label(catalog.CONFIRM_OFFLINE, "small")
        for w in (self.summary,):
            self.body.addWidget(w)
        self.body.addWidget(self.scroller, 1)
        self.body.addWidget(make_rule())
        self.body.addWidget(self.defender_label)
        self.body.addWidget(self.offline_label)

        self.rescan_button = button(catalog.CONFIRM_RESCAN, "primary")
        self.rescan_button.clicked.connect(self.rescan)
        self.defender_button = button(catalog.CONFIRM_DEFENDER)
        self.defender_button.clicked.connect(self.start_defender)
        self.restart_button = button(catalog.CONFIRM_RESTART)
        self.restart_button.clicked.connect(self._ask_restart)
        self.continue_button = button(catalog.BTN_TO_AFTER)
        self.continue_button.clicked.connect(self.proceed)
        for b in (self.rescan_button, self.defender_button, self.restart_button):
            self.left_actions.addWidget(b)
        self.right_actions.addWidget(self.continue_button)

        self._timer = QTimer(self)
        self._timer.setInterval(poll_ms)
        self._timer.timeout.connect(self._poll)

    # setup ----------------------------------------------------------------------------

    def configure(self, session: Session | None, baseline: list[Change]) -> None:
        self.session = session
        self.baseline = baseline
        self.diff = None

    def on_enter(self) -> None:
        self.rescan_button.setFocus()
        if self.session is not None and (self.session.folder / SCAN_FILE).is_file():
            self._resume_defender()

    def wait(self) -> None:
        for w in (self._worker, self._status_worker):
            if w is not None:
                w.wait()
        self._timer.stop()

    # repeat scan ----------------------------------------------------------------------

    def rescan(self) -> None:
        self.rescan_button.setEnabled(False)
        self.summary.setText(catalog.CONFIRM_RESCANNING)
        inspector = self._inspector
        self._worker = CallWorker(lambda: run_scan(inspector))
        self._worker.done.connect(self._on_rescanned)
        self._worker.start()

    def _on_rescanned(self, value: object) -> None:
        self.rescan_button.setEnabled(True)
        if not isinstance(value, ScanResult):
            self.summary.setText(f"A verificação repetida falhou: {redact(str(value))[:200]}")
            return
        self.second = value
        self.diff = compare_scans(self.baseline, value.checks)
        self._show(self.diff)
        if self.session is not None:
            self.session.write(
                "confirmation.json",
                {
                    "gone": baseline_to_json(self.diff.gone),
                    "remaining": baseline_to_json(self.diff.remaining),
                    "came_back": baseline_to_json(self.diff.came_back),
                    "still_unverified": list(self.diff.still_unverified),
                },
            )

    def _show(self, diff: ScanDiff) -> None:
        clear_layout(self.list_layout)
        for title, rows in (
            ("Desapareceu", diff.gone),
            ("Continua", diff.remaining),
            ("Voltou ou apareceu agora", diff.came_back),
        ):
            if not rows:
                continue
            self.list_layout.addWidget(make_label(title, "subtitle", wrap=False))
            for c in rows:
                self.list_layout.addWidget(make_label(f"{c.item}  ({c.location})", "small"))
        if diff.still_unverified:
            self.list_layout.addWidget(
                make_label("Não foi possível verificar", "subtitle", wrap=False)
            )
            self.list_layout.addWidget(make_label(", ".join(diff.still_unverified), "small"))
        self.list_layout.addStretch(1)
        self.summary.setText(catalog.CONFIRM_CLEAN if diff.clean else catalog.CONFIRM_NOT_CLEAN)

    def diff_lines(self) -> list[str]:
        d = self.diff
        if d is None:
            return []
        out = [f"desapareceu: {c.item}" for c in d.gone]
        out += [f"continua: {c.item}" for c in d.remaining]
        out += [f"voltou ou apareceu: {c.item}" for c in d.came_back]
        out += [f"não foi possível verificar: {c}" for c in d.still_unverified]
        return [redact(x) for x in out]

    # Defender -------------------------------------------------------------------------

    def _get_scanner(self) -> DefenderScanner | None:
        if self._scanner is None and self._scanner_factory is not None:
            self._scanner = self._scanner_factory()
        return self._scanner

    def start_defender(self) -> None:
        try:
            scanner = self._get_scanner()
            if scanner is None or self.session is None:
                raise RuntimeError("não disponível")
            pid, started = scanner.start()
        except Exception as exc:
            self.defender_label.setText(
                f"Não foi possível iniciar a análise: {redact(str(exc))[:200]}"
            )
            return
        self.session.write(SCAN_FILE, {"pid": pid, "started_at": started})
        self.defender_button.setEnabled(False)
        self.defender_label.setText(catalog.CONFIRM_DEFENDER_NOTE)
        self._timer.start()
        self._poll()

    def _resume_defender(self) -> None:
        if self.session is None:
            return
        if self.defender_status is None or self.defender_status.state not in _TERMINAL:
            self.defender_button.setEnabled(False)
            self._timer.start()
            self._poll()

    def _poll(self) -> None:
        scanner = self._get_scanner()
        if self.session is None or scanner is None:
            return
        if self._status_worker is not None and self._status_worker.isRunning():
            return  # a slow read is still going; never replace a running thread
        try:
            saved: Any = json.loads((self.session.folder / SCAN_FILE).read_text("utf-8"))
        except (OSError, ValueError):
            return
        pid: int | None = None
        started: str | None = None
        if isinstance(saved, dict):
            fields = cast("dict[str, Any]", saved)
            raw_pid, raw_start = fields.get("pid"), fields.get("started_at")
            pid = raw_pid if isinstance(raw_pid, int) else None
            started = raw_start if isinstance(raw_start, str) else None
        self._status_worker = CallWorker(lambda: scanner.status(pid, started))
        self._status_worker.done.connect(self._on_status)
        self._status_worker.start()

    def _on_status(self, value: object) -> None:
        if not isinstance(value, ScanStatus):
            return
        self.defender_status = value
        self.defender_label.setText(value.text)
        if value.state in _TERMINAL:
            self._timer.stop()
            self.defender_button.setEnabled(True)

    # restart --------------------------------------------------------------------------

    def _ask_restart(self) -> None:
        if self._restart is None or self.session is None:
            return
        ask = QMessageBox.question(
            self,
            "Reiniciar",
            catalog.CONFIRM_RESTART_ASK,
            QMessageBox.StandardButton.No | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.No,
        )
        if ask != QMessageBox.StandardButton.Yes:
            return
        update_session(self.session, pending_restart_check=True)
        try:
            self._restart()
        except Exception as exc:
            update_session(self.session, pending_restart_check=False)
            self.summary.setText(f"Não foi possível reiniciar: {redact(str(exc))[:200]}")


def baseline_for(result: ScanResult) -> list[Change]:
    return baseline_from_checks(result.checks)
