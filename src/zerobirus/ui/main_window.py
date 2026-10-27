"""The window: stage rail on the left, the current page on the right, gates between stages."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QResizeEvent
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from zerobirus import __version__
from zerobirus.core.context import Answers, check_order, emphasised
from zerobirus.core.diagnosis import Diagnosis
from zerobirus.core.models import TempEntry
from zerobirus.core.plan import AuthorizedPlan, Plan, build_plan, plan_to_dict
from zerobirus.core.report import build_report
from zerobirus.core.session import Session, create_session, update_session
from zerobirus.platform.base import Inspector
from zerobirus.platform.fake.ops import FakeOps
from zerobirus.platform.loader import create_remediation_ops
from zerobirus.remediation.engine import Remediation
from zerobirus.remediation.ops import SystemOps
from zerobirus.scanners.runner import ScanResult
from zerobirus.ui import catalog
from zerobirus.ui.page_authorize import AuthorizePage
from zerobirus.ui.page_base import Page
from zerobirus.ui.page_context import ContextPage
from zerobirus.ui.page_diagnosis import DiagnosisPage
from zerobirus.ui.page_removal import CallWorker, RemovalPage
from zerobirus.ui.page_scan import ScanPage
from zerobirus.ui.theme import MIN_WINDOW, NARROW_BELOW, TOKENS
from zerobirus.ui.widgets import make_label, make_rule

STAGE_KEYS = [key for key, _ in catalog.STAGES]
COMPACT_HEIGHT = 620  # logical points; under it pages use tighter margins


class PlaceholderPage(Page):
    """Stages whose content arrives with the removal and confirmation work."""

    def __init__(self, title: str, lead: str) -> None:
        super().__init__(title, lead)
        self.note = make_label(catalog.PLACEHOLDER_LATER, "lead")
        self.body.addWidget(self.note)
        self.body.addStretch(1)

    def set_note(self, text: str) -> None:
        self.note.setText(text)


class MainWindow(QMainWindow):
    def __init__(
        self,
        inspector: Inspector,
        *,
        demo: bool,
        data_dir: Path,
        desktop_dir: Path | None,
        animations: bool = True,
        relaunch: Callable[[], bool] | None = None,
        clock: Callable[[], datetime] = datetime.now,
        ops_factory: Callable[[], SystemOps] | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle(f"{catalog.APP_NAME} {catalog.SIGNATURE}")
        self.setMinimumSize(*MIN_WINDOW)
        self.inspector = inspector
        self.demo = demo
        self.data_dir = data_dir
        self.desktop_dir = desktop_dir
        self._clock = clock
        self._ops_factory = ops_factory
        self.temp_entries: tuple[TempEntry, ...] = ()
        self._temp_worker: CallWorker | None = None
        self.answers = Answers()
        self.result: ScanResult | None = None
        self.diagnosis: Diagnosis | None = None
        self.plan: Plan | None = None
        self.authorization: AuthorizedPlan | None = None
        self.session: Session | None = None
        self._unlocked = 0
        self._compact = False

        root = QWidget()
        root.setObjectName("root")
        root.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # left: identity and stage rail
        side = QWidget()
        side.setObjectName("root")
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(TOKENS.space_4, TOKENS.space_5, 0, TOKENS.space_4)
        side_layout.setSpacing(TOKENS.space_3)
        self.logo = QSvgWidget(str(resources.files("zerobirus.ui").joinpath("assets/logo.svg")))
        self.logo.setFixedSize(40, 40)
        self.logo.setAccessibleName("Sinal do ZeroBirus")
        self.brand = make_label(catalog.APP_NAME, "title", wrap=False, name="ZeroBirus")
        self.signature = make_label(catalog.SIGNATURE, "signature", wrap=False)
        side_layout.addWidget(self.logo)
        side_layout.addWidget(self.brand)
        side_layout.addWidget(self.signature)
        side_layout.addWidget(make_rule())
        self.rail = QListWidget()
        self.rail.setObjectName("rail")
        self.rail.setAccessibleName("Etapas")
        self.rail.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        # Seven short rows always fit; scrollbars here only eat the narrow compact rail.
        self.rail.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.rail.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        side_layout.addWidget(self.rail, 1)
        self.side = side
        layout.addWidget(side)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        # pages
        self.context_page = ContextPage(
            elevated=inspector.is_elevated(), demo=demo, relaunch=relaunch
        )
        self.scan_page = ScanPage(inspector, animations=animations)
        self.diagnosis_page = DiagnosisPage()
        self.authorize_page = AuthorizePage()
        self.removal_page = RemovalPage()
        self.confirm_page = PlaceholderPage(catalog.STAGES[5][1], catalog.STAGE_LEAD["confirm"])
        self.after_page = PlaceholderPage(catalog.STAGES[6][1], catalog.STAGE_LEAD["after"])
        self.pages: list[Page] = [
            self.context_page,
            self.scan_page,
            self.diagnosis_page,
            self.authorize_page,
            self.removal_page,
            self.confirm_page,
            self.after_page,
        ]
        for page in self.pages:
            self.stack.addWidget(page)
        for i, (_key, name) in enumerate(catalog.STAGES, start=1):
            item = QListWidgetItem(f"{i}  {name}")
            item.setData(Qt.ItemDataRole.AccessibleTextRole, f"Etapa {i}: {name}")
            self.rail.addItem(item)
        self.rail.currentRowChanged.connect(self._on_rail)

        # wiring
        self.context_page.done.connect(self._on_context_done)
        self.scan_page.scan_finished.connect(self._on_scan_finished)
        self.scan_page.next_button.clicked.connect(lambda: self.go("diagnosis"))
        self.diagnosis_page.continue_requested.connect(self._to_authorization)
        self.authorize_page.back_requested.connect(lambda: self.go("diagnosis"))
        self.authorize_page.kept_all.connect(self._on_kept_all)
        self.authorize_page.authorized.connect(self._on_authorized)
        self.removal_page.proceed.connect(self._after_removal)

        self._refresh_rail()
        self.go("context")

    # navigation -----------------------------------------------------------------------

    def stage(self) -> str:
        return STAGE_KEYS[self.stack.currentIndex()]

    def unlocked_stage(self) -> str:
        return STAGE_KEYS[self._unlocked]

    def go(self, key: str) -> None:
        index = STAGE_KEYS.index(key)
        if index > self._unlocked:
            return  # the gates: nothing opens before the previous stage is finished
        self.stack.setCurrentIndex(index)
        self.rail.blockSignals(True)
        self.rail.setCurrentRow(index)
        self.rail.blockSignals(False)
        self._refresh_rail()
        self.pages[index].on_enter()

    def _unlock(self, key: str) -> None:
        self._unlocked = max(self._unlocked, STAGE_KEYS.index(key))
        self._refresh_rail()

    def _on_rail(self, row: int) -> None:
        if 0 <= row < len(STAGE_KEYS):
            self.go(STAGE_KEYS[row])

    def _refresh_rail(self) -> None:
        current = self.stack.currentIndex()
        for i in range(self.rail.count()):
            item = self.rail.item(i)
            name = catalog.STAGES[i][1]
            state = "atual" if i == current else "concluída" if i < self._unlocked else ""
            number = f"{i + 1}"
            item.setText(
                number
                if self._compact
                else f"{number}  {name}" + (f"\n    {state}" if state else "")
            )
            item.setToolTip(f"Etapa {number}: {name}" + (f" ({state})" if state else ""))
            enabled = i <= self._unlocked
            flags = item.flags()
            item.setFlags(
                flags | Qt.ItemFlag.ItemIsEnabled if enabled else flags & ~Qt.ItemFlag.ItemIsEnabled
            )
        self.setWindowTitle(f"{catalog.APP_NAME} {catalog.SIGNATURE}: {catalog.STAGES[current][1]}")

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        for page in self.pages:
            page.set_compact(self.height() < COMPACT_HEIGHT)
        compact = self.width() < NARROW_BELOW
        if compact != self._compact:
            self._compact = compact
            self.side.setFixedWidth(64 if compact else 200)
            self.brand.setVisible(not compact)
            self.signature.setVisible(not compact)
            self._refresh_rail()
        elif self.side.minimumWidth() == 0:
            self.side.setFixedWidth(64 if compact else 200)

    # flow -----------------------------------------------------------------------------

    def _on_context_done(self, answers: object) -> None:
        if not isinstance(answers, Answers):
            return
        self.answers = answers
        if self.session is None:
            self.session = create_session(
                self.data_dir,
                self._clock(),
                tool_version=__version__,
                elevated=self.inspector.is_elevated(),
            )
        self.session.write(
            "context.json",
            {
                "symptoms": sorted(s.value for s in answers.symptoms),
                "other_text": answers.other_text,
            },
        )
        self.scan_page.set_order(check_order(answers), emphasised(answers))
        self._unlock("verify")
        self.go("verify")

    def _on_scan_finished(self, result: object) -> None:
        if not isinstance(result, ScanResult):
            return
        self.result = result
        self.diagnosis_page.set_result(result)
        self.diagnosis = self.diagnosis_page.diagnosis
        if self.session is not None:
            self.session.write("findings.json", build_report(result, include_snapshot=False))
            update_session(self.session, stage="diagnosis")
        self._unlock("diagnosis")
        self._temp_worker = CallWorker(self.inspector.temp_entries)
        self._temp_worker.start()

    def _collect_temp_entries(self, value: object) -> None:
        items: Any = getattr(value, "items", None)
        if isinstance(items, tuple):
            found: tuple[Any, ...] = items  # pyright: ignore[reportUnknownVariableType]
            self.temp_entries = tuple(e for e in found if isinstance(e, TempEntry))

    def wait_background(self) -> None:
        if self._temp_worker is not None:
            self._temp_worker.wait()
            self._collect_temp_entries(self._temp_worker.result)

    def _to_authorization(self) -> None:
        if self.result is None:
            return
        self.wait_background()  # the Temp listing started when the scan ended
        self.plan = build_plan(
            self.result.checks,
            self.result.snapshot.system,
            self.result.snapshot,
            self.temp_entries,
        )
        desktop = self.result.snapshot.desktop
        self.authorize_page.configure(
            session_id=self.session.session_id if self.session else "sem-sessao",
            desktop=Path(desktop) if desktop else self.desktop_dir,
            clock=lambda: self._clock().isoformat(timespec="seconds"),
            save_session=self._save_plan,
        )
        self.authorize_page.set_plan(self.plan)
        self._unlock("authorize")
        self.go("authorize")

    def _save_plan(self, plan: Plan, approved: list[str]) -> None:
        if self.session is not None:
            self.session.write("plan.json", plan_to_dict(plan, approved))
            update_session(self.session, stage="authorized")

    def _on_kept_all(self) -> None:
        if self.session is not None:
            update_session(self.session, stage="kept_all")
        self.after_page.set_note("Não foi removido nada, como pediste.")
        self._unlock("after")
        self.go("after")

    def _on_authorized(self, authorization: object) -> None:
        if not isinstance(authorization, AuthorizedPlan):
            return
        self.authorization = authorization
        if self.session is None or self.result is None:
            return
        ops = self._make_ops()
        remediation = Remediation(ops, self.result.snapshot.system, self.session)
        update_session(self.session, stage="removal")
        self._unlock("removal")
        self.go("removal")
        self.removal_page.start(authorization, remediation)

    def _make_ops(self) -> SystemOps:
        if self._ops_factory is not None:
            return self._ops_factory()
        if self.demo or self.result is None:
            if self.result is None:
                raise RuntimeError("não há resultado da verificação")
            return FakeOps.from_snapshot(self.result.snapshot, self.temp_entries)
        return create_remediation_ops()

    def _after_removal(self) -> None:
        if self.session is not None:
            update_session(self.session, stage="removed")
        self.confirm_page.set_note(
            "A confirmação (repetir a verificação e analisar com o Microsoft Defender) "
            "chega na próxima versão."
        )
        self._unlock("confirm")
        self.go("confirm")
