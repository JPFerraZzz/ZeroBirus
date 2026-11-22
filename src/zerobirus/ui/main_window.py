"""The window: stage rail on the left, the current page on the right, gates between stages."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent, QResizeEvent
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
from zerobirus.core.after import advice, render_final_report
from zerobirus.core.compare import (
    Change,
    baseline_from_checks,
    baseline_from_json,
    baseline_to_json,
)
from zerobirus.core.context import Answers, check_order, emphasised
from zerobirus.core.diagnosis import Diagnosis
from zerobirus.core.models import TempEntry
from zerobirus.core.plan import AuthorizedPlan, Plan, build_plan, plan_to_dict
from zerobirus.core.redact import redact
from zerobirus.core.report import build_report
from zerobirus.core.session import (
    Session,
    create_session,
    find_pending_restart_check,
    open_session,
    update_session,
)
from zerobirus.platform.base import DefenderScanner, Inspector, MemoryProbe
from zerobirus.platform.fake.defender_scan import FakeDefenderScanner
from zerobirus.platform.fake.memory import FakeMemoryProbe
from zerobirus.platform.fake.ops import FakeOps
from zerobirus.platform.loader import (
    create_defender_scanner,
    create_memory_probe,
    create_remediation_ops,
    restart_computer,
)
from zerobirus.remediation.cleanup import purge_session_work
from zerobirus.remediation.engine import Remediation
from zerobirus.remediation.ops import SystemOps
from zerobirus.scanners.runner import ScanResult
from zerobirus.ui import catalog
from zerobirus.ui.page_after import AfterPage
from zerobirus.ui.page_authorize import AuthorizePage
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.page_confirm import ConfirmPage
from zerobirus.ui.page_context import ContextPage
from zerobirus.ui.page_diagnosis import DiagnosisPage
from zerobirus.ui.page_game import FpsPage, GameModulePage, GameServices, MegaPage, RamPage
from zerobirus.ui.page_home import HomePage, HubPage
from zerobirus.ui.page_removal import CallWorker, RemovalPage
from zerobirus.ui.page_scan import ScanPage
from zerobirus.ui.theme import MIN_WINDOW, NARROW_BELOW, TOKENS
from zerobirus.ui.widgets import make_label, make_rule

STAGE_KEYS = [key for key, _ in catalog.STAGES]
COMPACT_HEIGHT = 620  # logical points; under it pages use tighter margins


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
        defender_factory: Callable[[], DefenderScanner] | None = None,
        memory_factory: Callable[[], MemoryProbe] | None = None,
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
        self.baseline: list[Change] = []
        self.kept_all = False
        self.answers = Answers()
        self.result: ScanResult | None = None
        self.diagnosis: Diagnosis | None = None
        self.plan: Plan | None = None
        self.authorization: AuthorizedPlan | None = None
        self.session: Session | None = None
        self._unlocked = 0
        self._compact = False

        # Two screens: the home menu, and the seven-stage flow of the deep analysis.
        self.screens = QStackedWidget()
        self.home_page = HomePage()
        self.hubs = {key: HubPage(key) for key in catalog.HUBS}
        flow = QWidget()
        flow.setObjectName("root")
        flow.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QHBoxLayout(flow)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # left: identity and stage rail
        side = QWidget()
        side.setObjectName("root")
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(TOKENS.space_4, TOKENS.space_5, 0, TOKENS.space_4)
        side_layout.setSpacing(TOKENS.space_3)
        self.logo = QSvgWidget(
            str(resources.files("zerobirus.ui").joinpath("assets/logo-dark.svg"))
        )
        self.logo.setFixedSize(40, 40)
        self.logo.setAccessibleName("Sinal do ZeroBirus")
        self.brand = make_label(catalog.APP_NAME, "title", wrap=False, name="ZeroBirus")
        self.signature = make_label(catalog.SIGNATURE, "signature", wrap=False)
        self.home_button = button(catalog.HOME_BACK, "link")
        self.home_button.clicked.connect(self.show_home)
        side_layout.addWidget(self.logo)
        side_layout.addWidget(self.brand)
        side_layout.addWidget(self.signature)
        side_layout.addWidget(make_rule())
        side_layout.addWidget(self.home_button)
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
        self.screens.addWidget(self.home_page)
        self.screens.addWidget(flow)
        for hub in self.hubs.values():
            self.screens.addWidget(hub)
            hub.back_requested.connect(self.show_home)
            hub.opened.connect(self.show_module)
        # Modo Jogo modules that exist; the others are skeleton cards in their hub.
        self.modules: dict[str, GameModulePage] = {
            "fps": FpsPage(),
            "ram": RamPage(),
            "mega": MegaPage(),
        }
        services = GameServices(
            inspector,
            ops_factory or self._default_ops,
            memory_factory or (FakeMemoryProbe if demo else create_memory_probe),
            data_dir,
            clock,
        )
        for module in self.modules.values():
            module.configure(services)
            self.screens.addWidget(module)
            module.back_requested.connect(lambda: self.show_hub(catalog.HOME_GAME))
        self.setCentralWidget(self.screens)

        # pages
        self.context_page = ContextPage(
            elevated=inspector.is_elevated(), demo=demo, relaunch=relaunch
        )
        self.scan_page = ScanPage(inspector, animations=animations)
        self.diagnosis_page = DiagnosisPage()
        self.authorize_page = AuthorizePage()
        self.removal_page = RemovalPage()
        self.confirm_page = ConfirmPage(
            inspector,
            defender_factory or (FakeDefenderScanner if demo else create_defender_scanner),
            None if demo else restart_computer,
        )
        self.after_page = AfterPage()
        self.home_page.chosen.connect(self._on_home_choice)
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
        self.confirm_page.proceed.connect(self._to_after)
        self.context_page.post_restart_requested.connect(self._on_post_restart)
        pending = find_pending_restart_check(data_dir)
        if pending:
            self.context_page.show_pending(pending[0])

        self._refresh_rail()
        self.go("context")
        self.show_home()

    # navigation -----------------------------------------------------------------------

    def show_home(self) -> None:
        self.screens.setCurrentWidget(self.home_page)
        self.setWindowTitle(f"{catalog.APP_NAME} {catalog.SIGNATURE}")
        self.home_page.on_enter()

    def show_flow(self) -> None:
        self.screens.setCurrentIndex(1)
        self._refresh_rail()
        self.pages[self.stack.currentIndex()].on_enter()

    def at_home(self) -> bool:
        return self.screens.currentWidget() is self.home_page

    def show_hub(self, key: str) -> None:
        hub = self.hubs[key]
        self.screens.setCurrentWidget(hub)
        self.setWindowTitle(f"{catalog.APP_NAME} {catalog.SIGNATURE}: {catalog.HUBS[key][0]}")
        hub.on_enter()

    def show_module(self, key: str) -> None:
        module = self.modules[key]
        self.screens.setCurrentWidget(module)
        self.setWindowTitle(f"{catalog.APP_NAME} {catalog.SIGNATURE}: {module.title_label.text()}")
        module.on_enter()

    def _default_ops(self) -> SystemOps:
        if self.demo:
            ops = FakeOps()
            for p in FakeMemoryProbe().snapshot().processes:  # the demo programs can be closed
                ops.processes[p.pid] = p.path or ""
            return ops
        return create_remediation_ops()

    def _on_home_choice(self, key: str) -> None:
        if key == catalog.HOME_DEEP:
            self.show_flow()
        elif key in self.hubs:
            self.show_hub(key)

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
        # Leaving mid-scan or mid-removal would hide work that is still running.
        self.home_button.setEnabled(STAGE_KEYS[current] not in ("verify", "removal", "confirm"))
        if self.screens.currentIndex() == 1:
            self.setWindowTitle(
                f"{catalog.APP_NAME} {catalog.SIGNATURE}: {catalog.STAGES[current][1]}"
            )

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        for page in (self.home_page, *self.hubs.values(), *self.modules.values(), *self.pages):
            page.set_compact(self.height() < COMPACT_HEIGHT)
        compact = self.width() < NARROW_BELOW
        if compact != self._compact:
            self._compact = compact
            self.side.setFixedWidth(64 if compact else 200)
            self.brand.setVisible(not compact)
            self.signature.setVisible(not compact)
            self.home_button.setText("←" if compact else catalog.HOME_BACK)
            self.home_button.setToolTip("Menu inicial")
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
            self.baseline = baseline_from_checks(result.checks)
            self.session.write("baseline.json", baseline_to_json(self.baseline))
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
        self.kept_all = True
        self.after_page.set_note("Não foi removido nada, como pediste.")
        self._configure_after()
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
        self.confirm_page.configure(self.session, self.baseline)
        self._unlock("confirm")
        self.go("confirm")

    def _on_post_restart(self, session_id: str) -> None:
        """After a restart: reopen the session that asked for it and go to the confirmation."""
        try:
            session = open_session(self.data_dir, session_id)
            baseline = baseline_from_json(session.read("baseline.json"))
        except (OSError, ValueError, KeyError):
            self.context_page.show_pending_error()
            return
        update_session(session, pending_restart_check=False)
        self.session, self.baseline = session, baseline
        self.confirm_page.configure(session, baseline)
        self._unlock("confirm")
        self.go("confirm")

    def _to_after(self) -> None:
        self.after_page.set_note("Limpeza concluída. Isto é o que convém fazer a seguir.")
        self._configure_after()
        if self.session is not None:
            update_session(self.session, stage="after")
        self._unlock("after")
        self.go("after")

    def _results(self) -> list[tuple[str, str, str]]:
        outcome = self.removal_page.outcome
        if outcome is None:
            return []
        return [(r.target, r.result.value, r.detail) for r in outcome.results]

    def _configure_after(self) -> None:
        outcome = self.removal_page.outcome
        rows = outcome.results if outcome else ()
        lines = advice(
            self.diagnosis,
            [r.result for r in rows],
            anything_failed=bool(self.confirm_page.diff and not self.confirm_page.diff.clean),
        )
        session = self.session

        def save() -> Path | None:
            if session is None:
                return None
            status = self.confirm_page.defender_status
            text = render_final_report(
                version=__version__,
                session_id=session.session_id,
                overall=self.diagnosis.overall.value if self.diagnosis else "-",
                results=[(redact(t), r, d) for t, r, d in self._results()],
                diff_lines=self.confirm_page.diff_lines(),
                defender_text=status.text if status else "não foi feita",
                advice_lines=lines,
            )
            (session.folder / "relatorio-final.txt").write_text(text, encoding="utf-8-sig")
            target = self.desktop_dir or session.folder
            target.mkdir(parents=True, exist_ok=True)
            path = target / f"ZeroBirus-relatorio-final-{session.session_id}.txt"
            path.write_text(text, encoding="utf-8-sig")
            return path

        def purge() -> list[str]:
            return purge_session_work(session) if session is not None else []

        self.after_page.configure(lines, save, purge)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Never destroy a running worker (a removal in progress finishes first)."""
        self.scan_page.cancel()
        self.wait_all()
        super().closeEvent(event)

    def wait_all(self) -> None:
        """Wait for every background thread (tests and shutdown)."""
        self.wait_background()
        self.scan_page.wait()
        self.removal_page.wait()
        self.confirm_page.wait()
        for module in self.modules.values():
            module.wait()
