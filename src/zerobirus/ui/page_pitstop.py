"""PitStop modules: BigDiag (read-only report) and AllUp (app updates through winget)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QCheckBox, QScrollArea, QVBoxLayout, QWidget

from zerobirus import __version__
from zerobirus.core.allup import UpdatePlan, UpdateResult, Upgrade, authorize_updates
from zerobirus.core.bigdiag import STATUS_WORD, DiagReport, Section, build_report, render_text
from zerobirus.core.drivers import (
    LINKS,
    OPTIONAL_UPDATES,
    installed_section,
    pending_section,
    vendor_links,
)
from zerobirus.core.firstsetup import (
    CATEGORIES,
    SCRIPT_NAME,
    SECURITY_NOTE,
    by_category,
    render_script,
)
from zerobirus.core.session import Session, create_session
from zerobirus.platform.base import DiagProbe, Inspector, MemoryProbe, PackageUpdater
from zerobirus.remediation.updates import run_updates
from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.page_game import ChoiceRow
from zerobirus.ui.page_removal import CallWorker
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import CollapsibleGroup, clear_layout, make_label, make_rule


@dataclass(frozen=True, slots=True)
class PitstopServices:
    inspector: Inspector
    diag_factory: Callable[[], DiagProbe]
    memory_factory: Callable[[], MemoryProbe]
    updater_factory: Callable[[], PackageUpdater]
    driver_factory: Callable[[], DiagProbe]
    opener: Callable[[str], None]
    data_dir: Path
    desktop_dir: Path | None
    clock: Callable[[], datetime]


class PitstopPage(Page):
    back_requested = Signal()

    def __init__(self, title: str, lead: str) -> None:
        super().__init__(title, lead)
        self.services: PitstopServices | None = None
        self._worker: CallWorker | None = None
        self.status = make_label("", name="Estado")
        self.scroller = QScrollArea()
        self.scroller.setWidgetResizable(True)
        self.scroller.setFrameShape(QScrollArea.Shape.NoFrame)
        self.host = QWidget()
        self.host.setObjectName("page")
        self.list_layout = QVBoxLayout(self.host)
        self.list_layout.setContentsMargins(0, 0, TOKENS.space_3, 0)
        self.scroller.setWidget(self.host)
        self.body.addWidget(self.status)
        self.body.addWidget(self.scroller, 1)
        self.back_button = button(catalog.PITSTOP_BACK)
        self.back_button.clicked.connect(self.back_requested)
        self.back_button.setDefault(True)
        self.left_actions.addWidget(self.back_button)

    @property
    def svc(self) -> PitstopServices:
        if self.services is None:
            raise RuntimeError("a página não foi configurada")
        return self.services

    def configure(self, services: PitstopServices) -> None:
        self.services = services

    def wait(self) -> None:
        if self._worker is not None:
            self._worker.wait()

    def _start(self, fn: Callable[[], Any], then: Callable[[Any], None]) -> None:
        self.wait()
        worker = CallWorker(fn)
        worker.done.connect(then)
        self._worker = worker
        worker.start()

    def _fill(self, widgets: list[QWidget]) -> None:
        clear_layout(self.list_layout)
        for w in widgets:
            self.list_layout.addWidget(w)
        self.list_layout.addStretch(1)

    def on_enter(self) -> None:
        self.back_button.setFocus()


class BigDiagPage(PitstopPage):
    def __init__(self) -> None:
        super().__init__("BigDiag", catalog.BIGDIAG_LEAD)
        self.report: DiagReport | None = None
        self.saved_path: Path | None = None
        self.save_button = button(catalog.BIGDIAG_SAVE)
        self.save_button.clicked.connect(self._save)
        self.save_button.setEnabled(False)
        self.run_button = button(catalog.BIGDIAG_RUN, "primary")
        self.run_button.clicked.connect(self._run)
        self.left_actions.addWidget(self.save_button)
        self.right_actions.addWidget(self.run_button)

    def on_enter(self) -> None:
        super().on_enter()
        self.status.setText(catalog.BIGDIAG_LEAD2)
        self.run_button.setFocus()

    def _run(self) -> None:
        svc = self.svc
        self.run_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.status.setText(catalog.BIGDIAG_RUNNING)
        self._start(lambda: self._collect(svc), self._on_done)

    @staticmethod
    def _collect(svc: PitstopServices) -> DiagReport:
        raw = svc.diag_factory().read()
        memory = svc.memory_factory().snapshot()
        defender = next(iter(svc.inspector.defender().items), None)
        return build_report(
            raw,
            memory=memory,
            defender=defender,
            generated_at=svc.clock().strftime("%Y-%m-%d %H:%M"),
        )

    def _on_done(self, value: object) -> None:
        self.run_button.setEnabled(True)
        if isinstance(value, BaseException):
            self.status.setText(catalog.REMOVAL_FAILED.format(reason=str(value)[:200]))
            return
        report = cast("DiagReport", value)
        self.report = report
        self.status.setText(catalog.BIGDIAG_SUMMARY.format(status=STATUS_WORD[report.status.value]))
        widgets: list[QWidget] = []
        for s in report.sections:
            widgets.append(
                make_label(f"{s.title}: {STATUS_WORD[s.status.value]}", "subtitle", wrap=False)
            )
            for line in s.lines:
                widgets.append(
                    make_label(f"{line.label}: {line.value} ({STATUS_WORD[line.status.value]})")
                )
            if s.note:
                widgets.append(make_label(s.note, "small"))
            widgets.append(make_rule())
        self._fill(widgets)
        self.save_button.setEnabled(True)

    def _save(self) -> None:
        if self.report is None:
            return
        svc = self.svc
        folder = svc.desktop_dir or svc.data_dir
        name = f"ZeroBirus-BigDiag-{svc.clock().strftime('%Y%m%d-%H%M%S')}.txt"
        try:
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / name
            path.write_text(render_text(self.report, version=__version__), encoding="utf-8-sig")
        except OSError as exc:
            self.status.setText(f"Não foi possível guardar o relatório ({exc.strerror or exc}).")
            return
        self.saved_path = path
        self.status.setText(catalog.BIGDIAG_SAVED.format(path=path))


class AllUpPage(PitstopPage):
    def __init__(self) -> None:
        super().__init__("AllUp", catalog.ALLUP_LEAD)
        self.listed: tuple[Upgrade, ...] = ()
        self.rows: dict[str, ChoiceRow] = {}
        self.results: tuple[UpdateResult, ...] = ()
        self._session: Session | None = None
        self._stop = False
        self.ack = QCheckBox(catalog.ALLUP_ACK)
        self.ack.toggled.connect(self._refresh)
        self.body.addWidget(self.ack)
        self.all_button = button(catalog.ALLUP_TICK_ALL, "link")
        self.all_button.clicked.connect(self._tick_all)
        self.stop_button = button(catalog.ALLUP_STOP)
        self.stop_button.clicked.connect(self._on_stop)
        self.stop_button.setVisible(False)
        self.apply_button = button("&Atualizar", "primary")
        self.apply_button.clicked.connect(self._apply)
        self.left_actions.addWidget(self.all_button)
        self.left_actions.addWidget(self.stop_button)
        self.right_actions.addWidget(self.apply_button)

    def on_enter(self) -> None:
        super().on_enter()
        self.status.setText(catalog.ALLUP_LISTING)
        self.apply_button.setEnabled(False)
        self.ack.setChecked(False)
        updater = self.svc.updater_factory()
        self._start(updater.list_upgrades, self._on_listed)

    def _on_listed(self, value: object) -> None:
        if isinstance(value, BaseException):
            self.status.setText(catalog.ALLUP_FAILED.format(reason=str(value)[:200]))
            self._fill([])
            return
        self.listed = cast("tuple[Upgrade, ...]", value)
        self.rows = {}
        widgets: list[QWidget] = []
        for u in self.listed:
            row = ChoiceRow(
                f"{u.name}", f"{u.id}: {u.version} → {u.available}", "", checked=False, enabled=True
            )
            row.check.toggled.connect(self._refresh)
            self.rows[u.id] = row
            widgets.append(row)
        if not widgets:
            widgets.append(make_label(catalog.ALLUP_NONE, "lead"))
        self.status.setText(
            catalog.ALLUP_FOUND.format(n=len(self.listed)) if self.listed else catalog.ALLUP_NONE
        )
        self._fill(widgets)
        self._refresh()

    def selected(self) -> list[str]:
        return [k for k, r in self.rows.items() if r.check.isChecked()]

    def _tick_all(self) -> None:
        for row in self.rows.values():
            row.check.setChecked(True)

    def _refresh(self) -> None:
        n = len(self.selected())
        self.ack.setEnabled(n > 0)
        self.apply_button.setText(
            catalog.ALLUP_APPLY_ONE if n == 1 else catalog.ALLUP_APPLY_N.format(n=n)
        )
        self.apply_button.setEnabled(n > 0 and self.ack.isChecked())

    def _apply(self) -> None:
        chosen = self.selected()
        if not chosen:
            return
        svc = self.svc
        if self._session is None:
            self._session = create_session(
                svc.data_dir,
                svc.clock(),
                tool_version=__version__,
                elevated=svc.inspector.is_elevated(),
            )
        plan: UpdatePlan = authorize_updates(
            self.listed,
            chosen,
            session_id=self._session.session_id,
            authorised_at=svc.clock().isoformat(timespec="seconds"),
        )
        # The plan is on disk before anything is installed.
        self._session.write("allup-plan.json", {"ids": list(plan.ids), "digest": plan.digest})
        updater = svc.updater_factory()
        listed = self.listed
        self._stop = False
        self.apply_button.setEnabled(False)
        self.stop_button.setVisible(True)
        self.status.setText(catalog.ALLUP_RUNNING)
        self._start(
            lambda: run_updates(plan, listed, updater, should_stop=lambda: self._stop),
            self._on_run,
        )

    def _on_stop(self) -> None:
        self._stop = True
        self.stop_button.setEnabled(False)

    def _on_run(self, value: object) -> None:
        self.stop_button.setVisible(False)
        self.stop_button.setEnabled(True)
        if isinstance(value, BaseException):
            self.status.setText(catalog.ALLUP_FAILED.format(reason=str(value)[:200]))
            return
        self.results = cast("tuple[UpdateResult, ...]", value)
        ok = sum(r.confirmed for r in self.results)
        self.status.setText(catalog.ALLUP_DONE.format(ok=ok, n=len(self.results)))
        widgets: list[QWidget] = []
        for r in self.results:
            word = "Confirmada" if r.confirmed else "Não confirmada"
            widgets.append(make_label(f"{word}: {r.name}", "subtitle", wrap=False))
            widgets.append(make_label(r.detail, "small"))
            widgets.append(make_rule())
        self._fill(widgets)


def _section_widgets(sections: list[Section]) -> list[QWidget]:
    widgets: list[QWidget] = []
    for s in sections:
        widgets.append(
            make_label(f"{s.title}: {STATUS_WORD[s.status.value]}", "subtitle", wrap=False)
        )
        for line in s.lines:
            widgets.append(
                make_label(f"{line.label}: {line.value} ({STATUS_WORD[line.status.value]})")
            )
        if s.note:
            widgets.append(make_label(s.note, "small"))
        widgets.append(make_rule())
    return widgets


class FirstSetupPage(PitstopPage):
    def __init__(self) -> None:
        super().__init__("FirstSetup", catalog.FIRST_LEAD)
        self.boxes: dict[str, QCheckBox] = {}
        self.groups: dict[str, CollapsibleGroup] = {}
        self.saved_path: Path | None = None
        widgets: list[QWidget] = []
        for category in CATEGORIES:
            group = CollapsibleGroup(
                category, expanded=category == CATEGORIES[0], marked_word="marcadas"
            )
            if category == "Security":
                group.content_layout.addWidget(make_label(SECURITY_NOTE, "small"))
            for app in by_category(category):
                label = app.name + ("" if app.verified else catalog.FIRST_UNVERIFIED)
                box = QCheckBox(label)
                box.setAccessibleName(app.name)
                box.toggled.connect(self._refresh)
                group.content_layout.addWidget(box)
                self.boxes[app.id] = box
            self.groups[category] = group
            widgets.append(group)
        self._fill(widgets)
        self.create_button = button(catalog.FIRST_CREATE_N.format(n=0), "primary")
        self.create_button.clicked.connect(self._create)
        self.right_actions.addWidget(self.create_button)
        self._refresh()

    def on_enter(self) -> None:
        super().on_enter()
        self.status.setText(catalog.FIRST_LEAD)

    def selected(self) -> list[str]:
        return [i for i, b in self.boxes.items() if b.isChecked()]

    def _refresh(self) -> None:
        chosen = set(self.selected())
        for category, group in self.groups.items():
            apps = by_category(category)
            group.set_counts(len(apps), sum(a.id in chosen for a in apps))
        n = len(chosen)
        self.create_button.setText(
            catalog.FIRST_CREATE_ONE if n == 1 else catalog.FIRST_CREATE_N.format(n=n)
        )
        self.create_button.setEnabled(n > 0)

    def _create(self) -> None:
        ids = self.selected()
        if not ids:
            self.status.setText(catalog.FIRST_NONE)
            return
        svc = self.svc
        try:
            text = render_script(ids, version=__version__)
            folder = svc.desktop_dir or svc.data_dir
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / SCRIPT_NAME
            n = 2
            while path.exists():  # never overwrite a file the person may have kept
                path = folder / SCRIPT_NAME.replace(".cmd", f"-{n}.cmd")
                n += 1
            path.write_bytes(text.encode("ascii"))
        except (OSError, ValueError) as exc:
            self.status.setText(f"Não foi possível criar o instalador ({exc}).")
            return
        self.saved_path = path
        self.status.setText(catalog.FIRST_DONE.format(path=path))


class DriversPage(PitstopPage):
    def __init__(self) -> None:
        super().__init__("AllDrivers", catalog.DRIVERS_LEAD)
        self.sections: list[Section] = []
        self.links: list[str] = []
        self.opened: list[str] = []
        self.link_buttons: list[QWidget] = []
        self.run_button = button(catalog.DRIVERS_RUN, "primary")
        self.run_button.clicked.connect(self._run)
        self.open_button = button("&Atualizações opcionais do Windows")
        self.open_button.clicked.connect(lambda: self._open(OPTIONAL_UPDATES))
        self.left_actions.addWidget(self.open_button)
        self.right_actions.addWidget(self.run_button)

    def on_enter(self) -> None:
        super().on_enter()
        self.status.setText(catalog.DRIVERS_LEAD)

    def _run(self) -> None:
        svc = self.svc
        self.run_button.setEnabled(False)
        self.status.setText(catalog.DRIVERS_RUNNING)
        self._start(lambda: dict(svc.driver_factory().read()), self._on_done)

    def _on_done(self, value: object) -> None:
        self.run_button.setEnabled(True)
        if isinstance(value, BaseException):
            self.status.setText(catalog.REMOVAL_FAILED.format(reason=str(value)[:200]))
            return
        raw = cast("dict[str, Any]", value)
        today = self.svc.clock().date()
        self.sections = [installed_section(raw, today), pending_section(raw)]
        widgets = _section_widgets(self.sections)
        self.links = vendor_links(raw)
        for url in self.links:
            link = button(LINKS[url], "link")
            link.clicked.connect(lambda _=False, u=url: self._open(u))
            widgets.append(link)
        self._fill(widgets)
        self.status.setText(catalog.DRIVERS_DONE)

    def _open(self, uri: str) -> None:
        self.open_with(self.svc.opener, uri)

    def open_with(self, opener: Callable[[str], None], uri: str) -> None:
        try:
            opener(uri)
        except (OSError, ValueError, RuntimeError) as exc:
            self.status.setText(catalog.DRIVERS_OPEN_FAILED.format(reason=str(exc)[:120]))
            return
        self.opened.append(uri)
