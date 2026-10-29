"""Modo Jogo modules: FPS Optimizer and RAM Lover (docs/ROADMAP.md, Fase 8).

Both change the system only through the removal engine: a plan the person authorises, the
previous value saved first, the result re-read, and "Repor" to put it back. Everything the
machine reports is shown as plain text.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QCheckBox, QScrollArea, QVBoxLayout, QWidget

from zerobirus import __version__
from zerobirus.core.models import ActionResult
from zerobirus.core.plan import (
    ActionType,
    AuthorizedPlan,
    Plan,
    PlanItem,
    authorize,
    plan_to_dict,
)
from zerobirus.core.ram import (
    MemoryProcess,
    MemorySnapshot,
    candidates,
    closable,
    close_item,
    diagnose,
    megabytes,
    signers_of,
)
from zerobirus.core.session import Session, create_session
from zerobirus.core.tweaks import (
    FPS_TWEAKS,
    MEGA_TWEAKS,
    Danger,
    Tweak,
    tweak_item,
    wanted_value,
)
from zerobirus.platform.base import Inspector, MemoryProbe
from zerobirus.remediation.engine import (
    ItemResult,
    Outcome,
    Remediation,
    RestorePointFailed,
    UndoResult,
)
from zerobirus.remediation.ops import SystemOps
from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.page_removal import CallWorker
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import CollapsibleGroup, WrapText, clear_layout, make_label, make_rule

_DONE = (ActionResult.APLICADO, ActionResult.REMOVIDO)


@dataclass(frozen=True, slots=True)
class GameServices:
    inspector: Inspector
    ops_factory: Callable[[], SystemOps]
    memory_factory: Callable[[], MemoryProbe]
    data_dir: Path
    clock: Callable[[], datetime]


class ChoiceRow(QWidget):
    """A checkbox with a plain explanation underneath and, when needed, a note on its state."""

    def __init__(self, title: str, why: str, note: str, *, checked: bool, enabled: bool) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, TOKENS.space_2, 0, TOKENS.space_2)
        lay.setSpacing(TOKENS.space_1)
        self.check = QCheckBox(title)
        self.check.setAccessibleName(title)
        self.check.setChecked(checked and enabled)
        self.check.setEnabled(enabled)
        lay.addWidget(self.check)
        lay.addWidget(WrapText(why, name="Explicação"))
        if note:
            lay.addWidget(make_label(note, "small"))


class GameModulePage(Page):
    back_requested = Signal()

    def __init__(self, title: str, lead: str) -> None:
        super().__init__(title, lead)
        self.services: GameServices | None = None
        self._worker: CallWorker | None = None
        self._session: Session | None = None
        self._ops: SystemOps | None = None
        self._engine_obj: Remediation | None = None
        self._pending: tuple[AuthorizedPlan, bool] | None = None
        self.results: tuple[ItemResult, ...] = ()

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

        self.back_button = button(catalog.GAME_BACK)
        self.back_button.clicked.connect(self.back_requested)
        self.undo_button = button(catalog.GAME_UNDO_ALL)
        self.undo_button.clicked.connect(self._undo_all)
        self.undo_button.setVisible(False)
        self.continue_button = button(catalog.GAME_CONTINUE_NO_RESTORE, "danger")
        self.continue_button.clicked.connect(self._continue_without_restore)
        self.continue_button.setVisible(False)
        self.apply_button = button("&Aplicar", "primary")
        self.left_actions.addWidget(self.back_button)
        self.left_actions.addWidget(self.undo_button)
        self.right_actions.addWidget(self.continue_button)
        self.right_actions.addWidget(self.apply_button)
        self.back_button.setDefault(True)

    # plumbing -------------------------------------------------------------------------

    def configure(self, services: GameServices) -> None:
        self.services = services
        self._ops = None
        self._engine_obj = None
        self._session = None

    @property
    def svc(self) -> GameServices:
        if self.services is None:
            raise RuntimeError("a página não foi configurada")
        return self.services

    def wait(self) -> None:
        if self._worker is not None:
            self._worker.wait()

    def _start(self, fn: Callable[[], Any], then: Callable[[Any], None]) -> None:
        self.wait()
        worker = CallWorker(fn)
        worker.done.connect(then)
        self._worker = worker
        worker.start()

    def ops(self) -> SystemOps:
        if self._ops is None:
            self._ops = self.svc.ops_factory()
        return self._ops

    def _engine(self) -> Remediation:
        if self._engine_obj is None:
            svc = self.svc
            self._session = create_session(
                svc.data_dir,
                svc.clock(),
                tool_version=__version__,
                elevated=svc.inspector.is_elevated(),
            )
            self._engine_obj = Remediation(
                self.ops(), svc.inspector.system_context(), self._session
            )
        return self._engine_obj

    def _authorise(self, items: list[PlanItem]) -> AuthorizedPlan:
        self._engine()
        if self._session is None:
            raise RuntimeError("não há sessão")
        plan = Plan(tuple(items), ())
        ids = [i.id for i in items]
        # The plan is on disk before anything changes, as in the removal flow.
        self._session.write("plan.json", plan_to_dict(plan, ids))
        return authorize(
            plan,
            ids,
            session_id=self._session.session_id,
            authorised_at=self.svc.clock().isoformat(timespec="seconds"),
            extra_confirmation_count=len(items),
        )

    def _run_plan(self, items: list[PlanItem], *, restore_point: bool) -> None:
        plan = self._authorise(items)
        self._pending = (plan, restore_point)
        self._execute(proceed=False)

    def _execute(self, *, proceed: bool) -> None:
        if self._pending is None:
            return
        plan, restore_point = self._pending
        engine = self._engine()
        self.apply_button.setEnabled(False)
        self.continue_button.setVisible(False)
        self._start(
            lambda: engine.run(
                plan, proceed_without_restore_point=proceed, restore_point=restore_point
            ),
            self._on_run,
        )

    def _continue_without_restore(self) -> None:
        self._execute(proceed=True)

    def _on_run(self, value: object) -> None:
        if isinstance(value, RestorePointFailed):
            self.status.setText(catalog.GAME_NO_RESTORE.format(reason=value.reason))
            self.continue_button.setVisible(True)
            self.apply_button.setEnabled(True)
            return
        if isinstance(value, Outcome):
            self.results = value.results
            self.undo_button.setVisible(any(r.result in _DONE for r in value.results))
            self.after_run(value)
            return
        self.status.setText(catalog.REMOVAL_FAILED.format(reason=str(value)[:200]))
        self.apply_button.setEnabled(True)

    def after_run(self, outcome: Outcome) -> None:
        raise NotImplementedError

    def _undo_all(self) -> None:
        engine = self._engine()
        self.undo_button.setEnabled(False)
        self._start(engine.undo_session, self._on_undo)

    def _on_undo(self, value: object) -> None:
        rows: list[Any] = value if isinstance(value, list) else []  # pyright: ignore[reportUnknownVariableType]
        undone = [u for u in rows if isinstance(u, UndoResult)]
        ok = bool(undone) and all(u.ok for u in undone)
        self.status.setText("Reposto como estava." if ok else "Alguns itens não foram repostos.")
        self.on_undone()

    def on_undone(self) -> None:
        """Hook: refresh the view after "Repor tudo"."""

    def _fill(self, widgets: list[QWidget]) -> None:
        clear_layout(self.list_layout)
        for w in widgets:
            self.list_layout.addWidget(w)
            self.list_layout.addWidget(make_rule())
        self.list_layout.addStretch(1)

    def on_enter(self) -> None:
        self.back_button.setFocus()

    def result_labels(self, outcome: Outcome) -> list[QWidget]:
        out: list[QWidget] = []
        for r in outcome.results:
            box = QWidget()
            lay = QVBoxLayout(box)
            lay.setContentsMargins(0, TOKENS.space_1, 0, TOKENS.space_1)
            lay.addWidget(
                make_label(f"{catalog.RESULT_LABEL[r.result.value]}: {r.target}", "subtitle")
            )
            lay.addWidget(make_label(r.detail, "small"))
            if r.result in _DONE and r.action is not ActionType.KILL_PROCESS:
                undo = button(catalog.GAME_UNDO_ONE, name=f"Repor {r.target}")
                undo.clicked.connect(lambda _=False, i=r.item_id: self._undo_one(i))
                lay.addWidget(undo)
            out.append(box)
        return out

    def _undo_one(self, item_id: str) -> None:
        engine = self._engine()
        self._start(lambda: [engine.undo_item(item_id)], self._on_undo_one)

    def _on_undo_one(self, value: object) -> None:
        rows: list[Any] = value if isinstance(value, list) else []  # pyright: ignore[reportUnknownVariableType]
        undone = [u for u in rows if isinstance(u, UndoResult)]
        ok = bool(undone) and all(u.ok for u in undone)
        self.status.setText(
            "Reposto como estava." if ok else (undone[0].detail if undone else "Não foi reposto.")
        )


def _free(snapshot: MemorySnapshot) -> str:
    return megabytes(snapshot.available)


class TweakPage(GameModulePage):
    """A list of catalog settings; grouped by category when the settings have one."""

    def __init__(self, title: str, lead: str, tweaks: tuple[Tweak, ...], note: str = "") -> None:
        super().__init__(title, lead)
        self._lead = lead
        self._catalog = tweaks
        self._note = note
        self.rows: dict[str, ChoiceRow] = {}
        self.groups: list[CollapsibleGroup] = []
        self._group_rows: list[tuple[CollapsibleGroup, list[ChoiceRow]]] = []
        self._tweaks: dict[str, Tweak] = {}
        self._free_before = ""
        self.risky = QCheckBox(catalog.GAME_RISKY_ACK)
        self.risky.setVisible(False)
        self.risky.toggled.connect(self._refresh)
        self.body.addWidget(self.risky)
        self.apply_button.clicked.connect(self._apply)

    def on_enter(self) -> None:
        super().on_enter()
        if self.services is None:
            return
        svc = self.services
        self.status.setText("A ler o estado atual...")
        self.apply_button.setEnabled(False)
        self.undo_button.setVisible(False)
        self._start(lambda: self._read(svc), self._on_read)

    def _read(self, svc: GameServices) -> tuple[dict[str, str], str, bool]:
        ops = self.ops()
        states: dict[str, str] = {}
        for t in self._catalog:
            item = tweak_item(t)
            try:
                saved = ops.capture(item)
            except LookupError:
                states[t.id] = "unsupported"
                continue
            except Exception:
                states[t.id] = "unreadable"
                continue
            current = saved.get("plan") if "plan" in saved else saved.get("data")
            same = saved.get("present", True) and str(current) == wanted_value(item)
            states[t.id] = "done" if same else "todo"
        return states, _free(svc.memory_factory().snapshot()), svc.inspector.is_elevated()

    def _on_read(self, value: object) -> None:
        if isinstance(value, BaseException):
            self.status.setText(catalog.REMOVAL_FAILED.format(reason=str(value)[:200]))
            return
        states, free, elevated = cast("tuple[dict[str, str], str, bool]", value)
        self._free_before = str(free)
        self.rows = {}
        self._tweaks = {}
        self.groups = []
        self._group_rows = []
        self.risky.setChecked(False)
        sections: dict[str, list[ChoiceRow]] = {}
        for t in self._catalog:
            state = states[t.id]
            note = ""
            enabled = state == "todo"
            if state == "done":
                note = catalog.FPS_STATE_DONE
            elif state == "unsupported":
                note = catalog.FPS_STATE_UNSUPPORTED
            elif state == "unreadable":
                note = catalog.FPS_STATE_UNREADABLE
            elif t.needs_admin and not elevated:
                note, enabled = catalog.FPS_STATE_ADMIN, False
            elif t.needs_reboot:
                note = catalog.FPS_STATE_REBOOT
            row = ChoiceRow(
                f"{t.title} ({t.danger.value})",
                t.why,
                note,
                checked=t.danger is Danger.SEGURO,
                enabled=enabled,
            )
            row.check.toggled.connect(self._refresh)
            self.rows[t.id] = row
            self._tweaks[t.id] = t
            if t.category:
                key = catalog.MEGA_RISKY_GROUP if t.danger is Danger.AGRESSIVO else t.category
                sections.setdefault(key, []).append(row)
        if catalog.MEGA_RISKY_GROUP in sections:  # the risky ones always come last
            sections[catalog.MEGA_RISKY_GROUP] = sections.pop(catalog.MEGA_RISKY_GROUP)
        widgets: list[QWidget] = []
        if sections:
            for i, (title, rows) in enumerate(sections.items()):
                risky = title == catalog.MEGA_RISKY_GROUP
                group = CollapsibleGroup(title, expanded=i == 0, marked_word="marcadas")
                if risky:
                    group.content_layout.addWidget(make_label(catalog.MEGA_RISKY_WARNING, "small"))
                for row in rows:
                    group.content_layout.addWidget(row)
                    group.content_layout.addWidget(make_rule())
                self.groups.append(group)
                self._group_rows.append((group, rows))
                widgets.append(group)
        else:
            widgets.extend(self.rows.values())
        if self._note:
            widgets.append(make_label(self._note, "small"))
        self._fill(widgets)
        self.status.setText(self._lead)
        self._refresh()

    def selected(self) -> list[Tweak]:
        return [self._tweaks[k] for k, r in self.rows.items() if r.check.isChecked()]

    def _refresh(self) -> None:
        chosen = self.selected()
        n = len(chosen)
        risky = any(t.danger is Danger.AGRESSIVO for t in chosen)
        for group, rows in self._group_rows:
            group.set_counts(len(rows), sum(r.check.isChecked() for r in rows))
        self.risky.setVisible(risky)
        self.apply_button.setText(
            catalog.GAME_APPLY_ONE if n == 1 else catalog.GAME_APPLY_N.format(n=n)
        )
        self.apply_button.setEnabled(n > 0 and (not risky or self.risky.isChecked()))

    def _apply(self) -> None:
        chosen = self.selected()
        if not chosen:
            return
        self._run_plan([tweak_item(t) for t in chosen], restore_point=True)

    def after_run(self, outcome: Outcome) -> None:
        svc = self.svc
        done = sum(r.result in _DONE for r in outcome.results)
        failed = len(outcome.results) - done
        after = _free(svc.memory_factory().snapshot())
        parts = [catalog.GAME_RESULT_DONE.format(n=done)]
        if failed:
            parts.append(catalog.GAME_RESULT_FAILED.format(n=failed))
        parts.append(catalog.FPS_RAM_LINE.format(before=self._free_before, after=after))
        self.status.setText(" ".join(parts))
        self._fill(self.result_labels(outcome))
        self.apply_button.setText("&Ver as definições")
        self.apply_button.setEnabled(True)
        self.apply_button.clicked.disconnect()
        self.apply_button.clicked.connect(self._back_to_list)

    def _back_to_list(self) -> None:
        self.apply_button.clicked.disconnect()
        self.apply_button.clicked.connect(self._apply)
        self.on_enter()

    def on_undone(self) -> None:
        self.undo_button.setEnabled(True)
        self.undo_button.setVisible(False)
        self._back_to_list()


class FpsPage(TweakPage):
    def __init__(self) -> None:
        super().__init__("FPS Optimizer", catalog.FPS_LEAD, FPS_TWEAKS, catalog.FPS_BACKGROUND_NOTE)


class MegaPage(TweakPage):
    def __init__(self) -> None:
        super().__init__("MegaTweaker", catalog.MEGA_LEAD, MEGA_TWEAKS)


class RamPage(GameModulePage):
    def __init__(self) -> None:
        super().__init__("RAM Lover", catalog.RAM_LEAD)
        self.rows: dict[int, ChoiceRow] = {}
        self._procs: dict[int, MemoryProcess] = {}
        self._free_before = ""
        self.ack = QCheckBox(catalog.RAM_ACK)
        self.ack.toggled.connect(self._refresh)
        self.body.addWidget(self.ack)
        self.note = make_label(catalog.RAM_NO_STANDBY, "small")
        self.body.addWidget(self.note)
        self.apply_button.clicked.connect(self._close)

    def on_enter(self) -> None:
        super().on_enter()
        if self.services is None:
            return
        svc = self.services
        self.status.setText("A ler a memória...")
        self.apply_button.setEnabled(False)
        self.ack.setChecked(False)
        self.undo_button.setVisible(False)
        self._start(lambda: self._read(svc), self._on_read)

    @staticmethod
    def _read(svc: GameServices) -> tuple[MemorySnapshot, tuple[MemoryProcess, ...]]:
        snap = svc.memory_factory().snapshot()
        ctx = svc.inspector.system_context()
        paths = [p.path for p in candidates(snap, ctx) if p.path]
        sigs = svc.inspector.signatures(paths).items if paths else ()
        return snap, closable(snap, ctx, signers_of(sigs))

    def _on_read(self, value: object) -> None:
        if isinstance(value, BaseException):
            self.status.setText(catalog.REMOVAL_FAILED.format(reason=str(value)[:200]))
            return
        snap, procs = cast("tuple[MemorySnapshot, tuple[MemoryProcess, ...]]", value)
        report = diagnose(snap)
        self._free_before = _free(snap)
        self.status.setText(
            catalog.RAM_SUMMARY.format(
                used=megabytes(report.used),
                total=megabytes(report.total),
                percent=report.percent,
                free=megabytes(report.available),
                pressure=catalog.RAM_PRESSURE_WORD[report.pressure.value],
            )
            + " "
            + report.advice
        )
        self.rows = {}
        self._procs = {}
        widgets: list[QWidget] = []
        for p in procs:
            row = ChoiceRow(
                f"{p.name} ({megabytes(p.rss)})", p.path or "", "", checked=False, enabled=True
            )
            row.check.toggled.connect(self._refresh)
            self.rows[p.pid] = row
            self._procs[p.pid] = p
            widgets.append(row)
        if not widgets:
            widgets.append(make_label(catalog.RAM_NONE, "lead"))
        self._fill(widgets)
        self._refresh()

    def selected(self) -> list[MemoryProcess]:
        return [self._procs[k] for k, r in self.rows.items() if r.check.isChecked()]

    def _refresh(self) -> None:
        n = len(self.selected())
        self.apply_button.setText(
            catalog.RAM_CLOSE_ONE if n == 1 else catalog.RAM_CLOSE_N.format(n=n)
        )
        self.ack.setEnabled(n > 0)
        self.apply_button.setEnabled(n > 0 and self.ack.isChecked())

    def _close(self) -> None:
        chosen = self.selected()
        if not chosen or not self.ack.isChecked():
            return
        # Closing programs has nothing to restore, so no restore point is asked for.
        self._run_plan([close_item(p) for p in chosen], restore_point=False)

    def after_run(self, outcome: Outcome) -> None:
        done = sum(
            r.result in _DONE for r in outcome.results if r.action is ActionType.KILL_PROCESS
        )
        after = _free(self.svc.memory_factory().snapshot())
        self.status.setText(
            catalog.RAM_AFTER.format(
                done=done, n=len(outcome.results), before=self._free_before, after=after
            )
        )
        self._fill(self.result_labels(outcome))
        self.undo_button.setVisible(False)  # a closed program does not come back
        self.apply_button.setEnabled(False)
