"""Stage 3: the exact list of what will change, decided by the person (BRIEF 5.3 and 11).

Friction is proportional and the safe action is the easiest: focus, Enter and Esc go to
"Voltar"; the removing button says what it does and how many, and stays disabled until the
person confirms having read the list.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QHBoxLayout,
    QLineEdit,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from zerobirus import __version__
from zerobirus.core.models import Level
from zerobirus.core.plan import (
    Plan,
    PlanItem,
    authorize,
    needs_extra_confirmation,
    render_plan_text,
)
from zerobirus.ui import catalog
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.theme import TOKENS
from zerobirus.ui.widgets import LevelBadge, WrapText, clear_layout, make_label, make_rule


class PlanItemRow(QWidget):
    """One plan item with its own Remover / Manter choice. CONFERIR starts on Manter."""

    changed = Signal()

    def __init__(self, item: PlanItem) -> None:
        super().__init__()
        self.item = item
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, TOKENS.space_2, 0, TOKENS.space_2)
        lay.setSpacing(TOKENS.space_4)
        choice = QVBoxLayout()
        choice.setSpacing(TOKENS.space_1)
        self.remove = QRadioButton(catalog.DECISION_REMOVE)
        self.keep = QRadioButton(catalog.DECISION_KEEP)
        self.remove.setAccessibleName(f"Remover: {item.target}")
        self.keep.setAccessibleName(f"Manter: {item.target}")
        group = QButtonGroup(self)
        group.addButton(self.remove)
        group.addButton(self.keep)
        (self.remove if item.default_selected else self.keep).setChecked(True)
        self.remove.toggled.connect(self.changed)
        choice.addWidget(self.remove)
        choice.addWidget(self.keep)
        lay.addLayout(choice)
        text = QVBoxLayout()
        text.setSpacing(TOKENS.space_1)
        text.addWidget(WrapText(item.description, name="Ação"))
        text.addWidget(make_label(item.why, "small"))
        lay.addLayout(text, 1)
        badge = LevelBadge(item.level)
        badge.set_level(item.level)
        badge.setFixedWidth(150)
        lay.addWidget(badge)

    def selected(self) -> bool:
        return self.remove.isChecked()


class AuthorizePage(Page):
    authorized = Signal(object)  # AuthorizedPlan
    kept_all = Signal()
    back_requested = Signal()

    def __init__(self) -> None:
        super().__init__("Autorização", catalog.STAGE_LEAD["authorize"])
        self._plan: Plan | None = None
        self._rows: list[PlanItemRow] = []
        self._session_id = ""
        self._desktop: Path | None = None
        self._save_session: Callable[[Plan, list[str]], None] | None = None
        self._clock: Callable[[], str] = lambda: ""
        self.saved_path: Path | None = None

        self.question = make_label(catalog.AUTH_QUESTION, "subtitle", wrap=False)
        self.body.addWidget(self.question)
        self.scroller = QScrollArea()
        self.scroller.setWidgetResizable(True)
        self.scroller.setFrameShape(QScrollArea.Shape.NoFrame)
        self.host = QWidget()
        self.host.setObjectName("page")
        self.scroller.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list_layout = QVBoxLayout(self.host)
        self.list_layout.setContentsMargins(0, 0, TOKENS.space_3, 0)
        self.scroller.setWidget(self.host)
        self.body.addWidget(self.scroller, 1)

        self.summary = make_label("", name="Resumo do que vai ser alterado")
        self.ack = QCheckBox(catalog.AUTH_ACK)
        self.ack.toggled.connect(self._refresh)
        self.extra_label = make_label("", wrap=True)
        self.extra = QLineEdit()
        self.extra.setAccessibleName("Número de itens, para confirmar")
        self.extra.setMaxLength(6)
        self.extra.setFixedWidth(120)
        self.extra.textChanged.connect(self._refresh)
        self.message = make_label("", name="Mensagem")
        for w in (self.summary, self.ack, self.extra_label, self.extra, self.message):
            self.body.addWidget(w)

        self.back_button = button(catalog.BTN_BACK)
        self.back_button.clicked.connect(self.back_requested)
        self.keep_button = button(catalog.BTN_KEEP_ALL)
        self.keep_button.clicked.connect(self.kept_all)
        self.remove_button = button(catalog.BTN_REMOVE_N.format(n=0), "danger")
        self.remove_button.clicked.connect(self._on_remove)
        self.left_actions.addWidget(self.back_button)
        self.left_actions.addWidget(self.keep_button)
        self.right_actions.addWidget(self.remove_button)
        self.back_button.setDefault(True)
        self._esc = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self._esc.activated.connect(self.back_requested)

    # setup ----------------------------------------------------------------------------

    def configure(
        self,
        *,
        session_id: str,
        desktop: Path | None,
        clock: Callable[[], str],
        save_session: Callable[[Plan, list[str]], None] | None = None,
    ) -> None:
        self._session_id = session_id
        self._desktop = desktop
        self._clock = clock
        self._save_session = save_session

    def set_plan(self, plan: Plan) -> None:
        self._plan = plan
        clear_layout(self.list_layout)
        self._rows = []
        if not plan.items:
            self.list_layout.addWidget(make_label(catalog.DIAG_NOTHING, "lead"))
        for title, members in plan.groups():
            self.list_layout.addWidget(make_label(title, "subtitle", wrap=False))
            for level, intro in (
                (Level.SUSPEITO, catalog.AUTH_INTRO_SUSPECT),
                (Level.CONFERIR, catalog.AUTH_INTRO_CONFER),
            ):
                chosen = [m for m in members if m.level is level]
                if not chosen:
                    continue
                self.list_layout.addWidget(make_label(intro, "small"))
                for m in chosen:
                    row = PlanItemRow(m)
                    row.changed.connect(self._refresh)
                    self._rows.append(row)
                    self.list_layout.addWidget(row)
                    self.list_layout.addWidget(make_rule())
            self.list_layout.addSpacing(TOKENS.space_4)
        if plan.not_plannable:
            self.list_layout.addWidget(
                make_label(catalog.AUTH_NOT_PLANNABLE, "subtitle", wrap=False)
            )
            for n in plan.not_plannable:
                self.list_layout.addWidget(make_label(f"{n.item}: {n.reason}", "small"))
        self.list_layout.addStretch(1)
        self.ack.setChecked(False)
        self.extra.clear()
        self.message.setText("")
        self._refresh()

    def on_enter(self) -> None:
        self.back_button.setFocus()

    # state ----------------------------------------------------------------------------

    def rows(self) -> list[PlanItemRow]:
        return list(self._rows)

    def selected_items(self) -> list[PlanItem]:
        return [r.item for r in self._rows if r.selected()]

    def _refresh(self) -> None:
        chosen = self.selected_items()
        n = len(chosen)
        if self._plan is None or not self._plan.items:
            self.summary.setText(catalog.DIAG_NOTHING)
        elif n == 0:
            self.summary.setText(catalog.AUTH_NONE_SELECTED)
        else:
            counts: dict[str, int] = {}
            for title, members in self._plan.groups():
                k = sum(1 for m in members if m in chosen)
                if k:
                    counts[title] = k
            parts = ", ".join(f"{v} em {k.lower()}" for k, v in counts.items())
            self.summary.setText(catalog.AUTH_SUMMARY.format(n=n, parts=parts))
        needs_extra = n > 0 and needs_extra_confirmation(chosen)
        self.extra_label.setVisible(needs_extra)
        self.extra.setVisible(needs_extra)
        self.extra_label.setText(catalog.AUTH_EXTRA.format(n=n))
        typed_ok = not needs_extra or self.extra.text().strip() == str(n)
        self.remove_button.setText(
            catalog.BTN_REMOVE_ONE if n == 1 else catalog.BTN_REMOVE_N.format(n=n)
        )
        self.remove_button.setEnabled(n > 0 and self.ack.isChecked() and typed_ok)
        self.ack.setEnabled(n > 0)

    def _on_remove(self) -> None:
        plan = self._plan
        chosen = self.selected_items()
        if plan is None or not chosen:
            return
        needs_extra = needs_extra_confirmation(chosen)
        ids = [i.id for i in chosen]
        stamp = self._clock()
        try:
            auth = authorize(
                plan,
                ids,
                session_id=self._session_id,
                authorised_at=stamp,
                extra_confirmation_count=int(self.extra.text())
                if needs_extra and self.extra.text().strip().isdigit()
                else None,
            )
        except ValueError as exc:
            self.message.setText(str(exc))
            return
        text = render_plan_text(
            plan, ids, session_id=self._session_id, authorised_at=stamp, version=__version__
        )
        try:
            if self._desktop is None:
                raise OSError("não há Ambiente de trabalho")
            self._desktop.mkdir(parents=True, exist_ok=True)
            path = self._desktop / f"ZeroBirus-plano-{self._session_id}.txt"
            path.write_text(text, encoding="utf-8-sig")
        except OSError as exc:
            # The plan must exist on disk BEFORE anything changes; if it cannot be saved, stop.
            self.message.setText(
                catalog.AUTH_PLAN_NOT_SAVED.format(reason=exc.strerror or str(exc))
            )
            return
        self.saved_path = path
        if self._save_session is not None:
            self._save_session(plan, ids)
        self.message.setText(catalog.AUTH_PLAN_SAVED.format(path=path))
        self.authorized.emit(auth)
