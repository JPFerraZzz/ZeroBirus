"""Stage 2: the diagnosis table is the main screen. Two layers: plain language, technical detail."""

from __future__ import annotations

from PySide6.QtCore import QItemSelection, QModelIndex, Qt, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QScrollArea,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from zerobirus.core.diagnosis import Diagnosis, diagnose
from zerobirus.core.models import Finding, Level
from zerobirus.core.redact import redact
from zerobirus.scanners.runner import ScanResult
from zerobirus.ui import catalog
from zerobirus.ui.models import (
    FINDING_ROLE,
    LEVEL_COLUMN,
    FindingsModel,
    make_proxy,
    what_is_it,
)
from zerobirus.ui.page_base import Page, button
from zerobirus.ui.theme import TOKENS, level_style
from zerobirus.ui.widgets import LevelBadge, LevelDelegate, WrapText, make_label


class DetailPanel(QScrollArea):
    """What the selected row means. Plain language first; the technical block on request."""

    def __init__(self) -> None:
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        host = QWidget()
        host.setObjectName("page")
        self._lay = QVBoxLayout(host)
        self._lay.setContentsMargins(TOKENS.space_3, TOKENS.space_3, TOKENS.space_3, TOKENS.space_3)
        self._lay.setSpacing(TOKENS.space_2)
        self.badge = LevelBadge()
        self.title = make_label("", "subtitle", name="Item selecionado")
        self.where = WrapText("", "small", name="Onde está")
        self.what = make_label("", name="O que é")
        self.explain = make_label("", "lead")
        self.why_title = make_label(catalog.DIAG_WHY_TITLE, "subtitle", wrap=False)
        self.why = make_label("", name="Porque aparece")
        self.advice = make_label("", name="Conselho")
        self.tech_toggle = button(catalog.BTN_SHOW_DETAIL, "link")
        self.tech_toggle.setCheckable(True)
        self.tech_toggle.toggled.connect(self._toggle)
        self.tech = WrapText("", "mono", name="Detalhe técnico")
        self.tech.setVisible(False)
        self.hint = make_label(catalog.DIAG_SELECT_HINT, "lead")
        for w in (
            self.hint,
            self.badge,
            self.title,
            self.where,
            self.what,
            self.explain,
            self.why_title,
            self.why,
            self.advice,
            self.tech_toggle,
            self.tech,
        ):
            self._lay.addWidget(w)
        self._lay.addStretch(1)
        self.setWidget(host)
        self.show_finding(None)

    def _toggle(self, shown: bool) -> None:
        self.tech.setVisible(shown)
        self.tech_toggle.setText(catalog.BTN_HIDE_DETAIL if shown else catalog.BTN_SHOW_DETAIL)

    def toggle_technical(self) -> None:
        if self.tech_toggle.isVisible():
            self.tech_toggle.toggle()

    def show_finding(self, f: Finding | None) -> None:
        detail = [
            self.badge,
            self.title,
            self.where,
            self.what,
            self.explain,
            self.why_title,
            self.why,
            self.advice,
            self.tech_toggle,
        ]
        self.hint.setVisible(f is None)
        for w in detail:
            w.setVisible(f is not None)
        self.tech.setVisible(f is not None and self.tech_toggle.isChecked())
        if f is None:
            return
        self.badge.set_level(f.level)
        self.title.setText(f.item)
        self.where.set_text(f.location)
        self.what.setText(f.description)
        self.explain.setText(catalog.LEVEL_EXPLAIN[f.level])
        self.why.setText("\n".join(f"- {s.text}" for s in f.signals) or "-")
        self.why_title.setVisible(bool(f.signals))
        self.why.setVisible(bool(f.signals))
        self.advice.setText(f.advice)
        self.advice.setVisible(bool(f.advice))
        lines: list[str] = []
        if f.path:
            lines.append(f"Caminho: {f.path}")
        for e in f.evidence:
            lines.append(f"Linha de comando ou valor: {redact(e)}")
        if f.sha256:
            lines.append(f"SHA-256: {f.sha256}")
        if f.signals:
            lines.append("Sinais: " + ", ".join(f"{s.code} ({s.weight:+d})" for s in f.signals))
        lines.append(f"Pontuação: {f.score}")
        self.tech.set_text("\n".join(lines))


class DiagnosisPage(Page):
    continue_requested = Signal()

    def __init__(self) -> None:
        super().__init__("Diagnóstico", catalog.STAGE_LEAD["diagnosis"])
        self.diagnosis: Diagnosis | None = None
        self.summary = make_label("", name="Resumo do diagnóstico")
        self.body.addWidget(self.summary)

        self.model = FindingsModel()
        self.proxy = make_proxy(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAccessibleName("Tabela de diagnóstico")
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.setSortingEnabled(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(TOKENS.row_height)
        self.table.setItemDelegateForColumn(LEVEL_COLUMN, LevelDelegate(self.table))
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setHighlightSections(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(LEVEL_COLUMN, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 260)
        self.table.selectionModel().selectionChanged.connect(self._on_selection)

        self.detail = DetailPanel()
        self.normal_view = make_label("", name="Coisas normais que assustam")
        self.not_verified_view = make_label("", name="Não foi possível verificar")
        self.threat_view = make_label("", name="Tipo de ameaça")
        self.tabs = QTabWidget()
        self.tabs.addTab(self.detail, "Detalhe do item")
        self.tabs.addTab(self._scrolled(self.threat_view), "Ameaça e origem")
        self.tabs.addTab(self._scrolled(self.normal_view), catalog.DIAG_NORMAL_TITLE)
        self.tabs.addTab(self._scrolled(self.not_verified_view), catalog.DIAG_NOT_VERIFIED_TITLE)

        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.tabs)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setChildrenCollapsible(False)
        self.table.setMinimumHeight(110)
        self.tabs.setMinimumHeight(110)
        self.body.addWidget(self.splitter, 1)

        # "T" shows or hides the technical detail; it only exists on this page, which has no text
        # field, so it can never swallow a typed letter.
        self._toggle_key = QShortcut(QKeySequence("T"), self, self.detail.toggle_technical)
        self._toggle_key.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.next_button = button(catalog.BTN_TO_AUTHORIZE, "primary")
        self.next_button.clicked.connect(self.continue_requested)
        self.right_actions.addWidget(self.next_button)

    @staticmethod
    def _scrolled(label: QWidget) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QScrollArea.Shape.NoFrame)
        host = QWidget()
        host.setObjectName("page")
        lay = QVBoxLayout(host)
        lay.setContentsMargins(TOKENS.space_3, TOKENS.space_3, TOKENS.space_3, TOKENS.space_3)
        lay.addWidget(label)
        lay.addStretch(1)
        area.setWidget(host)
        return area

    def set_result(self, result: ScanResult) -> None:
        self.diagnosis = diagnose(result.checks, result.snapshot)
        d = self.diagnosis
        self.model.set_rows(d.rows)
        word = level_style(d.overall).label
        self.summary.setText(
            f"Resultado geral: {word}. "
            + (f"{len(d.rows)} itens para ver." if d.rows else catalog.DIAG_NOTHING)
        )
        threat_lines = [
            f"{catalog.DIAG_THREAT_TITLE}: {t.name}"
            + (f" (certeza {t.certainty})" if not t.note else "")
            + ("\n" + t.note if t.note else "")
            for t in d.threats
        ]
        if d.entry_vector:
            threat_lines.append(f"{catalog.DIAG_ENTRY_TITLE}: {d.entry_vector}")
        threat_lines += list(d.notes)
        self.threat_view.setText("\n\n".join(threat_lines) or "Nada a assinalar.")
        self.normal_view.setText(
            "\n".join(f"{r.finding.item}: {r.finding.description}" for r in d.normal_things)
            or "Nada."
        )
        self.not_verified_view.setText(
            "\n".join(
                f"{catalog.CHECK_TITLE.get(n.check, n.check)}: {n.reason}" for n in d.not_verified
            )
            or "Todas as verificações correram por inteiro."
        )
        self.next_button.setEnabled(True)
        if d.rows:
            self.table.selectRow(0)
        else:
            self.detail.show_finding(None)

    def _on_selection(self, selected: QItemSelection, _deselected: QItemSelection) -> None:
        indexes = selected.indexes()
        if not indexes:
            self.detail.show_finding(None)
            return
        index: QModelIndex = indexes[0]
        finding = self.proxy.data(index, FINDING_ROLE)
        self.detail.show_finding(finding if isinstance(finding, Finding) else None)

    def selected_finding(self) -> Finding | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        finding = self.proxy.data(rows[0], FINDING_ROLE)
        return finding if isinstance(finding, Finding) else None

    def row_levels(self) -> list[Level]:
        return [
            self.proxy.data(self.proxy.index(r, LEVEL_COLUMN), FINDING_ROLE).level
            for r in range(self.proxy.rowCount())
        ]

    def what_text(self, finding: Finding) -> str:
        return what_is_it(finding)
