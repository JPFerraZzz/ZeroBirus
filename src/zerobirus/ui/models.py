"""The table model behind the diagnosis table (Item, Onde está, Nível, O que é)."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
)

from zerobirus.core.diagnosis import Row
from zerobirus.core.models import Finding, Level
from zerobirus.ui import catalog
from zerobirus.ui.widgets import LEVEL_ROLE

_ORDER = {Level.SUSPEITO: 0, Level.CONFERIR: 1, Level.NAO_VERIFICADO: 2, Level.OK: 3}
SORT_ROLE = Qt.ItemDataRole.UserRole + 2
FINDING_ROLE = Qt.ItemDataRole.UserRole + 3
COLUMNS = (catalog.HDR_ITEM, catalog.HDR_WHERE, catalog.HDR_LEVEL, catalog.HDR_WHAT)
LEVEL_COLUMN = 2


def what_is_it(f: Finding) -> str:
    """One plain sentence: what it is, then the strongest reason."""
    if not f.signals:
        return f.description
    top = max(f.signals, key=lambda s: s.weight)
    return f"{f.description} {top.text}"


class FindingsModel(QAbstractTableModel):
    def __init__(self, rows: tuple[Row, ...] = ()) -> None:
        super().__init__()
        self._rows = rows

    def set_rows(self, rows: tuple[Row, ...]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def finding_at(self, row: int) -> Finding:
        return self._rows[row].finding

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = 0) -> Any:
        if not index.isValid():
            return None
        f = self._rows[index.row()].finding
        col = index.column()
        if role == FINDING_ROLE:
            return f
        if col == LEVEL_COLUMN:
            if role == LEVEL_ROLE:
                return f.level.value
            if role == SORT_ROLE:
                return (_ORDER[f.level], -f.score)
            if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
                return catalog.LEVEL_WORD[f.level]
            return None
        text = (f.item, f.location, "", what_is_it(f))[col]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
            return text
        if role == Qt.ItemDataRole.ToolTipRole:
            return text
        if role == SORT_ROLE:
            return text.lower()
        return None


def make_proxy(model: FindingsModel) -> QSortFilterProxyModel:
    proxy = QSortFilterProxyModel()
    proxy.setSourceModel(model)
    proxy.setSortRole(SORT_ROLE)
    return proxy
