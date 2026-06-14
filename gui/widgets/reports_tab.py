import os
import subprocess
import platform
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QApplication, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor



_REPORT_EXTS = {".pdf", ".html", ".json", ".md", ".csv", ".sarif"}

_FMT_COLORS = {
    "PDF":   "#ff7b2d",
    "HTML":  "#00b8d4",
    "JSON":  "#00ff88",
    "MD":    "#a78bfa",
    "CSV":   "#f59e0b",
    "SARIF": "#4b5e7a",
}


def _open_path(path: str):
    if platform.system() == "Windows":
        os.startfile(path)
    elif platform.system() == "Darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n} {unit}"
        n //= 1024
    return f"{n} MB"


class ReportsTab(QWidget):
    def __init__(self, output_dir: str, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(20)

        # Header
        hdr = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title = QLabel("Reports")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet("color: #cbd5e1;")
        title_col.addWidget(title)
        sub = QLabel("Browse and open saved scan report files")
        sub.setStyleSheet("color: #3d5470; font-size: 12px;")
        title_col.addWidget(sub)
        hdr.addLayout(title_col)
        hdr.addStretch()
        root.addLayout(hdr)

        # Action bar
        bar = QHBoxLayout()
        bar.setSpacing(8)

        refresh_btn = QPushButton("⟳  Refresh")
        refresh_btn.setFixedWidth(110)
        refresh_btn.clicked.connect(self.refresh)
        bar.addWidget(refresh_btn)

        open_dir_btn = QPushButton("Open Output Folder")
        open_dir_btn.clicked.connect(lambda: _open_path(self._output_dir))
        bar.addWidget(open_dir_btn)

        bar.addStretch()

        self._count_lbl = QLabel("0 reports")
        self._count_lbl.setStyleSheet("color: #243550; font-size: 11px;")
        bar.addWidget(self._count_lbl)
        root.addLayout(bar)

        # Reports table
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Filename", "Target", "Format", "Size", "Modified"])
        hdr_view = self._table.horizontalHeader()
        hdr_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr_view.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        root.addWidget(self._table, stretch=1)

        # Empty state
        self._empty = QLabel(
            "No reports found.\nRun a scan to generate reports in the output directory.")
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty.setStyleSheet(
            "color: #243550; font-size: 14px; line-height: 2;"
            " border: 1px dashed #1a2e45; border-radius: 10px; padding: 40px;")
        self._empty.hide()
        root.addWidget(self._empty)

        # Action buttons
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background-color: #1a2e45; max-height: 1px; border: none;")
        root.addWidget(sep)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        open_btn = QPushButton("Open File")
        open_btn.clicked.connect(self._open_selected)
        btn_row.addWidget(open_btn)

        folder_btn = QPushButton("Open Folder")
        folder_btn.clicked.connect(self._open_folder_selected)
        btn_row.addWidget(folder_btn)

        copy_btn = QPushButton("Copy Path")
        copy_btn.clicked.connect(self._copy_path)
        btn_row.addWidget(copy_btn)

        btn_row.addStretch()
        root.addLayout(btn_row)

    def refresh(self):
        self._table.setRowCount(0)
        if not os.path.isdir(self._output_dir):
            self._show_empty(True)
            return

        files = []
        for fname in sorted(os.listdir(self._output_dir), reverse=True):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _REPORT_EXTS:
                continue
            fpath = os.path.join(self._output_dir, fname)
            stat  = os.stat(fpath)
            target = self._extract_target(fname)
            fmt    = ext.lstrip(".")
            size   = _human_size(stat.st_size)
            mtime  = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d  %H:%M")
            files.append((fname, target, fmt.upper(), size, mtime, fpath))

        if not files:
            self._show_empty(True)
            return

        self._show_empty(False)
        self._table.setRowCount(len(files))

        for r, (fname, target, fmt, size, mtime, fpath) in enumerate(files):
            self._table.setItem(r, 0, QTableWidgetItem(fname))

            tgt_item = QTableWidgetItem(target)
            tgt_item.setForeground(QColor("#8fadc8"))
            self._table.setItem(r, 1, tgt_item)

            fi = QTableWidgetItem(fmt)
            fi.setForeground(QColor(_FMT_COLORS.get(fmt, "#cbd5e1")))
            fi.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(r, 2, fi)

            sz_item = QTableWidgetItem(size)
            sz_item.setForeground(QColor("#4b5e7a"))
            sz_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(r, 3, sz_item)

            mt_item = QTableWidgetItem(mtime)
            mt_item.setForeground(QColor("#3d5470"))
            self._table.setItem(r, 4, mt_item)

            self._table.item(r, 0).setData(Qt.ItemDataRole.UserRole, fpath)

        self._count_lbl.setText(f"{len(files)} report(s)")

    def _show_empty(self, empty: bool):
        self._table.setVisible(not empty)
        self._empty.setVisible(empty)
        if empty:
            self._count_lbl.setText("0 reports")

    def _extract_target(self, fname: str) -> str:
        parts = fname.split("_")
        if len(parts) >= 3:
            return parts[1].replace("-", ".")
        return "—"

    def _selected_path(self) -> str | None:
        row = self._table.currentRow()
        if row < 0:
            return None
        item = self._table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _open_selected(self):
        path = self._selected_path()
        if path and os.path.exists(path):
            _open_path(path)

    def _open_folder_selected(self):
        path = self._selected_path()
        if path:
            _open_path(os.path.dirname(path))

    def _copy_path(self):
        path = self._selected_path()
        if path:
            QApplication.clipboard().setText(path)

    def _context_menu(self, pos):
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        menu.addAction("Open File",   self._open_selected)
        menu.addAction("Open Folder", self._open_folder_selected)
        menu.addAction("Copy Path",   self._copy_path)
        menu.exec(self._table.mapToGlobal(pos))
