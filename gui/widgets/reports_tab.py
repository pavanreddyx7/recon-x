import os
import json
import subprocess
import platform
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QGroupBox, QCheckBox, QFileDialog,
    QMessageBox, QApplication
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor


_REPORT_EXTS = {".pdf", ".html", ".json", ".md", ".csv", ".sarif"}


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
            return f"{n}{unit}"
        n //= 1024
    return f"{n}MB"


class ReportsTab(QWidget):
    def __init__(self, output_dir: str, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        title = QLabel("Reports")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        root.addWidget(title)

        # Action bar
        bar = QHBoxLayout()
        refresh_btn = QPushButton("⟳  Refresh")
        refresh_btn.setFixedWidth(110)
        refresh_btn.clicked.connect(self.refresh)
        bar.addWidget(refresh_btn)

        open_dir_btn = QPushButton("Open Output Folder")
        open_dir_btn.clicked.connect(lambda: _open_path(self._output_dir))
        bar.addWidget(open_dir_btn)
        bar.addStretch()

        self._count_lbl = QLabel("0 reports")
        self._count_lbl.setStyleSheet("color: #808090;")
        bar.addWidget(self._count_lbl)
        root.addLayout(bar)

        # Reports table
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Filename", "Target", "Format", "Size", "Modified"])
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        root.addWidget(self._table, stretch=1)

        # Quick action buttons
        btn_row = QHBoxLayout()
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
            mtime  = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            files.append((fname, target, fmt.upper(), size, mtime, fpath))

        self._table.setRowCount(len(files))
        fmt_colors = {
            "PDF": "#ff8800", "HTML": "#00d4ff", "JSON": "#00ff88",
            "MD": "#c084fc", "CSV": "#ffcc00", "SARIF": "#808090",
        }
        for r, (fname, target, fmt, size, mtime, fpath) in enumerate(files):
            self._table.setItem(r, 0, QTableWidgetItem(fname))
            self._table.setItem(r, 1, QTableWidgetItem(target))
            fi = QTableWidgetItem(fmt)
            fi.setForeground(QColor(fmt_colors.get(fmt, "#e0e0e0")))
            self._table.setItem(r, 2, fi)
            self._table.setItem(r, 3, QTableWidgetItem(size))
            self._table.setItem(r, 4, QTableWidgetItem(mtime))
            self._table.item(r, 0).setData(Qt.ItemDataRole.UserRole, fpath)

        self._count_lbl.setText(f"{len(files)} report(s)")

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
        if not item:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

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
        menu.setStyleSheet(
            "QMenu { background-color: #1a1a2e; color: #e0e0e0;"
            " border: 1px solid #00ff8830; border-radius: 4px; }"
            "QMenu::item:selected { background-color: #0d2040; }")
        menu.addAction("Open File",   self._open_selected)
        menu.addAction("Open Folder", self._open_folder_selected)
        menu.addAction("Copy Path",   self._copy_path)
        menu.exec(self._table.mapToGlobal(pos))
