import os
import json
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QPushButton, QLineEdit, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from gui.theme import SEV_COLORS


class _StatCard(QFrame):
    def __init__(self, title: str, value: str = "0",
                 subtitle: str = "", color: str = "#00ff88", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumWidth(160)
        lay = QVBoxLayout(self)
        lay.setSpacing(4)

        t = QLabel(title)
        t.setObjectName("CardTitle")
        lay.addWidget(t)

        self._val = QLabel(value)
        self._val.setObjectName("CardValue")
        self._val.setStyleSheet(f"color: {color};")
        lay.addWidget(self._val)

        if subtitle:
            s = QLabel(subtitle)
            s.setObjectName("CardLabel")
            s.setWordWrap(True)
            lay.addWidget(s)
            self._sub = s
        else:
            self._sub = None

    def update_value(self, v: str, subtitle: str = ""):
        self._val.setText(v)
        if subtitle and self._sub:
            self._sub.setText(subtitle)


class DashboardWidget(QWidget):
    scan_requested = pyqtSignal(str)  # target string

    def __init__(self, output_dir: str, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(16)

        # Title
        title = QLabel("Dashboard")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        root.addWidget(title)

        # Quick scan bar
        qbar = QHBoxLayout()
        self._quick_input = QLineEdit()
        self._quick_input.setPlaceholderText(
            "Quick scan — enter IP / domain / CIDR and press Enter…")
        self._quick_input.returnPressed.connect(self._on_quick_scan)
        qbar.addWidget(self._quick_input)
        go = QPushButton("Scan →")
        go.setFixedWidth(90)
        go.setObjectName("StartButton")
        go.clicked.connect(self._on_quick_scan)
        qbar.addWidget(go)
        root.addLayout(qbar)

        # Stat cards row
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        self._card_total   = _StatCard("TOTAL SCANS",      "0", color="#00d4ff")
        self._card_crit    = _StatCard("CRITICAL FINDINGS", "0", color="#ff4444")
        self._card_high    = _StatCard("HIGH FINDINGS",    "0", color="#ff8800")
        self._card_last    = _StatCard("LAST SCAN",        "—",
                                       subtitle="No scans yet", color="#00ff88")

        for card in (self._card_total, self._card_crit,
                     self._card_high, self._card_last):
            card.setSizePolicy(QSizePolicy.Policy.Expanding,
                               QSizePolicy.Policy.Fixed)
            cards_row.addWidget(card)
        root.addLayout(cards_row)

        # Recent scans table
        sec = QLabel("Recent Scans")
        sec.setObjectName("SectionLabel")
        root.addWidget(sec)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Target", "Date", "Profile", "Open Ports", "Vulns", "Risk"])
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        root.addWidget(self._table, stretch=1)

        refresh_btn = QPushButton("⟳  Refresh")
        refresh_btn.setFixedWidth(110)
        refresh_btn.clicked.connect(self.refresh)
        root.addWidget(refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _on_quick_scan(self):
        target = self._quick_input.text().strip()
        if target:
            self.scan_requested.emit(target)

    def refresh(self):
        self._table.setRowCount(0)
        db_path = os.path.join(self._output_dir, "scan_history.db")
        if not os.path.exists(db_path):
            return

        try:
            conn  = sqlite3.connect(db_path)
            cur   = conn.cursor()
            cur.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='scans'
            """)
            if not cur.fetchone():
                conn.close()
                return

            cur.execute("""
                SELECT target, timestamp, profile, open_ports,
                       vuln_count, risk_level, json_path
                FROM scans ORDER BY id DESC LIMIT 50
            """)
            rows = cur.fetchall()
            conn.close()
        except Exception:
            return

        total   = len(rows)
        crits   = 0
        highs   = 0
        last_t  = "—"
        last_s  = "No scans yet"

        self._table.setRowCount(total)
        for r, (target, ts, profile, ports, vulns, risk, jpath) in enumerate(rows):
            self._table.setItem(r, 0, QTableWidgetItem(str(target or "—")))
            self._table.setItem(r, 1, QTableWidgetItem(str(ts or "—")))
            self._table.setItem(r, 2, QTableWidgetItem(str(profile or "—")))
            self._table.setItem(r, 3, QTableWidgetItem(str(ports or 0)))
            self._table.setItem(r, 4, QTableWidgetItem(str(vulns or 0)))

            risk_item = QTableWidgetItem(str(risk or "—"))
            col = SEV_COLORS.get(str(risk).upper(), "#e0e0e0")
            risk_item.setForeground(__import__('PyQt6.QtGui', fromlist=['QColor']).QColor(col))
            self._table.setItem(r, 5, risk_item)

            if r == 0:
                last_t = str(target or "—")
                last_s = str(ts or "—")

        # Aggregate stats from JSON reports
        for _, _, _, _, _, _, jpath in rows:
            if jpath and os.path.exists(str(jpath)):
                try:
                    with open(jpath) as f:
                        data = json.load(f)
                    counts = data.get("risk_summary", {}).get("counts", {})
                    crits += counts.get("CRITICAL", 0)
                    highs += counts.get("HIGH", 0)
                except Exception:
                    pass

        self._card_total.update_value(str(total))
        self._card_crit.update_value(str(crits))
        self._card_high.update_value(str(highs))
        self._card_last.update_value(last_t, last_s)
