import os
import json
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QPushButton, QLineEdit, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from gui.theme import SEV_COLORS


class _StatCard(QFrame):
    def __init__(self, icon: str, title: str, value: str = "0",
                 subtitle: str = "", color: str = "#00ff88", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(110)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 18)
        lay.setSpacing(6)

        # Icon + title row
        top = QHBoxLayout()
        top.setSpacing(8)
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(
            f"font-size: 20px; color: {color}; background: transparent;")
        top.addWidget(icon_lbl)
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            "color: #3d5470; font-size: 10px; font-weight: 700;"
            " letter-spacing: 1.2px; background: transparent;")
        top.addWidget(title_lbl)
        top.addStretch()
        lay.addLayout(top)

        # Big value
        self._val = QLabel(value)
        self._val.setStyleSheet(
            f"color: {color}; font-size: 32px; font-weight: 700;"
            " letter-spacing: -1px; background: transparent;")
        lay.addWidget(self._val)

        # Subtitle
        self._sub = QLabel(subtitle or " ")
        self._sub.setStyleSheet(
            "color: #243550; font-size: 11px; background: transparent;")
        lay.addWidget(self._sub)

        # Accent bar
        bar = QFrame()
        bar.setFixedHeight(3)
        bar.setStyleSheet(
            f"background-color: {color}22; border-radius: 2px;"
            " max-height: 3px; margin-top: 4px;")
        bar.setFrameShape(QFrame.Shape.NoFrame)
        lay.addWidget(bar)

    def update_value(self, v: str, subtitle: str = ""):
        self._val.setText(v)
        if subtitle:
            self._sub.setText(subtitle)


class DashboardWidget(QWidget):
    scan_requested = pyqtSignal(str)

    def __init__(self, output_dir: str, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header bar ─────────────────────────────────────────────────────
        header_bar = QWidget()
        header_bar.setStyleSheet(
            "background-color: #080e1c; border-bottom: 1px solid #1a2e45;")
        header_bar.setFixedHeight(70)
        hb = QHBoxLayout(header_bar)
        hb.setContentsMargins(28, 14, 28, 14)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        t = QLabel("Dashboard")
        t.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        t.setStyleSheet("color: #cbd5e1; background: transparent;")
        title_col.addWidget(t)
        s = QLabel("Overview of reconnaissance activity and findings")
        s.setStyleSheet("color: #3d5470; font-size: 12px; background: transparent;")
        title_col.addWidget(s)
        hb.addLayout(title_col)
        hb.addStretch()

        refresh_btn = QPushButton("⟳  Refresh")
        refresh_btn.setFixedWidth(110)
        refresh_btn.clicked.connect(self.refresh)
        hb.addWidget(refresh_btn)
        root.addWidget(header_bar)

        # ── Scrollable body ────────────────────────────────────────────────
        from PyQt6.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        root.addWidget(scroll, stretch=1)

        body = QWidget()
        scroll.setWidget(body)
        body_lay = QVBoxLayout(body)
        body_lay.setContentsMargins(28, 28, 28, 28)
        body_lay.setSpacing(28)

        # ── Quick scan ─────────────────────────────────────────────────────
        scan_frame = QFrame()
        scan_frame.setObjectName("Card")
        scan_frame.setStyleSheet(
            "#Card { background-color: #0a1929; border: 1px solid #00ff8820;"
            " border-radius: 12px; }")
        sf_lay = QVBoxLayout(scan_frame)
        sf_lay.setContentsMargins(24, 20, 24, 20)
        sf_lay.setSpacing(10)

        qs_lbl = QLabel("QUICK SCAN")
        qs_lbl.setStyleSheet(
            "color: #00ff88; font-size: 10px; font-weight: 700;"
            " letter-spacing: 1.5px; background: transparent;")
        sf_lay.addWidget(qs_lbl)

        hint = QLabel(
            "Enter a target and press Scan — your results will appear automatically when done.")
        hint.setStyleSheet("color: #243550; font-size: 12px; background: transparent;")
        sf_lay.addWidget(hint)

        bar = QHBoxLayout()
        bar.setSpacing(10)
        self._quick_input = QLineEdit()
        self._quick_input.setPlaceholderText(
            "IP address · domain · CIDR range (192.168.1.0/24) · URL…")
        self._quick_input.setMinimumHeight(44)
        self._quick_input.setStyleSheet(
            "QLineEdit { background-color: #060e1c; border: 1px solid #1a2e45;"
            " border-radius: 8px; padding: 0 16px; font-size: 14px;"
            " color: #cbd5e1; }"
            "QLineEdit:focus { border-color: #00ff8860; }")
        self._quick_input.returnPressed.connect(self._on_quick_scan)
        bar.addWidget(self._quick_input, stretch=1)

        go = QPushButton("  Scan  →")
        go.setObjectName("StartButton")
        go.setMinimumHeight(44)
        go.setFixedWidth(120)
        go.clicked.connect(self._on_quick_scan)
        bar.addWidget(go)
        sf_lay.addLayout(bar)
        body_lay.addWidget(scan_frame)

        # ── Stat cards ─────────────────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(16)

        self._card_total = _StatCard("⊛", "TOTAL SCANS",       "0",
                                     color="#3b9eff")
        self._card_crit  = _StatCard("⚠", "CRITICAL FINDINGS", "0",
                                     color="#ff4757")
        self._card_high  = _StatCard("▲", "HIGH FINDINGS",     "0",
                                     color="#ff7b2d")
        self._card_last  = _StatCard("◷", "LAST SCAN",         "—",
                                     subtitle="No scans yet", color="#00ff88")

        for card in (self._card_total, self._card_crit,
                     self._card_high, self._card_last):
            cards_row.addWidget(card)
        body_lay.addLayout(cards_row)

        # ── Recent scans ───────────────────────────────────────────────────
        tbl_hdr = QHBoxLayout()
        sec = QLabel("RECENT SCANS")
        sec.setObjectName("SectionLabel")
        tbl_hdr.addWidget(sec)
        tbl_hdr.addStretch()
        self._count_lbl = QLabel("")
        self._count_lbl.setStyleSheet("color: #243550; font-size: 11px;")
        tbl_hdr.addWidget(self._count_lbl)
        body_lay.addLayout(tbl_hdr)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Target", "Date / Time", "Profile", "Open Ports", "Vulnerabilities", "Risk Level"])
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setMinimumHeight(220)
        body_lay.addWidget(self._table)

        # Empty state
        self._empty = QLabel(
            "No scans recorded yet.\n\n"
            "Use the Quick Scan bar above or go to New Scan to get started.")
        self._empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty.setStyleSheet(
            "color: #243550; font-size: 14px; line-height: 1.8;"
            " border: 1px dashed #1a2e45; border-radius: 12px;"
            " padding: 48px; background: transparent;")
        self._empty.hide()
        body_lay.addWidget(self._empty)

        body_lay.addStretch()

    def _on_quick_scan(self):
        target = self._quick_input.text().strip()
        if target:
            self.scan_requested.emit(target)

    def refresh(self):
        self._table.setRowCount(0)
        db_path = os.path.join(self._output_dir, "scan_history.db")
        if not os.path.exists(db_path):
            self._show_empty(True)
            return

        try:
            conn = sqlite3.connect(db_path)
            cur  = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            if not cur.fetchone():
                conn.close()
                self._show_empty(True)
                return
            cur.execute("""
                SELECT target, timestamp, profile, open_ports,
                       vuln_count, risk_level, json_path
                FROM scans ORDER BY id DESC LIMIT 50
            """)
            rows = cur.fetchall()
            conn.close()
        except Exception:
            self._show_empty(True)
            return

        if not rows:
            self._show_empty(True)
            return

        self._show_empty(False)
        total = len(rows)
        crits, highs = 0, 0
        last_t, last_s = "—", ""

        self._table.setRowCount(total)
        for r, (target, ts, profile, ports, vulns, risk, jpath) in enumerate(rows):
            self._table.setItem(r, 0, QTableWidgetItem(str(target or "—")))
            self._table.setItem(r, 1, QTableWidgetItem(str(ts or "—")))
            self._table.setItem(r, 2, QTableWidgetItem(str(profile or "—")))

            p_item = QTableWidgetItem(str(ports or 0))
            p_item.setForeground(QColor("#3b9eff"))
            p_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(r, 3, p_item)

            v_count = int(vulns or 0)
            v_item  = QTableWidgetItem(str(v_count))
            v_item.setForeground(QColor("#ff4757" if v_count > 0 else "#3d5470"))
            v_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(r, 4, v_item)

            risk_str  = str(risk or "—").upper()
            risk_item = QTableWidgetItem(risk_str)
            risk_item.setForeground(QColor(SEV_COLORS.get(risk_str, "#cbd5e1")))
            risk_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(r, 5, risk_item)

            if r == 0:
                last_t = str(target or "—")
                last_s = str(ts or "")

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
        self._count_lbl.setText(f"{total} scan(s)")

    def _show_empty(self, empty: bool):
        self._table.setVisible(not empty)
        self._empty.setVisible(empty)
        if empty:
            self._card_total.update_value("0")
            self._card_crit.update_value("0")
            self._card_high.update_value("0")
            self._card_last.update_value("—", "No scans yet")
            self._count_lbl.setText("")
