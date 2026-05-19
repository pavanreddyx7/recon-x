import os
import sys
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QFrame,
    QSizePolicy
)
from PyQt6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QIcon, QColor

from gui.theme import DARK_QSS
from gui.widgets.dashboard  import DashboardWidget
from gui.widgets.scan_tab   import ScanTab
from gui.widgets.results_tab import ResultsTab
from gui.widgets.reports_tab import ReportsTab
from gui.widgets.settings_tab import SettingsTab

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


_LOGO_ASCII = """
██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗    ██╗  ██╗
██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║    ╚██╗██╔╝
██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║     ╚███╔╝
██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗██║     ██╔██╗
██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║    ██╔╝ ██╗
╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝╚═╝  ╚═══╝    ╚═╝  ╚═╝
""".strip()


class _NavButton(QPushButton):
    def __init__(self, icon_char: str, label: str, parent=None):
        super().__init__(f"  {icon_char}  {label}", parent)
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setFixedHeight(42)
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class MainWindow(QMainWindow):
    def __init__(self, output_dir: str):
        super().__init__()
        self._output_dir = output_dir
        self._scanning   = False
        self.setWindowTitle("R3CON-X  —  Reconnaissance & Vulnerability Intelligence")
        self.setMinimumSize(1280, 800)
        self.setStyleSheet(DARK_QSS)
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_lay = QHBoxLayout(central)
        main_lay.setContentsMargins(0, 0, 0, 0)
        main_lay.setSpacing(0)

        # ── Sidebar ───────────────────────────────────────────────────────────
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(210)
        sb_lay = QVBoxLayout(sidebar)
        sb_lay.setContentsMargins(10, 16, 10, 16)
        sb_lay.setSpacing(4)

        # Logo
        logo = QLabel("R3CON-X")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet(
            "color: #00ff88; font-family: 'Consolas', monospace;"
            " font-size: 20px; font-weight: bold;"
            " padding: 6px 0 2px 0;")
        sb_lay.addWidget(logo)

        ver = QLabel("v2.0.0  ·  Recon Framework")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setStyleSheet("color: #404060; font-size: 10px; padding-bottom: 10px;")
        sb_lay.addWidget(ver)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #00ff8820;")
        sb_lay.addWidget(sep)
        sb_lay.addSpacing(8)

        # Navigation buttons
        self._nav_buttons: list[_NavButton] = []
        nav_items = [
            ("⊞", "Dashboard"),
            ("⌖", "New Scan"),
            ("⊙", "Results"),
            ("⊟", "Reports"),
            ("⚙", "Settings"),
        ]
        for icon, label in nav_items:
            btn = _NavButton(icon, label)
            btn.clicked.connect(lambda _, b=btn: self._nav_click(b))
            sb_lay.addWidget(btn)
            self._nav_buttons.append(btn)

        sb_lay.addStretch()

        # Status badge
        self._status_badge = QLabel("● IDLE")
        self._status_badge.setObjectName("StatusBadge")
        self._status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sb_lay.addWidget(self._status_badge)

        main_lay.addWidget(sidebar)

        # ── Content stack ─────────────────────────────────────────────────────
        self._stack = QStackedWidget()
        main_lay.addWidget(self._stack, stretch=1)

        self._dashboard = DashboardWidget(self._output_dir)
        self._scan_tab  = ScanTab(self._output_dir)
        self._results   = ResultsTab()
        self._reports   = ReportsTab(self._output_dir)
        self._settings  = SettingsTab()

        for w in (self._dashboard, self._scan_tab,
                  self._results, self._reports, self._settings):
            self._stack.addWidget(w)

        # ── Wire signals ──────────────────────────────────────────────────────
        self._dashboard.scan_requested.connect(self._on_quick_scan)
        self._scan_tab.scan_finished.connect(self._on_scan_done)
        self._scan_tab._worker_started = self._on_scan_started
        self._settings.settings_saved.connect(self._on_settings_saved)

        # Wire start/stop status to sidebar
        self._scan_tab._start_btn.clicked.connect(self._on_scan_started)
        self._scan_tab._stop_btn.clicked.connect(
            lambda: self._set_scanning(False))

        # Select Dashboard by default
        self._nav_buttons[0].setChecked(True)
        self._stack.setCurrentIndex(0)

    def _nav_click(self, clicked: _NavButton):
        for btn in self._nav_buttons:
            btn.setChecked(btn is clicked)
            btn.setProperty("active", "true" if btn is clicked else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        idx = self._nav_buttons.index(clicked)
        self._stack.setCurrentIndex(idx)

        # Refresh reports when switching to that tab
        if idx == 3:
            self._reports.refresh()
        if idx == 0:
            self._dashboard.refresh()

    def _on_quick_scan(self, target: str):
        self._nav_click(self._nav_buttons[1])
        self._scan_tab.start_scan_for_target(target)

    def _on_scan_started(self):
        self._set_scanning(True)

    def _on_scan_done(self, data: dict):
        self._set_scanning(False)
        self._results.load(data)
        self._nav_click(self._nav_buttons[2])
        self._dashboard.refresh()

    def _set_scanning(self, scanning: bool):
        self._scanning = scanning
        if scanning:
            self._status_badge.setText("● SCANNING")
            self._status_badge.setProperty("scanning", "true")
        else:
            self._status_badge.setText("● IDLE")
            self._status_badge.setProperty("scanning", "false")
        self._status_badge.style().unpolish(self._status_badge)
        self._status_badge.style().polish(self._status_badge)

    def _on_settings_saved(self, d: dict):
        if d.get("output_dir"):
            self._dashboard._output_dir = d["output_dir"]
            self._scan_tab._output_dir  = d["output_dir"]
            self._reports._output_dir   = d["output_dir"]
