import os
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QFrame,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeySequence, QShortcut

from gui.theme import DARK_QSS
from gui.widgets.dashboard   import DashboardWidget
from gui.widgets.scan_tab    import ScanTab
from gui.widgets.results_tab import ResultsTab
from gui.widgets.reports_tab import ReportsTab
from gui.widgets.settings_tab import SettingsTab

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


_NAV_ITEMS = [
    ("⊞", "Dashboard",  "Overview & quick launch"),
    ("⌖", "New Scan",   "Configure and run a scan"),
    ("⊙", "Results",    "View latest scan results"),
    ("⊟", "Reports",    "Browse saved report files"),
    ("⚙", "Settings",   "API keys & preferences"),
]


class _NavButton(QPushButton):
    def __init__(self, icon_char: str, label: str, tooltip: str = "", parent=None):
        super().__init__(f"  {icon_char}   {label}", parent)
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setMinimumHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        if tooltip:
            self.setToolTip(tooltip)


class _SidebarDivider(QFrame):
    def __init__(self, label: str = "", parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 6, 14, 2)
        lay.setSpacing(8)
        if label:
            lbl = QLabel(label.upper())
            lbl.setStyleSheet(
                "color: #243550; font-size: 9px; font-weight: 700;"
                " letter-spacing: 1.5px; background: transparent;")
            lay.addWidget(lbl)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("background-color: #1a2e45; max-height: 1px; border: none;")
        lay.addWidget(line, stretch=1)


class MainWindow(QMainWindow):
    def __init__(self, output_dir: str):
        super().__init__()
        self._output_dir = output_dir
        self._scanning   = False
        self.setWindowTitle("R3CON-X  —  Reconnaissance & Vulnerability Intelligence")
        self.setMinimumSize(800, 560)
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
        sidebar.setFixedWidth(230)
        sb_lay = QVBoxLayout(sidebar)
        sb_lay.setContentsMargins(0, 0, 0, 0)
        sb_lay.setSpacing(0)

        # Logo block
        logo_widget = QWidget()
        logo_widget.setStyleSheet("background-color: #060a14;")
        logo_lay = QVBoxLayout(logo_widget)
        logo_lay.setContentsMargins(16, 20, 16, 16)
        logo_lay.setSpacing(2)

        brand = QLabel("R3CON-X")
        brand.setStyleSheet(
            "color: #00ff88; font-family: 'JetBrains Mono', 'Consolas', monospace;"
            " font-size: 22px; font-weight: 700; letter-spacing: 1px;"
            " background: transparent;")
        logo_lay.addWidget(brand)

        tagline = QLabel("Recon & Vulnerability Intelligence")
        tagline.setStyleSheet(
            "color: #243550; font-size: 10px; font-weight: 500;"
            " letter-spacing: 0.3px; background: transparent;")
        logo_lay.addWidget(tagline)

        sb_lay.addWidget(logo_widget)

        # Thin separator under logo
        sep0 = QFrame()
        sep0.setFrameShape(QFrame.Shape.HLine)
        sep0.setStyleSheet("background-color: #1a2e45; max-height: 1px; border: none;")
        sb_lay.addWidget(sep0)

        # Nav area
        nav_widget = QWidget()
        nav_lay = QVBoxLayout(nav_widget)
        nav_lay.setContentsMargins(8, 12, 8, 8)
        nav_lay.setSpacing(2)

        self._nav_buttons: list[_NavButton] = []
        for icon, label, tip in _NAV_ITEMS:
            btn = _NavButton(icon, label, tip)
            btn.clicked.connect(lambda _, b=btn: self._nav_click(b))
            nav_lay.addWidget(btn)
            self._nav_buttons.append(btn)

        nav_lay.addStretch()
        sb_lay.addWidget(nav_widget, stretch=1)

        # Bottom: version + status
        bottom = QWidget()
        bottom.setStyleSheet("background-color: #060a14;")
        bot_lay = QVBoxLayout(bottom)
        bot_lay.setContentsMargins(12, 8, 12, 16)
        bot_lay.setSpacing(8)

        sep_b = QFrame()
        sep_b.setFrameShape(QFrame.Shape.HLine)
        sep_b.setStyleSheet("background-color: #1a2e45; max-height: 1px; border: none;")
        bot_lay.addWidget(sep_b)

        self._status_badge = QLabel("● IDLE")
        self._status_badge.setObjectName("StatusBadge")
        self._status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bot_lay.addWidget(self._status_badge)

        self._fs_btn = QPushButton("⛶  Full Screen  (F11)")
        self._fs_btn.setStyleSheet(
            "QPushButton { background: transparent; color: #243550;"
            " border: 1px solid #1a2e45; border-radius: 7px;"
            " padding: 6px 10px; font-size: 11px; }"
            "QPushButton:hover { color: #8fadc8; border-color: #2a3f5f; }")
        self._fs_btn.clicked.connect(self._toggle_fullscreen)
        bot_lay.addWidget(self._fs_btn)

        ver_lbl = QLabel("v2.0.0  ·  2026")
        ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver_lbl.setStyleSheet(
            "color: #1e3050; font-size: 10px; background: transparent;")
        bot_lay.addWidget(ver_lbl)

        sb_lay.addWidget(bottom)

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

        self._scan_tab._start_btn.clicked.connect(self._on_scan_started)
        self._scan_tab._stop_btn.clicked.connect(
            lambda: self._set_scanning(False))

        # F11 fullscreen shortcut
        fs_shortcut = QShortcut(QKeySequence("F11"), self)
        fs_shortcut.activated.connect(self._toggle_fullscreen)

        # Default: Dashboard
        self._nav_buttons[0].setChecked(True)
        self._stack.setCurrentIndex(0)

    def _nav_click(self, clicked: _NavButton):
        for btn in self._nav_buttons:
            active = btn is clicked
            btn.setChecked(active)
            btn.setProperty("active", "true" if active else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        idx = self._nav_buttons.index(clicked)
        self._stack.setCurrentIndex(idx)

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

    def _toggle_fullscreen(self):
        if self.isFullScreen():
            self.showMaximized()
            self._fs_btn.setText("⛶  Full Screen  (F11)")
        else:
            self.showFullScreen()
            self._fs_btn.setText("⊠  Exit Full Screen  (F11)")

    def _on_settings_saved(self, d: dict):
        if d.get("output_dir"):
            self._dashboard._output_dir = d["output_dir"]
            self._scan_tab._output_dir  = d["output_dir"]
            self._reports._output_dir   = d["output_dir"]
