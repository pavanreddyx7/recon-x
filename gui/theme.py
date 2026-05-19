DARK_QSS = """
/* ── Global ── */
* {
    font-family: 'Segoe UI', 'Inter', 'Ubuntu', sans-serif;
    font-size: 13px;
    color: #e0e0e0;
}
QMainWindow, QDialog {
    background-color: #0d0d0d;
}
QWidget {
    background-color: #0d0d0d;
    color: #e0e0e0;
}

/* ── Sidebar ── */
#Sidebar {
    background-color: #0a0a1a;
    border-right: 1px solid #00ff8822;
}
#SidebarTitle {
    color: #00ff88;
    font-size: 11px;
    font-family: 'Consolas', 'JetBrains Mono', monospace;
    padding: 8px 4px 4px 4px;
}
#NavButton {
    background-color: transparent;
    color: #a0a0b0;
    border: none;
    border-radius: 6px;
    padding: 10px 16px;
    text-align: left;
    font-size: 13px;
}
#NavButton:hover {
    background-color: #1a1a2e;
    color: #00d4ff;
}
#NavButton[active="true"] {
    background-color: #0d2040;
    color: #00ff88;
    border-left: 3px solid #00ff88;
}
#StatusBadge {
    background-color: #1a1a2e;
    border: 1px solid #00ff8844;
    border-radius: 10px;
    padding: 4px 10px;
    font-size: 11px;
    color: #00ff88;
}
#StatusBadge[scanning="true"] {
    color: #ffcc00;
    border-color: #ffcc0044;
}

/* ── Cards ── */
#Card {
    background-color: #16213e;
    border: 1px solid #00ff8820;
    border-radius: 8px;
    padding: 12px;
}
#CardTitle {
    color: #00d4ff;
    font-size: 11px;
    font-weight: bold;
}
#CardValue {
    color: #00ff88;
    font-size: 26px;
    font-weight: bold;
}
#CardLabel {
    color: #808090;
    font-size: 11px;
}

/* ── Tables ── */
QTableWidget {
    background-color: #111122;
    border: 1px solid #00ff8818;
    border-radius: 6px;
    gridline-color: #1a1a2e;
    selection-background-color: #0d2040;
    selection-color: #00d4ff;
    alternate-background-color: #13132a;
}
QTableWidget::item {
    padding: 6px 8px;
    border: none;
}
QTableWidget::item:selected {
    background-color: #0d2040;
    color: #00d4ff;
}
QHeaderView::section {
    background-color: #0a0a1a;
    color: #00d4ff;
    border: none;
    border-bottom: 1px solid #00ff8830;
    padding: 6px 8px;
    font-weight: bold;
    font-size: 12px;
}

/* ── Buttons ── */
QPushButton {
    background-color: #1a1a2e;
    color: #e0e0e0;
    border: 1px solid #00ff8830;
    border-radius: 6px;
    padding: 7px 18px;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #0d2040;
    color: #00d4ff;
    border-color: #00d4ff66;
}
QPushButton:pressed {
    background-color: #001a30;
}
QPushButton:disabled {
    background-color: #111118;
    color: #404050;
    border-color: #303040;
}
#StartButton {
    background-color: #003320;
    color: #00ff88;
    border: 1px solid #00ff8866;
    font-weight: bold;
    font-size: 14px;
    padding: 10px 28px;
    border-radius: 8px;
}
#StartButton:hover {
    background-color: #004428;
    border-color: #00ff88;
}
#StopButton {
    background-color: #330000;
    color: #ff4444;
    border: 1px solid #ff444466;
    font-weight: bold;
    font-size: 14px;
    padding: 10px 28px;
    border-radius: 8px;
}
#StopButton:hover {
    background-color: #440000;
    border-color: #ff4444;
}

/* ── Inputs ── */
QLineEdit, QComboBox, QSpinBox {
    background-color: #111122;
    color: #e0e0e0;
    border: 1px solid #00ff8828;
    border-radius: 5px;
    padding: 6px 10px;
    selection-background-color: #0d2040;
}
QLineEdit:focus, QComboBox:focus {
    border-color: #00ff8866;
}
QComboBox::drop-down {
    border: none;
    background-color: #1a1a2e;
    width: 24px;
    border-radius: 0 5px 5px 0;
}
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 6px solid #00d4ff;
    width: 0; height: 0;
}
QComboBox QAbstractItemView {
    background-color: #111122;
    border: 1px solid #00ff8830;
    selection-background-color: #0d2040;
    color: #e0e0e0;
}

/* ── CheckBox ── */
QCheckBox {
    color: #c0c0d0;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #00ff8840;
    border-radius: 3px;
    background-color: #111122;
}
QCheckBox::indicator:checked {
    background-color: #00ff88;
    border-color: #00ff88;
}

/* ── Progress bars ── */
QProgressBar {
    background-color: #111122;
    border: 1px solid #00ff8820;
    border-radius: 4px;
    text-align: center;
    color: #808090;
    height: 14px;
}
QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #00ff88, stop:1 #00d4ff);
    border-radius: 3px;
}

/* ── Tabs ── */
QTabWidget::pane {
    border: 1px solid #00ff8820;
    border-radius: 6px;
    background-color: #0d0d0d;
}
QTabBar::tab {
    background-color: #111122;
    color: #808090;
    border: 1px solid #00ff8820;
    border-bottom: none;
    padding: 7px 18px;
    border-radius: 5px 5px 0 0;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #0d0d0d;
    color: #00d4ff;
    border-color: #00d4ff40;
}
QTabBar::tab:hover {
    background-color: #1a1a2e;
    color: #00ff88;
}

/* ── ScrollBars ── */
QScrollBar:vertical {
    background-color: #111122;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background-color: #303050;
    border-radius: 4px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background-color: #00ff8840;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background-color: #111122;
    height: 8px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background-color: #303050;
    border-radius: 4px;
    min-width: 30px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Slider ── */
QSlider::groove:horizontal {
    background-color: #111122;
    height: 6px;
    border-radius: 3px;
}
QSlider::handle:horizontal {
    background-color: #00ff88;
    width: 14px; height: 14px;
    margin: -4px 0;
    border-radius: 7px;
}
QSlider::sub-page:horizontal {
    background-color: #00ff8840;
    border-radius: 3px;
}

/* ── Plain text / log ── */
QPlainTextEdit {
    background-color: #080810;
    color: #c0c0d0;
    border: 1px solid #00ff8818;
    border-radius: 6px;
    font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: #0d2040;
}

/* ── Labels ── */
QLabel {
    background-color: transparent;
    color: #e0e0e0;
}
#SectionLabel {
    color: #00d4ff;
    font-size: 12px;
    font-weight: bold;
    padding-bottom: 4px;
    border-bottom: 1px solid #00d4ff30;
}

/* ── Splitter ── */
QSplitter::handle {
    background-color: #1a1a2e;
}

/* ── GroupBox ── */
QGroupBox {
    border: 1px solid #00ff8820;
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 8px;
    color: #00d4ff;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: #00d4ff;
}
"""

SEV_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#00ccff",
    "NONE":     "#606070",
    "INFO":     "#00d4ff",
}

LEVEL_COLORS = {
    "info":    "#00d4ff",
    "warn":    "#ffcc00",
    "warning": "#ffcc00",
    "error":   "#ff4444",
    "success": "#00ff88",
    "debug":   "#606070",
    "section": "#c084fc",
}
