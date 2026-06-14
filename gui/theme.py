DARK_QSS = """
/* ═══════════════════════════════════════════════════════
   R3CON-X  ·  Cybersecurity Intelligence Platform
   Dark Professional Theme
   ═══════════════════════════════════════════════════════ */

/* ── Global Reset ──────────────────────────────────────── */
* {
    font-family: 'Inter', 'Segoe UI', 'Ubuntu', sans-serif;
    font-size: 13px;
    color: #cbd5e1;
}

QMainWindow, QDialog {
    background-color: #0b0f1a;
}

QWidget {
    background-color: #0b0f1a;
    color: #cbd5e1;
}

/* ── Sidebar ────────────────────────────────────────────── */
#Sidebar {
    background-color: #070b14;
    border-right: 1px solid #1a2235;
}

#NavButton {
    background-color: transparent;
    color: #4b5e7a;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0px;
    padding: 12px 16px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}
#NavButton:hover {
    background-color: #0f1929;
    color: #8fadc8;
    border-left: 3px solid #1a2e45;
}
#NavButton:checked, #NavButton[active="true"] {
    background-color: #0a1f35;
    color: #00ff88;
    border-left: 3px solid #00ff88;
    font-weight: 600;
}

#StatusBadge {
    background-color: #0d1729;
    border: 1px solid #1a2e45;
    border-radius: 14px;
    padding: 6px 14px;
    font-size: 11px;
    color: #00ff88;
    font-weight: 700;
    letter-spacing: 0.8px;
}
#StatusBadge[scanning="true"] {
    color: #f59e0b;
    border-color: #f59e0b55;
    background-color: #1a1200;
}

/* ── Cards ──────────────────────────────────────────────── */
#Card {
    background-color: #0f1929;
    border: 1px solid #1a2e45;
    border-radius: 12px;
    padding: 16px;
}
#CardIcon {
    font-size: 22px;
    padding-bottom: 4px;
}
#CardTitle {
    color: #4b5e7a;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.2px;
}
#CardValue {
    color: #00ff88;
    font-size: 30px;
    font-weight: 700;
    letter-spacing: -0.5px;
}
#CardLabel {
    color: #374151;
    font-size: 11px;
}

/* ── Tables ─────────────────────────────────────────────── */
QTableWidget {
    background-color: #0d1525;
    border: 1px solid #1a2e45;
    border-radius: 10px;
    gridline-color: #142035;
    selection-background-color: #00ff8810;
    selection-color: #e2e8f0;
    alternate-background-color: #0f1929;
    show-decoration-selected: 1;
}
QTableWidget::item {
    padding: 9px 12px;
    border: none;
    border-bottom: 1px solid #142035;
}
QTableWidget::item:selected {
    background-color: #00ff8812;
    color: #e2e8f0;
}
QTableWidget::item:hover:!selected {
    background-color: #0f1929;
}
QHeaderView {
    background-color: transparent;
}
QHeaderView::section {
    background-color: #08111f;
    color: #3d5470;
    border: none;
    border-bottom: 1px solid #1a2e45;
    border-right: 1px solid #142035;
    padding: 9px 12px;
    font-weight: 700;
    font-size: 10px;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}
QHeaderView::section:last {
    border-right: none;
}
QHeaderView::section:hover {
    background-color: #0d1929;
    color: #5b7a9a;
}

/* ── Buttons ────────────────────────────────────────────── */
QPushButton {
    background-color: #0f1929;
    color: #8fadc8;
    border: 1px solid #1a2e45;
    border-radius: 8px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 500;
    outline: none;
}
QPushButton:hover {
    background-color: #142035;
    color: #cbd5e1;
    border-color: #2a3f5f;
}
QPushButton:pressed {
    background-color: #0a1525;
    border-color: #00ff8840;
}
QPushButton:disabled {
    background-color: #080d18;
    color: #1e2f45;
    border-color: #121e30;
}
QPushButton:checked {
    background-color: #00ff8814;
    color: #00ff88;
    border-color: #00ff8844;
}

#StartButton {
    background-color: #003d22;
    color: #00ff88;
    border: 1px solid #00ff8855;
    font-weight: 700;
    font-size: 14px;
    padding: 11px 36px;
    border-radius: 9px;
    letter-spacing: 0.4px;
}
#StartButton:hover {
    background-color: #005230;
    border-color: #00ff8899;
    color: #33ffaa;
}
#StartButton:pressed {
    background-color: #002a18;
}
#StartButton:disabled {
    background-color: #0a1a12;
    color: #1a5533;
    border-color: #1a4028;
}

#StopButton {
    background-color: #3d0a00;
    color: #ff7b72;
    border: 1px solid #ff7b7255;
    font-weight: 700;
    font-size: 14px;
    padding: 11px 36px;
    border-radius: 9px;
}
#StopButton:hover {
    background-color: #521200;
    border-color: #ff7b7299;
    color: #ff9990;
}
#StopButton:pressed {
    background-color: #280600;
}
#StopButton:disabled {
    background-color: #150300;
    color: #3d1a18;
    border-color: #2d1210;
}

/* ── Inputs ─────────────────────────────────────────────── */
QLineEdit, QSpinBox {
    background-color: #0d1729;
    color: #cbd5e1;
    border: 1px solid #1a2e45;
    border-radius: 8px;
    padding: 9px 13px;
    selection-background-color: #00ff8825;
    font-size: 13px;
}
QLineEdit:focus, QSpinBox:focus {
    border-color: #00ff8860;
    background-color: #0f1e36;
}
QLineEdit:hover, QSpinBox:hover {
    border-color: #243550;
}

QComboBox {
    background-color: #0d1729;
    color: #cbd5e1;
    border: 1px solid #1a2e45;
    border-radius: 8px;
    padding: 9px 13px;
    selection-background-color: #00ff8825;
    font-size: 13px;
    min-height: 20px;
}
QComboBox:focus {
    border-color: #00ff8860;
}
QComboBox:hover {
    border-color: #243550;
}
QComboBox::drop-down {
    border: none;
    background-color: transparent;
    width: 30px;
    border-left: 1px solid #1a2e45;
}
QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid #4b5e7a;
    width: 0; height: 0;
    margin-right: 8px;
}
QComboBox QAbstractItemView {
    background-color: #0d1729;
    border: 1px solid #1a2e45;
    border-radius: 8px;
    selection-background-color: #00ff8815;
    selection-color: #00ff88;
    color: #cbd5e1;
    padding: 6px;
    outline: none;
}
QComboBox QAbstractItemView::item {
    min-height: 30px;
    padding: 4px 10px;
    border-radius: 5px;
}

/* ── CheckBox ───────────────────────────────────────────── */
QCheckBox {
    color: #8fadc8;
    spacing: 9px;
    font-size: 13px;
}
QCheckBox::indicator {
    width: 17px; height: 17px;
    border: 2px solid #243550;
    border-radius: 4px;
    background-color: #0d1729;
}
QCheckBox::indicator:checked {
    background-color: #00c96e;
    border-color: #00c96e;
}
QCheckBox::indicator:hover {
    border-color: #00ff8866;
}

/* ── Progress bars ──────────────────────────────────────── */
QProgressBar {
    background-color: #0d1525;
    border: none;
    border-radius: 4px;
    text-align: center;
    color: transparent;
    height: 5px;
    max-height: 5px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #00ff88, stop:1 #00b8d4);
    border-radius: 4px;
}

/* ── Tabs ───────────────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid #1a2e45;
    border-radius: 10px;
    background-color: #0b0f1a;
    top: -1px;
}
QTabBar {
    background-color: transparent;
}
QTabBar::tab {
    background-color: transparent;
    color: #3d5470;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 10px 22px;
    font-size: 13px;
    font-weight: 500;
    margin-right: 2px;
    min-width: 90px;
}
QTabBar::tab:selected {
    color: #00ff88;
    border-bottom: 2px solid #00ff88;
}
QTabBar::tab:hover:!selected {
    color: #8fadc8;
    border-bottom: 2px solid #1a2e45;
}

/* ── ScrollBars ─────────────────────────────────────────── */
QScrollBar:vertical {
    background-color: transparent;
    width: 7px;
    margin: 2px 0;
}
QScrollBar::handle:vertical {
    background-color: #1a2e45;
    border-radius: 3px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background-color: #243550;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }

QScrollBar:horizontal {
    background-color: transparent;
    height: 7px;
}
QScrollBar::handle:horizontal {
    background-color: #1a2e45;
    border-radius: 3px;
    min-width: 30px;
}
QScrollBar::handle:horizontal:hover {
    background-color: #243550;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Slider ─────────────────────────────────────────────── */
QSlider::groove:horizontal {
    background-color: #1a2e45;
    height: 4px;
    border-radius: 2px;
}
QSlider::handle:horizontal {
    background-color: #00ff88;
    width: 16px; height: 16px;
    margin: -6px 0;
    border-radius: 8px;
    border: 2px solid #009955;
}
QSlider::handle:horizontal:hover {
    background-color: #33ffaa;
}
QSlider::sub-page:horizontal {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #00ff88, stop:1 #00b8d4);
    border-radius: 2px;
}

/* ── Plain text / log ───────────────────────────────────── */
QPlainTextEdit {
    background-color: #060a13;
    color: #7a95b0;
    border: 1px solid #1a2e45;
    border-radius: 10px;
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 12px;
    selection-background-color: #00ff8820;
    padding: 6px;
    line-height: 1.5;
}

QTextEdit {
    background-color: #060a13;
    color: #7a95b0;
    border: 1px solid #1a2e45;
    border-radius: 10px;
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
    font-size: 12px;
    selection-background-color: #00ff8820;
    padding: 6px;
}

/* ── Labels ─────────────────────────────────────────────── */
QLabel {
    background-color: transparent;
    color: #cbd5e1;
}
#SectionLabel {
    color: #3d5470;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.2px;
    padding-bottom: 8px;
    border-bottom: 1px solid #1a2e45;
}

/* ── Splitter ───────────────────────────────────────────── */
QSplitter::handle {
    background-color: #1a2e45;
    border-radius: 2px;
    margin: 2px;
}
QSplitter::handle:horizontal { width: 4px; }
QSplitter::handle:vertical   { height: 4px; }

/* ── GroupBox ───────────────────────────────────────────── */
QGroupBox {
    background-color: #0f1929;
    border: 1px solid #1a2e45;
    border-radius: 12px;
    margin-top: 22px;
    padding: 16px 16px 16px 16px;
    font-weight: 700;
    font-size: 10px;
    letter-spacing: 0.8px;
    color: #3d5470;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 16px;
    top: 6px;
    padding: 2px 10px;
    color: #3d5470;
    background-color: #0f1929;
    border-radius: 5px;
    border: 1px solid #1a2e45;
}

/* ── Menu ───────────────────────────────────────────────── */
QMenu {
    background-color: #0f1929;
    border: 1px solid #1a2e45;
    border-radius: 10px;
    padding: 6px;
    color: #cbd5e1;
}
QMenu::item {
    padding: 9px 18px;
    border-radius: 6px;
}
QMenu::item:selected {
    background-color: #00ff8812;
    color: #00ff88;
}
QMenu::separator {
    height: 1px;
    background-color: #1a2e45;
    margin: 4px 10px;
}

/* ── ToolTip ────────────────────────────────────────────── */
QToolTip {
    background-color: #0f1929;
    color: #cbd5e1;
    border: 1px solid #243550;
    border-radius: 7px;
    padding: 7px 12px;
    font-size: 12px;
}

/* ── Frame lines ────────────────────────────────────────── */
QFrame[frameShape="4"],
QFrame[frameShape="5"] {
    background-color: #1a2e45;
    max-height: 1px;
    border: none;
}

/* ── FileDialog ─────────────────────────────────────────── */
QFileDialog {
    background-color: #0b0f1a;
}
"""

SEV_COLORS = {
    "CRITICAL": "#ff4757",
    "HIGH":     "#ff7b2d",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#3b9eff",
    "NONE":     "#4b5e7a",
    "INFO":     "#00b8d4",
}

LEVEL_COLORS = {
    "info":    "#5b9bd5",
    "warn":    "#f59e0b",
    "warning": "#f59e0b",
    "error":   "#ff4757",
    "success": "#00ff88",
    "debug":   "#3d5470",
    "section": "#a78bfa",
}
