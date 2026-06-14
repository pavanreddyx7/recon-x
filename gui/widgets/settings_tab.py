import json
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QPushButton, QSlider,
    QGroupBox, QGridLayout, QFileDialog, QFrame,
    QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont


_SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "gui_settings.json"
)

_DEFAULTS = {
    "nvd_api_key":      "",
    "output_dir":       "",
    "default_profile":  "standard",
    "port_range":       "1-1024",
    "threads":          150,
    "timeout":          10,
}


def load_settings() -> dict:
    if os.path.exists(_SETTINGS_FILE):
        try:
            with open(_SETTINGS_FILE) as f:
                d = json.load(f)
            merged = dict(_DEFAULTS)
            merged.update(d)
            return merged
        except Exception:
            pass
    return dict(_DEFAULTS)


def save_settings(d: dict):
    with open(_SETTINGS_FILE, "w") as f:
        json.dump(d, f, indent=2)


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("SectionLabel")
    return lbl


def _field_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet("color: #4b5e7a; font-size: 12px; font-weight: 600;")
    lbl.setMinimumWidth(130)
    return lbl


class SettingsTab(QWidget):
    settings_saved = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._load()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        root = QVBoxLayout(content)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(20)

        # Page header
        title = QLabel("Settings")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet("color: #cbd5e1;")
        root.addWidget(title)
        sub = QLabel("Configure API keys, output options, and scan defaults")
        sub.setStyleSheet("color: #3d5470; font-size: 12px;")
        root.addWidget(sub)

        # ── API Configuration ──────────────────────────────────────────────
        api_box = QGroupBox("API CONFIGURATION")
        api_grid = QGridLayout(api_box)
        api_grid.setSpacing(12)
        api_grid.setHorizontalSpacing(16)

        api_grid.addWidget(_field_label("NVD API Key"), 0, 0)
        self._api_key = QLineEdit()
        self._api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key.setPlaceholderText("Leave blank for anonymous (5 req / 30 s)")
        api_grid.addWidget(self._api_key, 0, 1)

        show_btn = QPushButton("Show")
        show_btn.setFixedWidth(70)
        show_btn.setCheckable(True)
        show_btn.toggled.connect(lambda on: self._api_key.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        api_grid.addWidget(show_btn, 0, 2)

        hint = QLabel("Get a free key at  nvd.nist.gov/developers/request-an-api-key")
        hint.setStyleSheet("color: #243550; font-size: 11px;")
        api_grid.addWidget(hint, 1, 1, 1, 2)

        root.addWidget(api_box)

        # ── Output ─────────────────────────────────────────────────────────
        out_box = QGroupBox("OUTPUT DIRECTORY")
        out_grid = QGridLayout(out_box)
        out_grid.setSpacing(12)

        out_grid.addWidget(_field_label("Output Directory"), 0, 0)
        self._output_dir = QLineEdit()
        self._output_dir.setPlaceholderText("Default: ./output/")
        out_grid.addWidget(self._output_dir, 0, 1)

        browse = QPushButton("Browse…")
        browse.setFixedWidth(90)
        browse.clicked.connect(self._browse_output)
        out_grid.addWidget(browse, 0, 2)

        root.addWidget(out_box)

        # ── Scan Defaults ──────────────────────────────────────────────────
        scan_box = QGroupBox("SCAN DEFAULTS")
        scan_grid = QGridLayout(scan_box)
        scan_grid.setSpacing(12)
        scan_grid.setHorizontalSpacing(16)

        scan_grid.addWidget(_field_label("Default Profile"), 0, 0)
        self._profile = QComboBox()
        self._profile.addItems(["standard", "quick", "full", "stealth"])
        scan_grid.addWidget(self._profile, 0, 1)

        profile_hint = QLabel(
            "standard — balanced  ·  quick — fast, fewer checks  "
            "·  full — deep, slower  ·  stealth — low-noise")
        profile_hint.setStyleSheet("color: #243550; font-size: 11px;")
        scan_grid.addWidget(profile_hint, 1, 1)

        scan_grid.addWidget(_field_label("Default Port Range"), 2, 0)
        self._port_range = QLineEdit()
        self._port_range.setPlaceholderText("e.g. 1-1024  or  80,443,8080")
        scan_grid.addWidget(self._port_range, 2, 1)

        # Threads slider
        scan_grid.addWidget(_field_label("Max Threads"), 3, 0)
        thread_row = QHBoxLayout()
        self._threads_slider = QSlider(Qt.Orientation.Horizontal)
        self._threads_slider.setRange(10, 300)
        self._threads_slider.setValue(150)
        self._threads_val = QLabel("150")
        self._threads_val.setFixedWidth(40)
        self._threads_val.setStyleSheet("color: #00ff88; font-weight: 600;")
        self._threads_slider.valueChanged.connect(
            lambda v: self._threads_val.setText(str(v)))
        thread_row.addWidget(self._threads_slider)
        thread_row.addWidget(self._threads_val)
        scan_grid.addLayout(thread_row, 3, 1)

        # Timeout slider
        scan_grid.addWidget(_field_label("Timeout (seconds)"), 4, 0)
        timeout_row = QHBoxLayout()
        self._timeout_slider = QSlider(Qt.Orientation.Horizontal)
        self._timeout_slider.setRange(2, 60)
        self._timeout_slider.setValue(10)
        self._timeout_val = QLabel("10 s")
        self._timeout_val.setFixedWidth(40)
        self._timeout_val.setStyleSheet("color: #00ff88; font-weight: 600;")
        self._timeout_slider.valueChanged.connect(
            lambda v: self._timeout_val.setText(f"{v} s"))
        timeout_row.addWidget(self._timeout_slider)
        timeout_row.addWidget(self._timeout_val)
        scan_grid.addLayout(timeout_row, 4, 1)

        root.addWidget(scan_box)

        # ── Save / Reset ───────────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background-color: #1a2e45; max-height: 1px; border: none;")
        root.addWidget(sep)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("StartButton")
        save_btn.setFixedWidth(160)
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(save_btn)

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.setFixedWidth(150)
        reset_btn.clicked.connect(self._reset)
        btn_row.addWidget(reset_btn)

        btn_row.addStretch()

        self._saved_lbl = QLabel("")
        self._saved_lbl.setStyleSheet("color: #00ff88; font-size: 13px; font-weight: 600;")
        btn_row.addWidget(self._saved_lbl)
        root.addLayout(btn_row)

        root.addStretch()

    def _browse_output(self):
        path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if path:
            self._output_dir.setText(path)

    def _load(self):
        d = load_settings()
        self._api_key.setText(d.get("nvd_api_key", ""))
        self._output_dir.setText(d.get("output_dir", ""))
        idx = self._profile.findText(d.get("default_profile", "standard"))
        self._profile.setCurrentIndex(max(0, idx))
        self._port_range.setText(d.get("port_range", "1-1024"))
        self._threads_slider.setValue(int(d.get("threads", 150)))
        self._timeout_slider.setValue(int(d.get("timeout", 10)))

    def _save(self):
        d = {
            "nvd_api_key":     self._api_key.text().strip(),
            "output_dir":      self._output_dir.text().strip(),
            "default_profile": self._profile.currentText(),
            "port_range":      self._port_range.text().strip(),
            "threads":         self._threads_slider.value(),
            "timeout":         self._timeout_slider.value(),
        }
        save_settings(d)

        if d["nvd_api_key"]:
            try:
                from config import cfg
                cfg.cve.api_key = d["nvd_api_key"]
            except Exception:
                pass

        self._saved_lbl.setText("✔  Saved")
        self.settings_saved.emit(d)
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(2500, lambda: self._saved_lbl.setText(""))

    def _reset(self):
        save_settings(dict(_DEFAULTS))
        self._load()
        self._saved_lbl.setText("✔  Reset")
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(2000, lambda: self._saved_lbl.setText(""))
