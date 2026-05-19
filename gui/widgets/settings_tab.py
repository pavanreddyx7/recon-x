import json
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QPushButton, QSlider,
    QGroupBox, QGridLayout, QFileDialog, QMessageBox,
    QCheckBox, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QIntValidator


_SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "gui_settings.json"
)

_DEFAULTS = {
    "nvd_api_key":   "",
    "output_dir":    "",
    "default_profile": "standard",
    "port_range":    "1-1024",
    "threads":       150,
    "timeout":       10,
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


class SettingsTab(QWidget):
    settings_saved = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._load()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(16)

        title = QLabel("Settings")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        root.addWidget(title)

        # API Settings
        api_box = QGroupBox("API Configuration")
        api_grid = QGridLayout(api_box)
        api_grid.setSpacing(10)

        api_grid.addWidget(QLabel("NVD API Key:"), 0, 0)
        self._api_key = QLineEdit()
        self._api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key.setPlaceholderText("Leave blank for anonymous (5 req/30s)")
        api_grid.addWidget(self._api_key, 0, 1)
        show_btn = QPushButton("Show")
        show_btn.setFixedWidth(60)
        show_btn.setCheckable(True)
        show_btn.toggled.connect(lambda checked: self._api_key.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password))
        api_grid.addWidget(show_btn, 0, 2)

        root.addWidget(api_box)

        # Output Settings
        out_box = QGroupBox("Output")
        out_grid = QGridLayout(out_box)
        out_grid.setSpacing(10)

        out_grid.addWidget(QLabel("Output Directory:"), 0, 0)
        self._output_dir = QLineEdit()
        self._output_dir.setPlaceholderText("Default: ./output/")
        out_grid.addWidget(self._output_dir, 0, 1)
        browse = QPushButton("Browse")
        browse.setFixedWidth(70)
        browse.clicked.connect(self._browse_output)
        out_grid.addWidget(browse, 0, 2)

        root.addWidget(out_box)

        # Scan Defaults
        scan_box = QGroupBox("Scan Defaults")
        scan_grid = QGridLayout(scan_box)
        scan_grid.setSpacing(10)

        scan_grid.addWidget(QLabel("Default Profile:"), 0, 0)
        self._profile = QComboBox()
        self._profile.addItems(["standard", "quick", "full", "stealth"])
        scan_grid.addWidget(self._profile, 0, 1)

        scan_grid.addWidget(QLabel("Default Port Range:"), 1, 0)
        self._port_range = QLineEdit()
        self._port_range.setPlaceholderText("e.g. 1-1024 or 80,443,8080")
        scan_grid.addWidget(self._port_range, 1, 1)

        scan_grid.addWidget(QLabel("Threads:"), 2, 0)
        thread_row = QHBoxLayout()
        self._threads_slider = QSlider(Qt.Orientation.Horizontal)
        self._threads_slider.setRange(10, 300)
        self._threads_slider.setValue(150)
        self._threads_val = QLabel("150")
        self._threads_val.setFixedWidth(36)
        self._threads_slider.valueChanged.connect(
            lambda v: self._threads_val.setText(str(v)))
        thread_row.addWidget(self._threads_slider)
        thread_row.addWidget(self._threads_val)
        scan_grid.addLayout(thread_row, 2, 1)

        scan_grid.addWidget(QLabel("Timeout (s):"), 3, 0)
        timeout_row = QHBoxLayout()
        self._timeout_slider = QSlider(Qt.Orientation.Horizontal)
        self._timeout_slider.setRange(2, 30)
        self._timeout_slider.setValue(10)
        self._timeout_val = QLabel("10s")
        self._timeout_val.setFixedWidth(36)
        self._timeout_slider.valueChanged.connect(
            lambda v: self._timeout_val.setText(f"{v}s"))
        timeout_row.addWidget(self._timeout_slider)
        timeout_row.addWidget(self._timeout_val)
        scan_grid.addLayout(timeout_row, 3, 1)

        root.addWidget(scan_box)

        # Save button
        btn_row = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("StartButton")
        save_btn.setFixedWidth(150)
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(save_btn)

        reset_btn = QPushButton("Reset Defaults")
        reset_btn.setFixedWidth(130)
        reset_btn.clicked.connect(self._reset)
        btn_row.addWidget(reset_btn)
        btn_row.addStretch()

        self._saved_lbl = QLabel("")
        self._saved_lbl.setStyleSheet("color: #00ff88;")
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
        self._threads_slider.setValue(d.get("threads", 150))
        self._timeout_slider.setValue(d.get("timeout", 10))

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

        # Apply NVD key to config immediately
        if d["nvd_api_key"]:
            try:
                from config import cfg
                cfg.cve.api_key = d["nvd_api_key"]
            except Exception:
                pass

        self._saved_lbl.setText("Saved ✔")
        self.settings_saved.emit(d)
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(2000, lambda: self._saved_lbl.setText(""))

    def _reset(self):
        d = dict(_DEFAULTS)
        save_settings(d)
        self._load()
        self._saved_lbl.setText("Reset ✔")
