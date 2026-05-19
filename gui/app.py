#!/usr/bin/env python3
"""
R3CON-X Desktop GUI — Entry Point
Launch: python3 gui/app.py
"""
import os
import sys

# Bootstrap path so reconX modules are importable
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Ensure venv / user packages are accessible
def _bootstrap():
    vi = sys.version_info
    candidates = [
        os.path.join(_ROOT, "venv", "lib",
                     f"python{vi.major}.{vi.minor}", "site-packages"),
        os.path.join(os.path.expanduser("~"), ".local", "lib",
                     f"python{vi.major}.{vi.minor}", "site-packages"),
        os.path.join(os.path.expanduser(
            f"~{os.environ.get('SUDO_USER', '')}"), ".local", "lib",
            f"python{vi.major}.{vi.minor}", "site-packages"),
    ]
    for p in candidates:
        if os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)

_bootstrap()

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt

from config import cfg
from gui.main_window import MainWindow
from gui.widgets.settings_tab import load_settings


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("R3CON-X")
    app.setApplicationVersion("2.0.0")
    app.setOrganizationName("R3CON-X Security")

    # High-DPI support
    app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    # Default font
    font = QFont("Segoe UI", 13)
    app.setFont(font)

    # Load saved settings and apply
    settings   = load_settings()
    output_dir = settings.get("output_dir") or cfg.output_dir
    os.makedirs(output_dir, exist_ok=True)

    if settings.get("nvd_api_key"):
        cfg.cve.api_key = settings["nvd_api_key"]

    window = MainWindow(output_dir)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
