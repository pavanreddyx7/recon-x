from PyQt6.QtWidgets import QLabel
from PyQt6.QtCore import Qt
from gui.theme import SEV_COLORS


class SeverityBadge(QLabel):
    def __init__(self, severity: str = "", parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSeverity(severity)

    def setSeverity(self, severity: str) -> None:
        sev   = severity.upper()
        color = SEV_COLORS.get(sev, "#4b5e7a")
        self.setText(sev or "—")
        self.setStyleSheet(f"""
            QLabel {{
                color: {color};
                background-color: {color}18;
                border: 1px solid {color}55;
                border-radius: 5px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.5px;
                font-family: 'JetBrains Mono', 'Consolas', monospace;
            }}
        """)
