from PyQt6.QtWidgets import QLabel
from PyQt6.QtCore import Qt
from gui.theme import SEV_COLORS


class SeverityBadge(QLabel):
    def __init__(self, severity: str = "", parent=None):
        super().__init__(parent)
        self.setSeverity(severity)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def setSeverity(self, severity: str) -> None:
        sev = severity.upper()
        color = SEV_COLORS.get(sev, "#606070")
        self.setText(sev or "—")
        self.setStyleSheet(f"""
            QLabel {{
                color: {color};
                background-color: {color}22;
                border: 1px solid {color}66;
                border-radius: 4px;
                padding: 2px 8px;
                font-size: 11px;
                font-weight: bold;
                font-family: 'Consolas', monospace;
            }}
        """)
