import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                              QPlainTextEdit, QPushButton, QCheckBox, QLabel)
from PyQt6.QtGui import QTextCharFormat, QColor, QTextCursor, QFont

from gui.theme import LEVEL_COLORS


_RICH_TAG = re.compile(r'\[/?[a-zA-Z0-9_.# ]+\]')


def _strip_rich(text: str) -> str:
    return _RICH_TAG.sub('', text).strip()


class LogConsole(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._auto_scroll = True
        self._line_count  = 0
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Toolbar
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self._line_lbl = QLabel("0 lines")
        self._line_lbl.setStyleSheet(
            "color: #243550; font-size: 11px; background: transparent;")
        bar.addWidget(self._line_lbl)
        bar.addStretch()

        self._auto_cb = QCheckBox("Auto-scroll")
        self._auto_cb.setChecked(True)
        self._auto_cb.setStyleSheet("color: #4b5e7a; font-size: 12px;")
        self._auto_cb.toggled.connect(lambda c: setattr(self, '_auto_scroll', c))
        bar.addWidget(self._auto_cb)

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedWidth(64)
        clear_btn.clicked.connect(self.clear)
        bar.addWidget(clear_btn)

        copy_btn = QPushButton("Copy")
        copy_btn.setFixedWidth(64)
        copy_btn.clicked.connect(self._copy_all)
        bar.addWidget(copy_btn)

        layout.addLayout(bar)

        # Log display
        self._edit = QPlainTextEdit()
        self._edit.setReadOnly(True)
        self._edit.setMaximumBlockCount(5000)
        mono = QFont("JetBrains Mono", 11)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._edit.setFont(mono)
        layout.addWidget(self._edit)

    def append(self, message: str, level: str = "info"):
        clean = _strip_rich(message)
        if not clean:
            return

        color = LEVEL_COLORS.get(level.lower(), "#cbd5e1")
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))

        cursor = self._edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(clean + "\n", fmt)

        self._line_count += 1
        self._line_lbl.setText(f"{self._line_count} lines")

        if self._auto_scroll:
            self._edit.setTextCursor(cursor)
            self._edit.ensureCursorVisible()

    def clear(self):
        self._edit.clear()
        self._line_count = 0
        self._line_lbl.setText("0 lines")

    def _copy_all(self):
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self._edit.toPlainText())
