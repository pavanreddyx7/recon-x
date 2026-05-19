import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                              QPlainTextEdit, QPushButton, QCheckBox)
from PyQt6.QtGui import QTextCharFormat, QColor, QTextCursor, QFont
from PyQt6.QtCore import Qt
from gui.theme import LEVEL_COLORS


_RICH_TAG = re.compile(r'\[/?[a-zA-Z0-9_.# ]+\]')


def _strip_rich(text: str) -> str:
    return _RICH_TAG.sub('', text).strip()


class LogConsole(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._auto_scroll = True
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Toolbar
        bar = QHBoxLayout()
        bar.setSpacing(6)

        self._auto_cb = QCheckBox("Auto-scroll")
        self._auto_cb.setChecked(True)
        self._auto_cb.toggled.connect(self._on_autoscroll)
        bar.addWidget(self._auto_cb)
        bar.addStretch()

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
        self._edit.setMaximumBlockCount(4000)
        mono = QFont("JetBrains Mono", 11)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._edit.setFont(mono)
        layout.addWidget(self._edit)

    def _on_autoscroll(self, checked: bool):
        self._auto_scroll = checked

    def append(self, message: str, level: str = "info"):
        clean = _strip_rich(message)
        if not clean:
            return

        color = LEVEL_COLORS.get(level.lower(), "#e0e0e0")

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))

        cursor = self._edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(clean + "\n", fmt)

        if self._auto_scroll:
            self._edit.setTextCursor(cursor)
            self._edit.ensureCursorVisible()

    def clear(self):
        self._edit.clear()

    def _copy_all(self):
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self._edit.toPlainText())
