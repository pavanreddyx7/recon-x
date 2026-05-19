import math
from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen, QFont, QConicalGradient


class GaugeWidget(QWidget):
    """Circular arc gauge. value range is 0..max_val."""

    def __init__(self, max_val: float = 100, label: str = "",
                 unit: str = "", parent=None):
        super().__init__(parent)
        self._value   = 0.0
        self._max     = max_val
        self._label   = label
        self._unit    = unit
        self.setMinimumSize(140, 140)

    def setValue(self, v: float) -> None:
        self._value = max(0.0, min(float(v), self._max))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h   = self.width(), self.height()
        size   = min(w, h) - 20
        x      = (w - size) / 2
        y      = (h - size) / 2
        rect   = QRectF(x, y, size, size)
        ratio  = self._value / self._max if self._max else 0

        # Color based on ratio
        if ratio >= 0.8:
            arc_color = QColor("#ff4444")
        elif ratio >= 0.6:
            arc_color = QColor("#ff8800")
        elif ratio >= 0.4:
            arc_color = QColor("#ffcc00")
        else:
            arc_color = QColor("#00ff88")

        # Background arc
        bg_pen = QPen(QColor("#1a1a2e"), 10, Qt.PenStyle.SolidLine,
                      Qt.PenCapStyle.RoundCap)
        p.setPen(bg_pen)
        p.drawArc(rect, 225 * 16, -270 * 16)

        # Value arc
        if ratio > 0:
            fg_pen = QPen(arc_color, 10, Qt.PenStyle.SolidLine,
                          Qt.PenCapStyle.RoundCap)
            p.setPen(fg_pen)
            span = int(-270 * 16 * ratio)
            p.drawArc(rect, 225 * 16, span)

        # Center value text
        p.setPen(QPen(arc_color))
        vfont = QFont("Consolas", int(size * 0.18), QFont.Weight.Bold)
        p.setFont(vfont)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter,
                   f"{self._value:.0f}{self._unit}")

        # Label below center
        if self._label:
            p.setPen(QPen(QColor("#808090")))
            lfont = QFont("Segoe UI", int(size * 0.09))
            p.setFont(lfont)
            label_rect = QRectF(x, y + size * 0.58, size, size * 0.2)
            p.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, self._label)

        p.end()
