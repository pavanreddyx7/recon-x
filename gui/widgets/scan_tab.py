from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QCheckBox, QPushButton,
    QProgressBar, QFileDialog, QGroupBox, QGridLayout,
    QFrame, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from gui.widgets.log_console import LogConsole
from gui.worker import ScanWorker, STAGE_NAMES

_STAGE_ICONS  = ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
_STAGE_COLORS = {
    "waiting": ("#1a2e45", "#3d5470"),
    "running": ("#f59e0b", "#f59e0b"),
    "done":    ("#00ff88", "#00c96e"),
    "failed":  ("#ff4757", "#ff4757"),
}


class _StageRow(QWidget):
    def __init__(self, name: str, idx: int, parent=None):
        super().__init__(parent)
        self._name = name
        self._idx  = idx
        self.setMinimumHeight(36)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 4, 8, 4)
        lay.setSpacing(12)

        # Numbered badge
        self._badge = QLabel(_STAGE_ICONS[idx])
        self._badge.setFixedSize(26, 26)
        self._badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._badge.setStyleSheet(
            "color: #1a2e45; font-size: 16px; background: transparent;")
        lay.addWidget(self._badge)

        # Stage name
        short = name.split("·")[-1].strip()
        self._lbl = QLabel(short)
        self._lbl.setMinimumWidth(170)
        self._lbl.setStyleSheet("color: #3d5470; font-size: 13px;")
        lay.addWidget(self._lbl)

        # Progress bar
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(6)
        self._bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        lay.addWidget(self._bar, stretch=1)

        # Time label
        self._time = QLabel("")
        self._time.setFixedWidth(56)
        self._time.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._time.setStyleSheet("color: #243550; font-size: 11px; font-family: monospace;")
        lay.addWidget(self._time)

        # Status icon
        self._status = QLabel("–")
        self._status.setFixedWidth(20)
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status.setStyleSheet("color: #1a2e45; font-size: 14px;")
        lay.addWidget(self._status)

    def set_waiting(self):
        self._badge.setStyleSheet("color: #1a2e45; font-size: 16px; background: transparent;")
        self._lbl.setStyleSheet("color: #3d5470; font-size: 13px; font-weight: 400;")
        self._bar.setValue(0)
        self._bar.setStyleSheet("")
        self._time.setText("")
        self._status.setText("–")
        self._status.setStyleSheet("color: #1a2e45; font-size: 14px;")

    def set_running(self):
        self._badge.setStyleSheet("color: #f59e0b; font-size: 16px; background: transparent;")
        self._lbl.setStyleSheet("color: #f59e0b; font-size: 13px; font-weight: 600;")
        self._bar.setValue(50)
        self._bar.setStyleSheet(
            "QProgressBar::chunk { background: qlineargradient("
            "x1:0,y1:0,x2:1,y2:0,stop:0 #f59e0b,stop:1 #ff7b2d); }")
        self._status.setText("⟳")
        self._status.setStyleSheet("color: #f59e0b; font-size: 14px;")

    def set_done(self, elapsed: float = 0.0):
        self._badge.setStyleSheet("color: #00ff88; font-size: 16px; background: transparent;")
        self._lbl.setStyleSheet("color: #00c96e; font-size: 13px; font-weight: 500;")
        self._bar.setValue(100)
        self._bar.setStyleSheet(
            "QProgressBar::chunk { background: qlineargradient("
            "x1:0,y1:0,x2:1,y2:0,stop:0 #00ff88,stop:1 #00b8d4); }")
        self._time.setText(f"{elapsed:.1f}s")
        self._time.setStyleSheet("color: #00c96e; font-size: 11px; font-family: monospace;")
        self._status.setText("✔")
        self._status.setStyleSheet("color: #00ff88; font-size: 14px;")

    def set_failed(self):
        self._badge.setStyleSheet("color: #ff4757; font-size: 16px; background: transparent;")
        self._lbl.setStyleSheet("color: #ff4757; font-size: 13px; font-weight: 500;")
        self._bar.setValue(100)
        self._bar.setStyleSheet(
            "QProgressBar::chunk { background-color: #ff4757; }")
        self._status.setText("✗")
        self._status.setStyleSheet("color: #ff4757; font-size: 14px;")


class ScanTab(QWidget):
    scan_finished = pyqtSignal(dict)

    def __init__(self, output_dir: str, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._worker: ScanWorker | None = None
        self._build_ui()

    def _build_ui(self):
        # Outer layout: page header + two-column body
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Page header bar ────────────────────────────────────────────────
        header_bar = QWidget()
        header_bar.setStyleSheet("background-color: #080e1c; border-bottom: 1px solid #1a2e45;")
        header_bar.setFixedHeight(70)
        hb_lay = QHBoxLayout(header_bar)
        hb_lay.setContentsMargins(28, 14, 28, 14)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        t = QLabel("New Scan")
        t.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        t.setStyleSheet("color: #cbd5e1; background: transparent;")
        title_col.addWidget(t)
        s = QLabel("Configure target and pipeline options, then launch")
        s.setStyleSheet("color: #3d5470; font-size: 12px; background: transparent;")
        title_col.addWidget(s)
        hb_lay.addLayout(title_col)
        hb_lay.addStretch()

        self._status_lbl = QLabel("Ready to scan")
        self._status_lbl.setStyleSheet(
            "color: #3d5470; font-size: 13px; background: transparent;")
        hb_lay.addWidget(self._status_lbl)
        outer.addWidget(header_bar)

        # ── Main body: left config | right pipeline ────────────────────────
        body = QWidget()
        body_lay = QHBoxLayout(body)
        body_lay.setContentsMargins(0, 0, 0, 0)
        body_lay.setSpacing(0)
        outer.addWidget(body, stretch=1)

        # ── LEFT PANEL: scrollable config ─────────────────────────────────
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.Shape.NoFrame)
        left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        left_scroll.setMinimumWidth(480)
        left_scroll.setMaximumWidth(620)

        left_w = QWidget()
        left_lay = QVBoxLayout(left_w)
        left_lay.setContentsMargins(24, 24, 24, 24)
        left_lay.setSpacing(18)

        # Target
        target_box = QGroupBox("TARGET")
        tb_lay = QVBoxLayout(target_box)
        tb_lay.setSpacing(8)

        self._target_inp = QLineEdit()
        self._target_inp.setPlaceholderText(
            "IP address, hostname, CIDR (10.0.0.0/24), or URL…")
        self._target_inp.setMinimumHeight(42)
        tb_lay.addWidget(self._target_inp)

        file_row = QHBoxLayout()
        browse = QPushButton("Load from File…")
        browse.clicked.connect(self._browse_targets)
        file_row.addWidget(browse)
        file_row.addStretch()
        tb_lay.addLayout(file_row)
        left_lay.addWidget(target_box)

        # Scan options
        opts_box = QGroupBox("SCAN OPTIONS")
        og = QGridLayout(opts_box)
        og.setSpacing(12)
        og.setHorizontalSpacing(20)

        og.addWidget(_lbl("Profile"), 0, 0)
        self._profile = QComboBox()
        self._profile.addItems(["standard", "quick", "full", "stealth"])
        og.addWidget(self._profile, 0, 1)

        og.addWidget(_lbl("Port Range"), 1, 0)
        self._ports = QLineEdit()
        self._ports.setPlaceholderText("e.g. 80,443,8080  or  1-65535")
        og.addWidget(self._ports, 1, 1)

        og.addWidget(_lbl("HTTP Proxy"), 2, 0)
        self._proxy = QLineEdit()
        self._proxy.setPlaceholderText("http://127.0.0.1:8080")
        og.addWidget(self._proxy, 2, 1)

        og.addWidget(_lbl("Auth Cookie"), 3, 0)
        self._cookie = QLineEdit()
        self._cookie.setPlaceholderText("session=abc123…")
        og.addWidget(self._cookie, 3, 1)

        og.addWidget(_lbl("Slack Webhook"), 4, 0)
        self._slack = QLineEdit()
        self._slack.setPlaceholderText("https://hooks.slack.com/services/…")
        og.addWidget(self._slack, 4, 1)

        left_lay.addWidget(opts_box)

        # Skip options
        skip_box = QGroupBox("SKIP OPTIONS")
        sk_lay = QVBoxLayout(skip_box)
        sk_lay.setSpacing(10)
        self._chk_passive = _chk("Skip Passive Reconnaissance")
        self._chk_web     = _chk("Skip Web Enumeration")
        self._chk_cve     = _chk("Skip CVE Lookup")
        for c in (self._chk_passive, self._chk_web, self._chk_cve):
            sk_lay.addWidget(c)
        left_lay.addWidget(skip_box)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self._start_btn = QPushButton("▶   Start Scan")
        self._start_btn.setObjectName("StartButton")
        self._start_btn.setMinimumHeight(44)
        self._start_btn.clicked.connect(self._start_scan)
        btn_row.addWidget(self._start_btn)

        self._stop_btn = QPushButton("■   Stop")
        self._stop_btn.setObjectName("StopButton")
        self._stop_btn.setEnabled(False)
        self._stop_btn.setMinimumHeight(44)
        self._stop_btn.clicked.connect(self._stop_scan)
        btn_row.addWidget(self._stop_btn)
        left_lay.addLayout(btn_row)

        left_lay.addStretch()
        left_scroll.setWidget(left_w)
        body_lay.addWidget(left_scroll)

        # Vertical divider
        vdiv = QFrame()
        vdiv.setFrameShape(QFrame.Shape.VLine)
        vdiv.setStyleSheet("background-color: #1a2e45; max-width: 1px; border: none;")
        body_lay.addWidget(vdiv)

        # ── RIGHT PANEL: pipeline + log ────────────────────────────────────
        right_w = QWidget()
        right_lay = QVBoxLayout(right_w)
        right_lay.setContentsMargins(24, 24, 24, 24)
        right_lay.setSpacing(18)

        # Pipeline stages
        pipe_label = QLabel("PIPELINE STAGES")
        pipe_label.setObjectName("SectionLabel")
        right_lay.addWidget(pipe_label)

        stages_widget = QWidget()
        stages_widget.setObjectName("Card")
        stages_widget.setStyleSheet(
            "#Card { background-color: #0f1929; border: 1px solid #1a2e45;"
            " border-radius: 10px; }")
        stages_lay = QVBoxLayout(stages_widget)
        stages_lay.setContentsMargins(12, 12, 12, 12)
        stages_lay.setSpacing(2)

        self._stage_rows: list[_StageRow] = []
        for idx, name in enumerate(STAGE_NAMES):
            row = _StageRow(name, idx)
            stages_lay.addWidget(row)
            self._stage_rows.append(row)

            if idx < len(STAGE_NAMES) - 1:
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.HLine)
                sep.setStyleSheet(
                    "background-color: #142035; max-height: 1px; border: none;")
                stages_lay.addWidget(sep)

        right_lay.addWidget(stages_widget)

        # Overall progress
        ovr_row = QHBoxLayout()
        ovr_row.setSpacing(12)
        ovr_lbl = QLabel("Overall Progress")
        ovr_lbl.setStyleSheet("color: #3d5470; font-size: 12px;")
        ovr_row.addWidget(ovr_lbl)
        self._overall_bar = QProgressBar()
        self._overall_bar.setRange(0, len(STAGE_NAMES))
        self._overall_bar.setValue(0)
        self._overall_bar.setFixedHeight(8)
        ovr_row.addWidget(self._overall_bar)
        right_lay.addLayout(ovr_row)

        # Live output
        log_label = QLabel("LIVE OUTPUT")
        log_label.setObjectName("SectionLabel")
        right_lay.addWidget(log_label)

        self._log = LogConsole()
        right_lay.addWidget(self._log, stretch=1)

        body_lay.addWidget(right_w, stretch=1)

    # ── Helpers ───────────────────────────────────────────────────────────
    def _browse_targets(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select targets file", "", "Text files (*.txt);;All (*)")
        if path:
            self._target_inp.setText(f"@{path}")

    def _reset_stages(self):
        for row in self._stage_rows:
            row.set_waiting()
        self._overall_bar.setValue(0)

    def start_scan_for_target(self, target: str):
        self._target_inp.setText(target)
        self._start_scan()

    def _start_scan(self):
        target = self._target_inp.text().strip()
        if not target:
            self._status_lbl.setText("⚠  Enter a target first.")
            self._status_lbl.setStyleSheet("color: #ff7b2d; font-size: 13px; background: transparent;")
            return
        if self._worker and self._worker.isRunning():
            return

        self._log.clear()
        self._reset_stages()
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._status_lbl.setText("Scanning…")
        self._status_lbl.setStyleSheet("color: #f59e0b; font-size: 13px; background: transparent;")

        scan_args = {
            "output":       self._output_dir,
            "ports":        self._ports.text().strip() or None,
            "profile":      self._profile.currentText(),
            "skip_passive": self._chk_passive.isChecked(),
            "skip_web":     self._chk_web.isChecked(),
            "skip_cve":     self._chk_cve.isChecked(),
            "proxy":        self._proxy.text().strip() or None,
            "auth_cookie":  self._cookie.text().strip() or None,
            "notify_slack": self._slack.text().strip() or None,
        }

        self._worker = ScanWorker(target, scan_args)
        self._worker.stage_started.connect(self._on_stage_started)
        self._worker.stage_done.connect(self._on_stage_done)
        self._worker.stage_failed.connect(self._on_stage_failed)
        self._worker.log_line.connect(self._on_log)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.progress_update.connect(self._on_progress)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def _stop_scan(self):
        if self._worker:
            self._worker.stop()
            self._worker.terminate()
        self._status_lbl.setText("Stopped")
        self._status_lbl.setStyleSheet("color: #ff4757; font-size: 13px; background: transparent;")
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)

    def _on_stage_started(self, name: str):
        for row, sname in zip(self._stage_rows, STAGE_NAMES):
            if sname == name:
                row.set_running()
                break

    def _on_stage_done(self, name: str, elapsed: float):
        for row, sname in zip(self._stage_rows, STAGE_NAMES):
            if sname == name:
                row.set_done(elapsed)
                break

    def _on_stage_failed(self, name: str, _err: str = ""):
        for row, sname in zip(self._stage_rows, STAGE_NAMES):
            if sname == name:
                row.set_failed()
                break

    def _on_log(self, msg: str, level: str):
        self._log.append(msg, level)

    def _on_progress(self, idx: int, _total: int):
        self._overall_bar.setValue(idx)

    def _on_scan_complete(self, data: dict):
        self._status_lbl.setText("Scan complete  ✔")
        self._status_lbl.setStyleSheet("color: #00ff88; font-size: 13px; background: transparent;")
        for row in self._stage_rows:
            if row._bar.value() < 100:
                row.set_done()
        self._overall_bar.setValue(len(STAGE_NAMES))
        self.scan_finished.emit(data)

    def _on_worker_finished(self):
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)


def _lbl(text: str) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet("color: #4b5e7a; font-size: 13px; font-weight: 600;")
    return l


def _chk(text: str) -> QCheckBox:
    c = QCheckBox(text)
    c.setStyleSheet("color: #8fadc8; font-size: 13px; spacing: 10px;")
    return c
