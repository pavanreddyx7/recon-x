import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QCheckBox, QPushButton,
    QProgressBar, QFileDialog, QGroupBox, QGridLayout,
    QSizePolicy, QFrame, QSplitter
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from gui.widgets.log_console import LogConsole
from gui.worker import ScanWorker, STAGE_NAMES


class _StageRow(QWidget):
    def __init__(self, name: str, parent=None):
        super().__init__(parent)
        self._name = name
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 2, 0, 2)
        lay.setSpacing(8)

        self._status = QLabel("⏸")
        self._status.setFixedWidth(20)
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._status)

        short = name.split('·')[-1].strip()
        lbl = QLabel(short)
        lbl.setFixedWidth(180)
        lbl.setStyleSheet("color: #808090; font-size: 12px;")
        self._lbl = lbl
        lay.addWidget(lbl)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(10)
        lay.addWidget(self._bar, stretch=1)

        self._time = QLabel("")
        self._time.setFixedWidth(60)
        self._time.setStyleSheet("color: #606070; font-size: 11px;")
        self._time.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(self._time)

    def set_waiting(self):
        self._status.setText("⏸")
        self._status.setStyleSheet("color: #404050;")
        self._lbl.setStyleSheet("color: #606070; font-size: 12px;")
        self._bar.setValue(0)
        self._bar.setStyleSheet("")
        self._time.setText("")

    def set_running(self):
        self._status.setText("⟳")
        self._status.setStyleSheet("color: #ffcc00;")
        self._lbl.setStyleSheet("color: #ffcc00; font-size: 12px; font-weight: bold;")
        self._bar.setValue(50)
        self._bar.setStyleSheet(
            "QProgressBar::chunk { background-color: #ffcc00; }")

    def set_done(self, elapsed: float = 0.0):
        self._status.setText("✔")
        self._status.setStyleSheet("color: #00ff88;")
        self._lbl.setStyleSheet("color: #00ff88; font-size: 12px;")
        self._bar.setValue(100)
        self._bar.setStyleSheet(
            "QProgressBar::chunk { background-color: #00ff88; }")
        self._time.setText(f"{elapsed:.1f}s")

    def set_failed(self):
        self._status.setText("✗")
        self._status.setStyleSheet("color: #ff4444;")
        self._lbl.setStyleSheet("color: #ff4444; font-size: 12px;")
        self._bar.setValue(100)
        self._bar.setStyleSheet(
            "QProgressBar::chunk { background-color: #ff4444; }")


class ScanTab(QWidget):
    scan_finished = pyqtSignal(dict)

    def __init__(self, output_dir: str, parent=None):
        super().__init__(parent)
        self._output_dir = output_dir
        self._worker: ScanWorker | None = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        title = QLabel("New Scan")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #00ff88;")
        root.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Vertical)
        root.addWidget(splitter, stretch=1)

        # ── Top: config + progress ────────────────────────────────────────
        top_w = QWidget()
        top_lay = QVBoxLayout(top_w)
        top_lay.setContentsMargins(0, 0, 0, 0)
        top_lay.setSpacing(12)

        # Config group
        cfg_box = QGroupBox("Target Configuration")
        cfg_grid = QGridLayout(cfg_box)
        cfg_grid.setSpacing(8)

        cfg_grid.addWidget(QLabel("Target:"), 0, 0)
        self._target_inp = QLineEdit()
        self._target_inp.setPlaceholderText("IP, domain, CIDR, or URL…")
        cfg_grid.addWidget(self._target_inp, 0, 1, 1, 3)

        browse = QPushButton("From File")
        browse.setFixedWidth(90)
        browse.clicked.connect(self._browse_targets)
        cfg_grid.addWidget(browse, 0, 4)

        cfg_grid.addWidget(QLabel("Profile:"), 1, 0)
        self._profile = QComboBox()
        self._profile.addItems(["standard", "quick", "full", "stealth"])
        cfg_grid.addWidget(self._profile, 1, 1)

        cfg_grid.addWidget(QLabel("Ports:"), 1, 2)
        self._ports = QLineEdit()
        self._ports.setPlaceholderText("80,443,8080 or 1-1024")
        cfg_grid.addWidget(self._ports, 1, 3, 1, 2)

        cfg_grid.addWidget(QLabel("Proxy:"), 2, 0)
        self._proxy = QLineEdit()
        self._proxy.setPlaceholderText("http://127.0.0.1:8080")
        cfg_grid.addWidget(self._proxy, 2, 1, 1, 2)

        cfg_grid.addWidget(QLabel("Cookie:"), 2, 3)
        self._cookie = QLineEdit()
        self._cookie.setPlaceholderText("session=abc123")
        cfg_grid.addWidget(self._cookie, 2, 4)

        cfg_grid.addWidget(QLabel("Slack:"), 3, 0)
        self._slack = QLineEdit()
        self._slack.setPlaceholderText("https://hooks.slack.com/…")
        cfg_grid.addWidget(self._slack, 3, 1, 1, 4)

        # Checkboxes
        chk_row = QHBoxLayout()
        self._chk_passive = QCheckBox("Skip Passive Recon")
        self._chk_web     = QCheckBox("Skip Web Enumeration")
        self._chk_cve     = QCheckBox("Skip CVE Lookup")
        for c in (self._chk_passive, self._chk_web, self._chk_cve):
            chk_row.addWidget(c)
        chk_row.addStretch()
        cfg_grid.addLayout(chk_row, 4, 0, 1, 5)

        top_lay.addWidget(cfg_box)

        # Scan action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setObjectName("StartButton")
        self._start_btn.clicked.connect(self._start_scan)
        btn_row.addWidget(self._start_btn)

        self._stop_btn = QPushButton("■  Stop")
        self._stop_btn.setObjectName("StopButton")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_scan)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()

        self._status_lbl = QLabel("Ready")
        self._status_lbl.setStyleSheet("color: #808090; font-size: 12px;")
        btn_row.addWidget(self._status_lbl)
        top_lay.addLayout(btn_row)

        # Stage progress bars
        prog_box = QGroupBox("Pipeline Progress")
        prog_lay = QVBoxLayout(prog_box)
        prog_lay.setSpacing(4)

        self._stage_rows: list[_StageRow] = []
        for name in STAGE_NAMES:
            row = _StageRow(name)
            prog_lay.addWidget(row)
            self._stage_rows.append(row)

        # Overall progress
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #1a1a2e;")
        prog_lay.addWidget(sep)

        overall_row = QHBoxLayout()
        overall_row.addWidget(QLabel("Overall:"))
        self._overall_bar = QProgressBar()
        self._overall_bar.setRange(0, len(STAGE_NAMES))
        self._overall_bar.setValue(0)
        self._overall_bar.setFixedHeight(12)
        overall_row.addWidget(self._overall_bar)
        prog_lay.addLayout(overall_row)
        top_lay.addWidget(prog_box)

        splitter.addWidget(top_w)

        # ── Bottom: log console ───────────────────────────────────────────
        log_w = QWidget()
        log_lay = QVBoxLayout(log_w)
        log_lay.setContentsMargins(0, 0, 0, 0)

        log_title = QLabel("Live Output")
        log_title.setObjectName("SectionLabel")
        log_lay.addWidget(log_title)

        self._log = LogConsole()
        log_lay.addWidget(self._log)
        splitter.addWidget(log_w)

        splitter.setSizes([420, 300])

    def _browse_targets(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select targets file",
                                               "", "Text files (*.txt);;All (*)")
        if path:
            self._target_inp.setText(f"@{path}")

    def _reset_stages(self):
        for row in self._stage_rows:
            row.set_waiting()
        self._overall_bar.setValue(0)

    def start_scan_for_target(self, target: str):
        """Called externally (e.g. from Dashboard quick scan)."""
        self._target_inp.setText(target)
        self._start_scan()

    def _start_scan(self):
        target = self._target_inp.text().strip()
        if not target:
            self._status_lbl.setText("Enter a target first.")
            return
        if self._worker and self._worker.isRunning():
            return

        self._log.clear()
        self._reset_stages()
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._status_lbl.setText("Scanning…")
        self._status_lbl.setStyleSheet("color: #ffcc00;")

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
        self._status_lbl.setText("Stopped.")
        self._status_lbl.setStyleSheet("color: #ff4444;")
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

    def _on_stage_failed(self, name: str, err: str):
        for row, sname in zip(self._stage_rows, STAGE_NAMES):
            if sname == name:
                row.set_failed()
                break

    def _on_log(self, msg: str, level: str):
        self._log.append(msg, level)

    def _on_progress(self, idx: int, total: int):
        self._overall_bar.setValue(idx)

    def _on_scan_complete(self, data: dict):
        self._status_lbl.setText("Scan complete ✔")
        self._status_lbl.setStyleSheet("color: #00ff88;")
        # Mark all remaining stages done
        for row in self._stage_rows:
            if row._bar.value() < 100:
                row.set_done()
        self._overall_bar.setValue(len(STAGE_NAMES))
        self.scan_finished.emit(data)

    def _on_worker_finished(self):
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
