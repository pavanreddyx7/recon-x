"""
ScanWorker — runs the R3CON-X pipeline in a QThread.
Intercepts utils.logger.log to emit Qt signals for live UI updates.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import traceback

from PyQt6.QtCore import QThread, pyqtSignal

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_STRIP_RICH = re.compile(r'\[/?[a-zA-Z0-9_.# ]+\]')


def _clean(msg: str) -> str:
    return _STRIP_RICH.sub('', str(msg)).strip()


STAGE_NAMES = [
    "STAGE 1 · Input Validation",
    "STAGE 2 · Passive Reconnaissance",
    "STAGE 3 · Active Scanning",
    "STAGE 4 · Web Enumeration",
    "STAGE 5 · CVE Correlation",
    "STAGE 6 · Risk Analysis",
    "STAGE 7 · Report Generation",
]


class ScanWorker(QThread):
    stage_started   = pyqtSignal(str)
    stage_done      = pyqtSignal(str, float)
    stage_failed    = pyqtSignal(str, str)
    log_line        = pyqtSignal(str, str)   # message, level
    scan_complete   = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)   # stage_idx, total

    def __init__(self, target: str, scan_args: dict):
        super().__init__()
        self._target    = target
        self._scan_args = scan_args
        self._abort     = False

    def stop(self):
        self._abort = True

    # ── Build fake argparse.Namespace ────────────────────────────────────────
    def _build_args(self) -> argparse.Namespace:
        from config import cfg
        a = argparse.Namespace()
        d = self._scan_args
        a.target       = self._target
        a.targets      = None
        a.output       = d.get("output") or cfg.output_dir
        a.ports        = d.get("ports") or None
        a.profile      = d.get("profile", "standard")
        a.skip_passive = bool(d.get("skip_passive", False))
        a.skip_web     = bool(d.get("skip_web", False))
        a.skip_cve     = bool(d.get("skip_cve", False))
        a.proxy        = d.get("proxy") or None
        a.auth_cookie  = d.get("auth_cookie") or None
        a.notify_slack = d.get("notify_slack") or None
        a.config       = None
        a.verbose      = bool(d.get("verbose", False))
        return a

    # ── Logger interception ──────────────────────────────────────────────────
    def _patch_logger(self):
        import utils.logger as _lmod
        original = _lmod.log
        sig      = self.log_line

        class _Interceptor:
            path = getattr(original, '_log_path', '')

            def _log(self, msg, level):
                sig.emit(_clean(msg), level)
                # also write to original file sink
                getattr(original, '_emit', lambda *a: None)(level.upper(), _clean(msg))

            def info(self, msg, **_):    self._log(msg, "info")
            def warn(self, msg, **_):    self._log(msg, "warn")
            def warning(self, msg, **_): self._log(msg, "warn")
            def error(self, msg, **_):   self._log(msg, "error")
            def success(self, msg, **_): self._log(msg, "success")
            def debug(self, msg, **_):   self._log(msg, "debug")
            def critical(self, msg, **_):self._log(msg, "error")
            def finding(self, label, value, severity="", **_):
                self._log(f"{label}: {value}", "info")
            def table_row(self, *cols):  pass
            def section(self, title):
                sig.emit(f"━━ {_clean(title)} ━━", "section")
            def init(self, *a, **kw):    original.init(*a, **kw)

        interceptor = _Interceptor()
        _lmod.log = interceptor
        return original, _lmod

    def _restore_logger(self, original, mod):
        mod.log = original

    # ── Stage tracking via success messages ─────────────────────────────────
    def _make_stage_tracker(self):
        """Returns a callable that wraps log.success to detect stage completion."""
        _sig_done   = self.stage_done
        _sig_update = self.progress_update
        _total      = len(STAGE_NAMES)

        def _on_success(msg: str):
            clean = _clean(msg)
            for idx, name in enumerate(STAGE_NAMES):
                short = name.split('·')[-1].strip().lower()
                if short in clean.lower() and "completed in" in clean.lower():
                    try:
                        elapsed = float(re.search(r'([\d.]+)s', clean).group(1))
                    except Exception:
                        elapsed = 0.0
                    _sig_done.emit(name, elapsed)
                    _sig_update.emit(idx + 1, _total)
                    break
        return _on_success

    # ── Intercept section() to emit stage_started ────────────────────────────
    def _patch_section(self, interceptor):
        """Monkey-patch section() on the interceptor to also fire stage_started."""
        _sig  = self.stage_started
        _orig = interceptor.section

        def _section(title):
            clean = _clean(title)
            for name in STAGE_NAMES:
                if name.lower() in clean.lower() or clean.lower() in name.lower():
                    _sig.emit(name)
                    break
            _orig(title)

        interceptor.section = _section

    # ── Main run ─────────────────────────────────────────────────────────────
    def run(self):
        try:
            import main as _main

            orig_log, log_mod = self._patch_logger()
            interceptor       = log_mod.log
            self._patch_section(interceptor)

            on_success = self._make_stage_tracker()
            _orig_success = interceptor.success

            def _wrapped_success(msg, **kw):
                _orig_success(msg, **kw)
                on_success(msg)

            interceptor.success = _wrapped_success

            # Suppress Rich console output during GUI scan
            import io
            from rich.console import Console
            _null = Console(file=io.StringIO(), highlight=False)
            import utils.logger as _lmod
            _orig_console = _lmod._console
            _lmod._console = _null

            try:
                args   = self._build_args()
                result = _main._scan_target(self._target, args)
                if result is not None:
                    self.scan_complete.emit(
                        result.to_dict() if hasattr(result, 'to_dict') else {}
                    )
            finally:
                _lmod._console = _orig_console
                self._restore_logger(orig_log, log_mod)

        except Exception as exc:
            self.log_line.emit(f"Worker error: {exc}", "error")
            self.log_line.emit(traceback.format_exc(), "debug")
