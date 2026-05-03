"""
Structured logger — Rich console (coloured, panel-based) + JSON file sink.
Singleton: import `log` and call log.info(), log.warn(), log.section(), etc.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme
from rich import box

# ── Rich theme ────────────────────────────────────────────────────────────────
_THEME = Theme({
    "info":     "bold green",
    "warn":     "bold yellow",
    "error":    "bold red",
    "success":  "bold cyan",
    "debug":    "dim white",
    "critical": "bold white on red",
    "section":  "bold cyan",
    "tag.ok":   "green",
    "tag.warn": "yellow",
    "tag.err":  "red",
    "tag.info": "cyan",
})

_console = Console(theme=_THEME, highlight=False)


# ── JSON file sink ────────────────────────────────────────────────────────────
def _make_file_handler(log_dir: str) -> RotatingFileHandler:
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(
        log_dir, f"r3conx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    h = RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(message)s"))   # raw JSON lines
    return h, path


# ── Core logger class ─────────────────────────────────────────────────────────
class _Logger:
    """Thread-safe, structured logger. One global instance exposed as `log`."""

    def __init__(self) -> None:
        self._lock       = threading.Lock()
        self._log_path   = ""
        self._py_logger  = logging.getLogger("r3conx")
        self._py_logger.setLevel(logging.DEBUG)
        self._verbose    = False

    def init(self, log_dir: str, verbose: bool = False) -> None:
        """Call once at startup with the output directory path."""
        with self._lock:
            self._verbose = verbose
            handler, self._log_path = _make_file_handler(log_dir)
            self._py_logger.addHandler(handler)

    @property
    def path(self) -> str:
        return self._log_path

    # ── internal ──────────────────────────────────────────────────────────────
    def _emit(self, level: str, msg: str, extra: dict[str, Any] | None = None) -> None:
        record = {
            "ts":    datetime.now(timezone.utc).isoformat(),
            "level": level,
            "msg":   msg,
        }
        if extra:
            record.update(extra)
        with self._lock:
            self._py_logger.info(json.dumps(record))

    # ── public API ─────────────────────────────────────────────────────────────
    def info(self, msg: str, **extra: Any) -> None:
        _console.print(f"[tag.ok]\\[+][/tag.ok] {msg}")
        self._emit("INFO", msg, extra or None)

    def warn(self, msg: str, **extra: Any) -> None:
        _console.print(f"[tag.warn]\\[!][/tag.warn] [warn]{msg}[/warn]")
        self._emit("WARN", msg, extra or None)

    def error(self, msg: str, **extra: Any) -> None:
        _console.print(f"[tag.err]\\[-][/tag.err] [error]{msg}[/error]")
        self._emit("ERROR", msg, extra or None)

    def success(self, msg: str, **extra: Any) -> None:
        _console.print(f"[success]\\[✔] {msg}[/success]")
        self._emit("SUCCESS", msg, extra or None)

    def debug(self, msg: str, **extra: Any) -> None:
        if self._verbose:
            _console.print(f"[debug]\\[D] {msg}[/debug]")
        self._emit("DEBUG", msg, extra or None)

    def critical(self, msg: str, **extra: Any) -> None:
        _console.print(f"[critical] CRITICAL: {msg} [/critical]")
        self._emit("CRITICAL", msg, extra or None)

    def section(self, title: str) -> None:
        """Print a prominent section divider."""
        _console.print()
        _console.print(Panel(
            Text(title, style="bold white", justify="center"),
            style="cyan",
            box=box.DOUBLE_EDGE,
            expand=True,
            padding=(0, 2),
        ))
        _console.print()
        self._emit("SECTION", title)

    def finding(self, label: str, value: str, severity: str = "") -> None:
        """Print a key-value finding with optional severity badge."""
        sev_colours = {
            "CRITICAL": "red", "HIGH": "magenta",
            "MEDIUM": "yellow", "LOW": "cyan", "": "white",
        }
        colour = sev_colours.get(severity.upper(), "white")
        badge  = f" [{colour}][{severity}][/{colour}]" if severity else ""
        _console.print(f"  [bold]{label}[/bold]{badge}: {value}")
        self._emit("FINDING", f"{label}: {value}", {"severity": severity} if severity else None)

    def table_row(self, *cols: str) -> None:
        parts = "  ".join(f"[dim]│[/dim] {c:<20}" for c in cols)
        _console.print(f"  {parts}")


# ── Singleton ─────────────────────────────────────────────────────────────────
log = _Logger()


# ── Convenience aliases (backward-compat for any module that imports directly) ─
def info(msg: str,    **kw: Any) -> None: log.info(msg,    **kw)
def warn(msg: str,    **kw: Any) -> None: log.warn(msg,    **kw)
def error(msg: str,   **kw: Any) -> None: log.error(msg,   **kw)
def success(msg: str, **kw: Any) -> None: log.success(msg, **kw)
def debug(msg: str,   **kw: Any) -> None: log.debug(msg,   **kw)
def section(title: str)          -> None: log.section(title)
def log_file_path()              -> str:  return log.path
