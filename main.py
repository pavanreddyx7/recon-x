"""
R3CON-X — Reconnaissance & Vulnerability Intelligence Framework
Entry point: orchestrates the 7-stage async-capable pipeline with
signal handling, rich progress tracking, and structured result store.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import time

# ── Path bootstrap (ensures packages are found under sudo) ───────────────────
def _bootstrap_path() -> None:
    _base = os.path.dirname(os.path.abspath(__file__))
    _candidates = [
        # venv inside the project directory
        os.path.join(_base, "venv", "lib",
                     f"python{sys.version_info.major}.{sys.version_info.minor}",
                     "site-packages"),
        # user local packages (~/.local/lib/...)
        os.path.join(os.path.expanduser("~"), ".local", "lib",
                     f"python{sys.version_info.major}.{sys.version_info.minor}",
                     "site-packages"),
        # original user's local packages when running under sudo
        os.path.join(os.path.expanduser(f"~{os.environ.get('SUDO_USER', '')}"),
                     ".local", "lib",
                     f"python{sys.version_info.major}.{sys.version_info.minor}",
                     "site-packages"),
    ]
    for path in _candidates:
        if os.path.isdir(path) and path not in sys.path:
            sys.path.insert(0, path)

_bootstrap_path()
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.progress import (
    BarColumn, Progress, SpinnerColumn,
    TaskProgressColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich import box

from utils.banner import print_banner
from utils.logger import log, section
from utils.validator import parse_target, probe_reachability, TargetKind
from utils.exceptions import R3ConXError, ValidationError
from config import cfg

_console = Console(highlight=False)

# ── Signal handling ───────────────────────────────────────────────────────────
_shutdown = False

def _handle_signal(_signum: int, _frame: Any) -> None:
    global _shutdown
    _shutdown = True
    _console.print("\n[bold yellow][!] Interrupt received — finishing current stage then stopping.[/bold yellow]")

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── Scan result store ─────────────────────────────────────────────────────────
@dataclass
class ScanResult:
    meta:            dict       = field(default_factory=dict)
    passive_recon:   dict       = field(default_factory=dict)
    active_scan:     dict       = field(default_factory=dict)
    web_enum:        dict       = field(default_factory=dict)
    vulnerabilities: list[dict] = field(default_factory=list)
    risk_summary:    dict       = field(default_factory=dict)
    stage_timings:   dict[str, float] = field(default_factory=dict)
    stage_errors:    dict[str, str]   = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ── CLI ───────────────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="r3conx",
        description="R3CON-X: Unified Reconnaissance & Vulnerability Intelligence Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 main.py -t scanme.nmap.org\n"
            "  python3 main.py -t 192.168.1.1 --profile full\n"
            "  python3 main.py -t 10.0.0.0/24 --profile quick\n"
            "  python3 main.py -t example.com --skip-cve -v\n"
        ),
    )
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("-t", "--target",  metavar="TARGET",
                     help="Single target: IPv4, IPv6, CIDR, domain, or URL")
    tgt.add_argument("-T", "--targets", metavar="FILE",
                     help="File with one target per line (multi-target batch scan)")
    p.add_argument("-o", "--output",   default=cfg.output_dir, metavar="DIR",
                   help=f"Output directory  (default: {cfg.output_dir})")
    p.add_argument("--ports",          default=None, metavar="RANGE",
                   help="Override port range  (e.g. 1-65535, 80,443,8080)")
    p.add_argument("--profile",        choices=list(cfg.profiles), default="standard",
                   help=(
                       "quick    — top-100 ports, no passive/web\n"
                       "standard — 1-1024, all modules  [default]\n"
                       "full     — 1-65535, all modules\n"
                       "stealth  — low-noise T2 scan"
                   ))
    p.add_argument("--skip-passive",   action="store_true", help="Skip passive reconnaissance")
    p.add_argument("--skip-web",       action="store_true", help="Skip web enumeration")
    p.add_argument("--skip-cve",       action="store_true", help="Skip CVE correlation (offline mode)")
    p.add_argument("--proxy",          default=None, metavar="URL",
                   help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080 for Burp)")
    p.add_argument("--auth-cookie",    default=None, metavar="COOKIE",
                   help="Session cookie for authenticated scans (e.g. 'session=abc123')")
    p.add_argument("--notify-slack",   default=None, metavar="WEBHOOK_URL",
                   help="Slack webhook URL — posts CRITICAL findings after scan")
    p.add_argument("--config",         default=None, metavar="FILE",
                   help="Path to custom config.yaml")
    p.add_argument("-v", "--verbose",  action="store_true", help="Enable verbose/debug output")
    return p


# ── Progress bar factory ──────────────────────────────────────────────────────
def _make_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots2"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=_console,
        transient=False,
    )


# ── Stage runner ──────────────────────────────────────────────────────────────
@contextmanager
def _stage(result: ScanResult, name: str, progress: Progress):
    """Context manager: section banner + progress task + timing + error capture."""
    section(name)
    task = progress.add_task(name, total=None)   # indeterminate spinner
    t0   = time.perf_counter()
    try:
        yield
        elapsed = round(time.perf_counter() - t0, 2)
        result.stage_timings[name] = elapsed
        progress.update(task, total=1, completed=1,
                        description=f"[green]{name}  ({elapsed}s)[/green]")
        log.success(f"{name} completed in {elapsed}s")
    except R3ConXError as exc:
        elapsed = round(time.perf_counter() - t0, 2)
        result.stage_timings[name] = elapsed
        result.stage_errors[name]  = str(exc)
        progress.update(task, description=f"[red]{name}  FAILED[/red]")
        log.error(f"{name} failed: {exc}")
    except Exception as exc:
        elapsed = round(time.perf_counter() - t0, 2)
        result.stage_timings[name] = elapsed
        result.stage_errors[name]  = str(exc)
        progress.update(task, description=f"[red]{name}  ERROR[/red]")
        log.error(f"Unexpected error in {name}: {exc}")


# ── Final summary table ───────────────────────────────────────────────────────
def _print_summary(result: ScanResult) -> None:
    section("SCAN COMPLETE — SUMMARY")

    counts  = result.risk_summary.get("counts", {})
    colours = {"CRITICAL":"red","HIGH":"magenta","MEDIUM":"yellow","LOW":"cyan","NONE":"white"}

    t = Table(box=box.ROUNDED, border_style="cyan", show_header=True, header_style="bold cyan")
    t.add_column("Metric",      style="bold white", no_wrap=True)
    t.add_column("Value",       style="white")

    t.add_row("Target",          result.meta.get("target","—"))
    t.add_row("IP Address",      result.meta.get("ip","—"))
    t.add_row("Profile",         result.meta.get("profile","—"))
    t.add_row("Open Ports",      str(result.active_scan.get("total_open", 0)))
    t.add_row("Vulnerabilities", str(len(result.vulnerabilities)))
    t.add_section()
    for level in cfg.SEVERITY_ORDER:
        n   = counts.get(level, 0)
        col = colours.get(level, "white")
        t.add_row(f"  {level}", f"[{col}]{n}[/{col}]")
    t.add_section()
    for stage, elapsed in result.stage_timings.items():
        err = result.stage_errors.get(stage, "")
        status = f"[red]FAILED — {err}[/red]" if err else f"[green]{elapsed}s[/green]"
        t.add_row(f"  {stage}", status)

    _console.print(t)
    log.success(f"Reports saved to: {result.meta.get('output_dir','output/')}")


# ── Slack notifier ────────────────────────────────────────────────────────────
def _notify_slack(webhook: str, result: ScanResult) -> None:
    """Post a summary of CRITICAL/HIGH findings to a Slack webhook."""
    counts  = result.risk_summary.get("counts", {})
    crits   = counts.get("CRITICAL", 0)
    highs   = counts.get("HIGH", 0)
    if crits == 0 and highs == 0:
        return
    try:
        import requests as _req
        lines = [
            f":rotating_light: *R3CON-X Alert* — `{result.meta.get('target')}`",
            f"CRITICAL: {crits}  |  HIGH: {highs}  |  Profile: {result.meta.get('profile')}",
        ]
        for v in result.vulnerabilities:
            if v.get("severity", "") in ("CRITICAL", "HIGH"):
                lines.append(f"  • `{v['cve_id']}` ({v['severity']}) — {v['description'][:80]}…")
        _req.post(webhook, json={"text": "\n".join(lines)}, timeout=10)
        log.success("Slack notification sent.")
    except Exception as e:
        log.warn(f"Slack notification failed: {e}")


# ── Web finding → vulnerability converter ────────────────────────────────────
_SEV_TO_SCORE: dict[str, float] = {
    "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5
}

def _web_enum_to_vulns(web: dict) -> list[dict]:
    """Convert web-enum findings into vulnerability records for Stage 6."""
    vulns: list[dict] = []
    port    = 443 if web.get("scheme") == "https" else 80
    service = web.get("scheme", "http")
    product = web.get("server", "Web Application") or "Web Application"

    def _make(vuln_id: str, desc: str, severity: str) -> dict:
        score  = _SEV_TO_SCORE.get(severity, 3.5)
        impact = "HIGH" if severity in ("CRITICAL", "HIGH") else "LOW"
        return {
            "cve_id":          vuln_id,
            "description":     desc[:500],
            "published":       "",
            "last_modified":   "",
            "score":           score,
            "severity":        severity,
            "cvss": {
                "version":                "3.1",
                "base_score":             score,
                "base_severity":          severity,
                "attack_vector":          "NETWORK",
                "attack_complexity":      "LOW",
                "privileges_required":    "NONE",
                "user_interaction":       "NONE",
                "scope":                  "UNCHANGED",
                "confidentiality_impact": impact,
                "integrity_impact":       impact,
                "availability_impact":    "NONE",
                "vector_string":          "",
                "exploitability_score":   0.0,
                "impact_score":           0.0,
            },
            "has_exploit":     False,
            "matched_port":    port,
            "matched_ports":   [port],
            "matched_service": service,
            "matched_product": product,
            "matched_version": "",
            "match_source":    "web_enum",
            "cwe":             [],
            "references":      [],
            "exploits":        [],
            "network_exploitable": True,
            "no_auth_required":    True,
        }

    # Missing / misconfigured security headers
    for h in web.get("headers", []):
        severity = h.get("severity", "")
        if not severity or h.get("present", True):
            continue
        hdr_key = h.get("header", "").lstrip("!").replace("-", "_").upper()
        vulns.append(_make(
            f"WEB-HDR-{hdr_key}",
            h.get("message", f"Missing header: {h.get('header','')}"),
            severity,
        ))

    # Dangerous HTTP methods
    for method in web.get("dangerous_methods", []):
        vulns.append(_make(
            f"WEB-METHOD-{method.upper()}",
            f"Dangerous HTTP method enabled: {method} — may allow server-side request forgery or cache poisoning.",
            "HIGH",
        ))

    # Cookie security issues
    seen_cookie_ids: set[str] = set()
    for cookie in web.get("cookies", []):
        name = cookie.get("name", "cookie")
        for issue in cookie.get("issues", []):
            vuln_id = f"WEB-COOKIE-{name.upper()}"
            if vuln_id not in seen_cookie_ids:
                vulns.append(_make(vuln_id, f"Cookie '{name}': {issue}", "MEDIUM"))
                seen_cookie_ids.add(vuln_id)

    # CORS misconfiguration
    cors = web.get("cors", {})
    cors_sev = cors.get("severity", "")
    if cors_sev and cors_sev not in ("INFO", ""):
        vulns.append(_make("WEB-CORS", cors.get("detail", "CORS misconfiguration detected."), cors_sev))

    # Nikto findings
    for i, finding in enumerate(web.get("nikto_findings", []), 1):
        vulns.append(_make(f"WEB-NIKTO-{i:03d}", finding, "MEDIUM"))

    return vulns


# ── Single-target scan pipeline ───────────────────────────────────────────────
def _scan_target(raw_target: str, args) -> ScanResult:
    """Run the full 7-stage pipeline for one target. Returns the ScanResult."""

    # ── STAGE 1 · Input Validation ────────────────────────────────────────────
    section("STAGE 1 · Input Validation")
    try:
        target = parse_target(raw_target)
    except ValidationError as exc:
        log.error(str(exc))
        return ScanResult(meta={"target": raw_target, "error": str(exc)})

    if target.kind is TargetKind.DOMAIN and not target.ip:
        log.error(f"DNS resolution failed for '{target.host}'. Aborting.")
        return ScanResult(meta={"target": raw_target, "error": "DNS failed"})

    profile_flags = cfg.profile_flags(args.profile)
    skip_passive  = args.skip_passive or profile_flags.get("skip_passive", False)
    skip_web      = args.skip_web     or profile_flags.get("skip_web",     False)
    skip_cve      = args.skip_cve
    port_range    = args.ports or profile_flags.get("port_range", cfg.network.port_range)

    log.info(f"Target  : [bold]{target.host}[/bold]  ({target.kind.name})")
    log.info(f"IP      : {target.ip or 'N/A (CIDR)'}")
    log.info(f"Profile : {args.profile}  |  Ports: {port_range}")
    log.info(f"Log     : {log.path}")

    ip_for_probe = target.ip or str(list(target.iter_hosts())[0])
    if not probe_reachability(ip_for_probe):
        log.warn("Host did not respond to probes — scan will proceed anyway.")

    result = ScanResult(meta={
        "target":      target.host,
        "ip":          target.ip,
        "target_kind": target.kind.name,
        "profile":     args.profile,
        "ports":       port_range,
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "output_dir":  args.output,
    })

    # Proxy / auth-cookie injected into shared env vars picked up by web_enum
    if args.proxy:
        os.environ["RECONX_PROXY"]       = args.proxy
        log.info(f"Proxy   : {args.proxy}")
    if args.auth_cookie:
        os.environ["RECONX_AUTH_COOKIE"] = args.auth_cookie
        log.info("Auth cookie set for web enumeration.")

    progress = _make_progress()

    with Live(progress, console=_console, refresh_per_second=10):

        if not skip_passive and not _shutdown:
            from modules.passive_recon import PassiveRecon
            with _stage(result, "STAGE 2 · Passive Reconnaissance", progress):
                result.passive_recon = PassiveRecon(target.host, target.ip).run()

        if not _shutdown:
            from modules.active_scan import ActiveScan
            with _stage(result, "STAGE 3 · Active Scanning", progress):
                result.active_scan = ActiveScan(
                    target.ip or ip_for_probe, port_range, args.profile
                ).run()

        if not skip_web and not _shutdown:
            from modules.web_enum import WebEnum
            with _stage(result, "STAGE 4 · Web Enumeration", progress):
                result.web_enum = WebEnum(target.host).run()

        if not skip_cve and not _shutdown:
            from modules.cve_engine import CVEEngine
            with _stage(result, "STAGE 5 · CVE Correlation", progress):
                result.vulnerabilities = CVEEngine(
                    result.active_scan, result.web_enum
                ).run()

        # Merge web-enum findings into vulnerabilities for Stage 6
        if not skip_web and result.web_enum and not _shutdown:
            web_vulns = _web_enum_to_vulns(result.web_enum)
            result.vulnerabilities.extend(web_vulns)
            if web_vulns:
                log.info(f"  Web findings added: {len(web_vulns)} vulnerability record(s)")

        if not _shutdown:
            from modules.risk_engine import RiskEngine
            with _stage(result, "STAGE 6 · Risk Analysis", progress):
                result.risk_summary = RiskEngine(result.vulnerabilities).run()

        if not _shutdown:
            from modules.report_gen import ReportGenerator
            with _stage(result, "STAGE 7 · Report Generation", progress):
                ReportGenerator(result.to_dict(), args.output).run()

    _print_summary(result)

    if args.notify_slack:
        _notify_slack(args.notify_slack, result)

    return result


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> int:
    print_banner()

    parser = _build_parser()
    args   = parser.parse_args()

    if args.config:
        from config import Config
        import config as _cfg_module
        loaded = Config.from_yaml(args.config)
        _cfg_module.cfg = loaded

    os.makedirs(args.output, exist_ok=True)
    log.init(args.output, verbose=args.verbose)

    # ── Build target list ─────────────────────────────────────────────────────
    if args.targets:
        try:
            with open(args.targets) as fh:
                targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            log.error(f"Cannot read targets file: {e}")
            return 1
        log.info(f"Batch mode: {len(targets)} target(s) from {args.targets}")
    else:
        targets = [args.target]

    exit_code = 0
    for i, raw in enumerate(targets, 1):
        if len(targets) > 1:
            section(f"TARGET {i}/{len(targets)} — {raw}")
        result = _scan_target(raw, args)
        if result.stage_errors:
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
