"""
Stage 3 — Active Scanning
Two-phase approach:
  Phase 1  · Fast concurrent TCP-connect sweep → discover open ports
  Phase 2  · Nmap service/version/OS detection on open ports only
  Phase 3  · Protocol-aware banner grabbing on every open port
"""
from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from enum import Enum, auto

import nmap
from rich.console import Console
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich import box

from utils.logger import log
from utils.decorators import retry
from utils.exceptions import PortScanError
from config import cfg

_console = Console(highlight=False)


# ── Data models ───────────────────────────────────────────────────────────────
class PortState(Enum):
    OPEN      = auto()
    CLOSED    = auto()
    FILTERED  = auto()
    UNKNOWN   = auto()


@dataclass
class PortResult:
    port:       int
    protocol:   str          = "tcp"
    state:      PortState    = PortState.UNKNOWN
    service:    str          = ""
    product:    str          = ""
    version:    str          = ""
    extra_info: str          = ""
    cpe:        list[str]    = field(default_factory=list)
    banner:     str          = ""
    os_guess:   str          = ""
    confidence: int          = 0      # Nmap confidence 0-10
    tunnel:     str          = ""     # ssl / http etc.
    script_out: dict         = field(default_factory=dict)

    # Derived helpers
    @property
    def service_string(self) -> str:
        parts = [p for p in [self.product, self.version, self.extra_info] if p]
        return f"{self.service}  {' '.join(parts)}".strip()

    @property
    def is_web(self) -> bool:
        return self.service in {"http", "https", "http-alt", "ssl/http"} or self.port in {80, 443, 8080, 8443, 8000, 3000}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.name
        return d


@dataclass
class OSGuess:
    name:       str
    accuracy:   int
    os_family:  str = ""
    os_gen:     str = ""
    cpe:        str = ""


@dataclass
class ScanReport:
    ip:          str
    hostname:    str             = ""
    mac:         str             = ""
    vendor:      str             = ""
    ports:       list[PortResult] = field(default_factory=list)
    os_guesses:  list[OSGuess]   = field(default_factory=list)
    total_open:  int             = 0
    scan_time:   float           = 0.0
    nmap_version: str            = ""

    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state is PortState.OPEN]

    def web_ports(self) -> list[PortResult]:
        return [p for p in self.open_ports() if p.is_web]

    def to_dict(self) -> dict:
        return {
            "ip":          self.ip,
            "hostname":    self.hostname,
            "mac":         self.mac,
            "vendor":      self.vendor,
            "os_guesses":  [asdict(o) for o in self.os_guesses],
            "open_ports":  [p.to_dict() for p in self.open_ports()],
            "total_open":  self.total_open,
            "scan_time":   self.scan_time,
            "nmap_version": self.nmap_version,
        }


# ── Protocol-specific banner probes ──────────────────────────────────────────
_PROBES: dict[int, bytes] = {
    21:   b"",                                    # FTP — server sends first
    22:   b"",                                    # SSH — server sends first
    23:   b"",                                    # Telnet — server sends first
    25:   b"EHLO r3conx\r\n",                     # SMTP
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:  b"",                                    # POP3 — server sends first
    143:  b"",                                    # IMAP — server sends first
    443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    445:  b"\x00\x00\x00\x85\xff\x53\x4d\x42",   # SMB negotiate
    3306: b"",                                    # MySQL — server sends first
    5432: b"",                                    # PostgreSQL — server sends first
    6379: b"*1\r\n$4\r\nPING\r\n",               # Redis
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    27017:b"",                                    # MongoDB — server sends first
}

_DEFAULT_PROBE = b"\r\n"


class BannerGrabber:
    """Attempts a protocol-appropriate probe and returns the decoded banner."""

    def __init__(self, timeout: float = cfg.network.timeout):
        self.timeout = timeout

    @retry(max_attempts=2, delay=0.5, exceptions=(OSError, TimeoutError))
    def grab(self, ip: str, port: int) -> str:
        probe = _PROBES.get(port, _DEFAULT_PROBE)
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                if probe:
                    s.sendall(probe)
                raw = b""
                deadline = time.monotonic() + self.timeout
                while time.monotonic() < deadline:
                    try:
                        chunk = s.recv(cfg.network.banner_bytes)
                        if not chunk:
                            break
                        raw += chunk
                        if len(raw) >= cfg.network.banner_bytes:
                            break
                    except socket.timeout:
                        break
                return raw.decode("utf-8", errors="replace").strip()[:512]
        except (OSError, TimeoutError):
            return ""
        except Exception:
            return ""


# ── Phase 1: Fast TCP-connect sweep ──────────────────────────────────────────
class TCPConnectScanner:
    """
    Concurrent TCP-connect scan — much faster than Nmap for discovery.
    Returns the set of open port numbers.
    """

    def __init__(self, ip: str, ports: list[int], threads: int = cfg.network.max_threads):
        self.ip      = ip
        self.ports   = ports
        self.threads = threads
        self._lock   = threading.Lock()
        self._open: set[int] = set()

    def _probe(self, port: int) -> None:
        try:
            with socket.create_connection((self.ip, port), timeout=cfg.network.timeout):
                with self._lock:
                    self._open.add(port)
        except (OSError, TimeoutError):
            pass

    def scan(self, progress: Progress | None = None) -> set[int]:
        task = None
        if progress:
            task = progress.add_task(
                f"  [cyan]TCP sweep[/cyan] → {self.ip}",
                total=len(self.ports),
            )
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe, p): p for p in self.ports}
            for f in as_completed(futures):
                f.result()
                if progress and task is not None:
                    progress.advance(task)

        if progress and task is not None:
            progress.update(task, description=f"  [green]TCP sweep done — {len(self._open)} open[/green]")

        return self._open


# ── Phase 2: Nmap service detection ──────────────────────────────────────────
class NmapServiceScanner:
    """
    Runs Nmap -sV (service/version) + -O (OS) + -sC (default scripts)
    only against ports confirmed open by Phase 1.
    Parses the full XML result into PortResult objects.
    """

    # Nmap timing/flag sets per profile
    # -Pn: skip host discovery (assume up — TCP sweep already confirmed reachable ports)
    NMAP_FLAGS = {
        "quick":    "-Pn -sV -T4 --open --version-intensity 3",
        "standard": "-Pn -sV -sC -T4 --open --version-intensity 5",
        "full":     "-Pn -sV -sC -O -T4 --open --version-intensity 9",
        "stealth":  "-Pn -sS -sV -T2 --open --version-intensity 4 --data-length 15",
    }

    def __init__(self, ip: str, open_ports: set[int], profile: str = "standard"):
        self.ip         = ip
        self.open_ports = open_ports
        self.profile    = profile
        self._nm        = nmap.PortScanner()

    def scan(self) -> ScanReport:
        if not self.open_ports:
            log.warn("No open ports discovered — skipping Nmap service detection.")
            return ScanReport(ip=self.ip)

        port_str = ",".join(str(p) for p in sorted(self.open_ports))
        flags    = self.NMAP_FLAGS.get(self.profile, self.NMAP_FLAGS["standard"])

        log.info(f"Nmap service scan: {self.ip}  ports={port_str}  flags={flags}")
        try:
            self._nm.scan(hosts=self.ip, ports=port_str, arguments=flags)
        except nmap.PortScannerError as e:
            raise PortScanError(f"Nmap failed: {e}", detail=str(e))

        return self._parse()

    def _parse(self) -> ScanReport:
        report = ScanReport(
            ip=self.ip,
            nmap_version=self._nm.nmap_version(),
        )

        if self.ip not in self._nm.all_hosts():
            log.warn(f"Nmap returned no data for {self.ip}")
            return report

        host_data = self._nm[self.ip]

        # ── hostname ──────────────────────────────────────────────────────────
        hostnames = host_data.get("hostnames", [])
        if hostnames:
            report.hostname = hostnames[0].get("name", "")

        # ── MAC / vendor ──────────────────────────────────────────────────────
        addresses = host_data.get("addresses", {})
        report.mac    = addresses.get("mac", "")
        vendor_dict   = host_data.get("vendor", {})
        report.vendor = vendor_dict.get(report.mac, "") if report.mac else ""

        # ── OS detection ──────────────────────────────────────────────────────
        for match in host_data.get("osmatch", []):
            classes = match.get("osclass", [{}])
            cls     = classes[0] if classes else {}
            report.os_guesses.append(OSGuess(
                name      = match.get("name", ""),
                accuracy  = int(match.get("accuracy", 0)),
                os_family = cls.get("osfamily", ""),
                os_gen    = cls.get("osgen", ""),
                cpe       = cls.get("cpe", [""])[0] if cls.get("cpe") else "",
            ))

        # ── Ports ─────────────────────────────────────────────────────────────
        for proto in host_data.all_protocols():
            for port_num in sorted(host_data[proto]):
                p_data  = host_data[proto][port_num]
                state   = _parse_state(p_data.get("state", "unknown"))
                scripts = {k: v for k, v in p_data.get("script", {}).items()}

                cpe_raw = p_data.get("cpe", "")
                cpes    = [c.strip() for c in cpe_raw.split("\n") if c.strip()] if cpe_raw else []

                pr = PortResult(
                    port       = port_num,
                    protocol   = proto,
                    state      = state,
                    service    = p_data.get("name", ""),
                    product    = p_data.get("product", ""),
                    version    = p_data.get("version", ""),
                    extra_info = p_data.get("extrainfo", ""),
                    cpe        = cpes,
                    tunnel     = p_data.get("tunnel", ""),
                    confidence = int(p_data.get("conf", 0)),
                    script_out = scripts,
                )
                report.ports.append(pr)
                _log_port(pr, report.os_guesses)

        report.total_open = sum(1 for p in report.ports if p.state is PortState.OPEN)
        return report


def _parse_state(raw: str) -> PortState:
    return {
        "open":     PortState.OPEN,
        "closed":   PortState.CLOSED,
        "filtered": PortState.FILTERED,
    }.get(raw, PortState.UNKNOWN)


def _log_port(pr: PortResult, _os_guesses: list[OSGuess]) -> None:
    state_col = {
        PortState.OPEN:     "[green]OPEN[/green]",
        PortState.CLOSED:   "[red]CLOSED[/red]",
        PortState.FILTERED: "[yellow]FILTERED[/yellow]",
        PortState.UNKNOWN:  "[dim]UNKNOWN[/dim]",
    }.get(pr.state, "")
    svc = pr.service_string or "unknown"
    log.info(f"  {pr.port:>5}/{pr.protocol:<3}  {state_col}  {svc}")
    for cpe in pr.cpe:
        log.debug(f"         CPE: {cpe}")


# ── Phase 3: Banner grabbing ──────────────────────────────────────────────────
class BannerPhase:
    def __init__(self, ip: str, report: ScanReport, threads: int = 20):
        self.ip      = ip
        self.report  = report
        self.threads = threads
        self.grabber = BannerGrabber()

    def run(self, progress: Progress | None = None) -> None:
        open_results = self.report.open_ports()
        if not open_results:
            return

        task = None
        if progress:
            task = progress.add_task(
                "  [cyan]Banner grabbing[/cyan]",
                total=len(open_results),
            )

        def _grab(pr: PortResult) -> None:
            banner = self.grabber.grab(self.ip, pr.port)
            if banner and not pr.banner:
                pr.banner = banner
                log.debug(f"  Banner [{pr.port}]: {banner[:80]!r}")
            if progress and task is not None:
                progress.advance(task)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            list(pool.map(_grab, open_results))

        if progress and task is not None:
            progress.update(task, description="  [green]Banner grabbing done[/green]")


# ── Port range parser ─────────────────────────────────────────────────────────
def _parse_port_range(spec: str) -> list[int]:
    """
    Parse port specifications like:
      '1-1024'          → range
      '80,443,8080'     → explicit list
      '1-100,443,8080'  → mixed
    """
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    # Deduplicate and clamp to valid range
    return sorted(set(p for p in ports if 1 <= p <= 65535))


# ── Result table ──────────────────────────────────────────────────────────────
def _print_results(report: ScanReport) -> None:
    open_list = report.open_ports()
    if not open_list:
        log.warn("No open ports found.")
        return

    t = Table(
        title=f"Open Ports — {report.ip}",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    t.add_column("Port",       style="bold white",  no_wrap=True, width=8)
    t.add_column("Proto",      style="dim",          width=6)
    t.add_column("Service",    style="green",         width=12)
    t.add_column("Product / Version",                 width=28)
    t.add_column("CPE",        style="dim yellow",    width=30)
    t.add_column("Banner",     style="dim",           width=30)

    for pr in open_list:
        cpe_str     = pr.cpe[0] if pr.cpe else ""
        banner_clip = pr.banner[:40].replace("\n", " ") if pr.banner else ""
        t.add_row(
            str(pr.port),
            pr.protocol,
            pr.service or "—",
            f"{pr.product} {pr.version}".strip() or "—",
            cpe_str or "—",
            banner_clip or "—",
        )

    _console.print(t)

    if report.os_guesses:
        best = report.os_guesses[0]
        log.info(f"OS guess: {best.name} (accuracy {best.accuracy}%)")
        if best.cpe:
            log.info(f"OS CPE : {best.cpe}")


# ── Public API ────────────────────────────────────────────────────────────────
class ActiveScan:
    """
    Orchestrates Phase 1 (TCP sweep) → Phase 2 (Nmap) → Phase 3 (banners).
    Returns a plain dict for the shared ScanResult store.
    """

    def __init__(self, ip: str, port_range: str = cfg.network.port_range,
                 profile: str = "standard"):
        self.ip         = ip
        self.port_range = port_range
        self.profile    = profile

    def run(self) -> dict:
        t0    = time.perf_counter()
        ports = _parse_port_range(self.port_range)

        log.info(f"Scanning {self.ip} — {len(ports)} ports — profile: {self.profile}")

        progress = Progress(
            SpinnerColumn("dots2"),
            TextColumn("{task.description}"),
            BarColumn(bar_width=28, style="cyan", complete_style="green"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=_console,
            transient=False,
        )

        with progress:
            # ── Phase 1: fast TCP sweep ───────────────────────────────────────
            sweeper  = TCPConnectScanner(self.ip, ports)
            open_set = sweeper.scan(progress)

            log.info(f"TCP sweep: {len(open_set)}/{len(ports)} ports open")

            if not open_set:
                # Fallback: Nmap -Pn on top common ports (skips host-discovery,
                # works against hosts that filter ICMP / drop unsolicited SYN-RST)
                log.warn("TCP sweep found 0 open ports — running Nmap -Pn fallback on common ports…")
                _COMMON = {
                    21,22,23,25,53,80,110,111,143,443,445,465,587,
                    993,995,1080,1433,1521,3000,3306,3389,5432,
                    5900,6379,8080,8443,8888,9200,27017
                }
                fallback_ports = _COMMON & set(ports)
                if fallback_ports:
                    task_fb = progress.add_task(
                        "  [yellow]Nmap -Pn fallback scan[/yellow]", total=None
                    )
                    try:
                        nm = nmap.PortScanner()
                        port_str = ",".join(str(p) for p in sorted(fallback_ports))
                        nm.scan(
                            hosts=self.ip,
                            arguments=f"-Pn -sV -T4 --open --version-intensity 5 -p {port_str}",
                        )
                        for host in nm.all_hosts():
                            for proto in nm[host].all_protocols():
                                for p, info in nm[host][proto].items():
                                    if info.get("state") == "open":
                                        open_set.add(p)
                        progress.update(task_fb,
                                        description=f"  [green]Nmap fallback — {len(open_set)} open[/green]",
                                        total=1, completed=1)
                    except Exception as e:
                        log.warn(f"Nmap fallback failed: {e}")
                        progress.update(task_fb, total=1, completed=1,
                                        description="  [red]Nmap fallback failed[/red]")

                if not open_set:
                    log.warn("No open ports found after fallback — host may be firewalled.")
                    return ScanReport(ip=self.ip).to_dict()

            # ── Phase 2: Nmap service detection ───────────────────────────────
            nmap_scanner = NmapServiceScanner(self.ip, open_set, self.profile)
            task_nmap    = progress.add_task(
                "  [cyan]Nmap service/version detection[/cyan]", total=None
            )
            report = nmap_scanner.scan()
            progress.update(task_nmap,
                            description="  [green]Nmap detection done[/green]",
                            total=1, completed=1)

            # ── Phase 3: banner grabbing ──────────────────────────────────────
            banner_phase = BannerPhase(self.ip, report)
            banner_phase.run(progress)

            # ── Phase 4: UDP scan (top ports, requires root) ──────────────────
            if self.profile != "quick":
                task_udp = progress.add_task(
                    "  [cyan]UDP scan (top ports)[/cyan]", total=None
                )
                try:
                    nm_udp = nmap.PortScanner()
                    nm_udp.scan(
                        hosts=self.ip,
                        arguments="-Pn -sU -T4 --open --version-intensity 3 "
                                  "--top-ports 20",
                    )
                    udp_found = 0
                    for host in nm_udp.all_hosts():
                        for port, info in nm_udp[host].get("udp", {}).items():
                            if info.get("state") in ("open", "open|filtered"):
                                pr = PortResult(
                                    port      = port,
                                    protocol  = "udp",
                                    state     = PortState.OPEN,
                                    service   = info.get("name", ""),
                                    product   = info.get("product", ""),
                                    version   = info.get("version", ""),
                                )
                                report.ports.append(pr)
                                report.total_open += 1
                                udp_found += 1
                                log.info(f"  UDP open: {port}/{info.get('name','?')}")
                    progress.update(task_udp,
                                    description=f"  [green]UDP scan done — {udp_found} open[/green]",
                                    total=1, completed=1)
                except Exception as e:
                    log.warn(f"  UDP scan skipped ({e}) — run as root for UDP")
                    progress.update(task_udp, total=1, completed=1,
                                    description="  [yellow]UDP scan skipped (needs root)[/yellow]")

        # ── Print results table ───────────────────────────────────────────────
        report.scan_time = round(time.perf_counter() - t0, 2)
        _print_results(report)

        log.success(
            f"Active scan complete: {report.total_open} open ports in {report.scan_time}s"
        )
        return report.to_dict()
