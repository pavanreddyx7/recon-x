# R3CON-X Development Guide
## Reconnaissance & Vulnerability Intelligence Framework

---

## PROJECT STRUCTURE (Final)

```
reconX/
├── main.py                  # Entry point
├── config.py                # Global config & constants
├── requirements.txt         # Python dependencies
├── output/                  # Generated reports
├── modules/
│   ├── __init__.py
│   ├── passive_recon.py     # Stage 2: Passive Reconnaissance
│   ├── active_scan.py       # Stage 3: Active Scanning
│   ├── web_enum.py          # Stage 4: Web Enumeration
│   ├── cve_engine.py        # Stage 5: CVE Correlation
│   ├── risk_engine.py       # Stage 6: Risk Analysis
│   └── report_gen.py        # Stage 7: Report Generation
└── utils/
    ├── __init__.py
    ├── validator.py          # Input validation
    ├── logger.py             # Logging utility
    └── banner.py             # CLI banner
```

---

## STAGE 0 — ENVIRONMENT SETUP

### 0.1 Install Python & pip
```bash
sudo apt update && sudo apt install python3 python3-pip python3-venv -y
```

### 0.2 Create Virtual Environment
```bash
cd ~/Desktop/reconX
python3 -m venv venv
source venv/bin/activate
```

### 0.3 Install Required Libraries
```bash
pip install requests
pip install python-nmap
pip install beautifulsoup4
pip install reportlab
pip install dnspython
pip install scapy
pip install colorama
pip install tabulate
pip install aiohttp
pip install asyncio
```

### 0.4 Install Optional System Tools
```bash
sudo apt install nmap nikto whois dnsutils -y
```

### 0.5 Create requirements.txt
```
requests>=2.31.0
python-nmap>=0.7.1
beautifulsoup4>=4.12.0
reportlab>=4.0.0
dnspython>=2.4.0
scapy>=2.5.0
colorama>=0.4.6
tabulate>=0.9.0
aiohttp>=3.9.0
```

---

## STAGE 1 — PROJECT SKELETON & ENTRY POINT

**Goal:** Create base folder structure, config file, utilities, and main entry point.

### 1.1 Create Folder Structure
```bash
mkdir -p ~/Desktop/reconX/{modules,utils,output}
touch ~/Desktop/reconX/modules/__init__.py
touch ~/Desktop/reconX/utils/__init__.py
```

### 1.2 Create config.py
```python
# config.py
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = ""  # Optional: Register at nvd.nist.gov for higher rate limits

TIMEOUT = 10          # HTTP request timeout in seconds
MAX_THREADS = 50      # Thread pool size for port scanning
PORT_RANGE = "1-1024" # Default port scan range

RISK_LEVELS = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
    "NONE":     (0.0, 0.0),
}
```

### 1.3 Create utils/banner.py
```python
# utils/banner.py
from colorama import Fore, Style, init
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.RED}
 ██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗      ██╗  ██╗
 ██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║      ╚██╗██╔╝
 ██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║       ╚███╔╝ 
 ██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗██║       ██╔██╗ 
 ██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║      ██╔╝ ██╗
 ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}   [ Reconnaissance & Vulnerability Intelligence Framework ]{Style.RESET_ALL}
{Fore.CYAN}                   Author: R3CON-X Team{Style.RESET_ALL}
{Fore.RED}         !! For Authorized Security Testing Only !!{Style.RESET_ALL}
"""
    print(banner)
```

### 1.4 Create utils/logger.py
```python
# utils/logger.py
import logging
import os
from datetime import datetime
from colorama import Fore, Style

LOG_FILE = f"output/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def info(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
    logging.info(msg)

def warn(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
    logging.warning(msg)

def error(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
    logging.error(msg)

def section(title):
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{Style.RESET_ALL}\n")
```

### 1.5 Create utils/validator.py
```python
# utils/validator.py
import re
import socket

def validate_target(target):
    """Returns ('ip', target) or ('domain', target) or raises ValueError."""
    target = target.strip()

    # Check if IP address
    ip_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    if ip_pattern.match(target):
        return ("ip", target)

    # Check if valid domain
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if domain_pattern.match(target):
        return ("domain", target)

    raise ValueError(f"Invalid target: '{target}'. Provide a valid IP or domain.")

def resolve_domain(domain):
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None
```

### 1.6 Create main.py
```python
# main.py
import sys
import os
import argparse
from datetime import datetime

from utils.banner import print_banner
from utils.logger import info, warn, error, section
from utils.validator import validate_target, resolve_domain
from config import OUTPUT_DIR

from modules.passive_recon import PassiveRecon
from modules.active_scan import ActiveScan
from modules.web_enum import WebEnum
from modules.cve_engine import CVEEngine
from modules.risk_engine import RiskEngine
from modules.report_gen import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description="R3CON-X: Reconnaissance & Vulnerability Intelligence Framework"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP or domain")
    parser.add_argument("-o", "--output", default=OUTPUT_DIR, help="Output directory")
    parser.add_argument("--skip-passive", action="store_true", help="Skip passive recon")
    parser.add_argument("--skip-web", action="store_true", help="Skip web enumeration")
    parser.add_argument("--ports", default="1-1024", help="Port range (default: 1-1024)")
    return parser.parse_args()


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print_banner()

    args = parse_args()

    # --- STAGE 1: INPUT VALIDATION ---
    section("STAGE 1: Input Validation")
    try:
        target_type, target = validate_target(args.target)
        info(f"Target: {target} ({target_type})")
    except ValueError as e:
        error(str(e))
        sys.exit(1)

    ip_address = target if target_type == "ip" else resolve_domain(target)
    if not ip_address:
        error("Could not resolve domain to IP.")
        sys.exit(1)
    info(f"Resolved IP: {ip_address}")

    scan_results = {
        "target": target,
        "ip": ip_address,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "passive_recon": {},
        "active_scan": {},
        "web_enum": {},
        "vulnerabilities": [],
        "risk_summary": {},
    }

    # --- STAGE 2: PASSIVE RECON ---
    if not args.skip_passive:
        section("STAGE 2: Passive Reconnaissance")
        pr = PassiveRecon(target, ip_address)
        scan_results["passive_recon"] = pr.run()

    # --- STAGE 3: ACTIVE SCAN ---
    section("STAGE 3: Active Scanning")
    scanner = ActiveScan(ip_address, args.ports)
    scan_results["active_scan"] = scanner.run()

    # --- STAGE 4: WEB ENUMERATION ---
    if not args.skip_web:
        section("STAGE 4: Web Enumeration")
        we = WebEnum(target)
        scan_results["web_enum"] = we.run()

    # --- STAGE 5: CVE CORRELATION ---
    section("STAGE 5: CVE Correlation")
    cve = CVEEngine(scan_results["active_scan"])
    scan_results["vulnerabilities"] = cve.run()

    # --- STAGE 6: RISK ANALYSIS ---
    section("STAGE 6: Risk Analysis")
    risk = RiskEngine(scan_results["vulnerabilities"])
    scan_results["risk_summary"] = risk.run()

    # --- STAGE 7: REPORT GENERATION ---
    section("STAGE 7: Report Generation")
    reporter = ReportGenerator(scan_results, args.output)
    reporter.run()

    info("Scan complete. Check the output/ directory for reports.")


if __name__ == "__main__":
    main()
```

---

## STAGE 2 — PASSIVE RECONNAISSANCE MODULE

**File:** `modules/passive_recon.py`

**Goal:** Gather DNS records, WHOIS info, and open-source intelligence without touching the target directly.

### What it does:
- DNS A, MX, NS, TXT record enumeration
- WHOIS lookup (registrar, dates, nameservers)
- Subdomain enumeration using wordlist brute-force
- Reverse DNS lookup

```python
# modules/passive_recon.py
import dns.resolver
import dns.reversename
import socket
import subprocess
import requests
from utils.logger import info, warn, error
from config import TIMEOUT

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging",
    "vpn", "remote", "portal", "blog", "shop", "test",
    "webmail", "mx", "ns1", "ns2", "cdn", "secure", "app"
]

class PassiveRecon:
    def __init__(self, target, ip):
        self.target = target
        self.ip = ip
        self.results = {}

    def dns_lookup(self):
        info("Running DNS record enumeration...")
        records = {}
        for record_type in ["A", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records[record_type] = [str(r) for r in answers]
                info(f"  {record_type}: {records[record_type]}")
            except Exception:
                records[record_type] = []
        return records

    def whois_lookup(self):
        info("Running WHOIS lookup...")
        try:
            result = subprocess.run(
                ["whois", self.target],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout
            parsed = {}
            for line in output.splitlines():
                for field in ["Registrar:", "Creation Date:", "Expiry Date:",
                              "Updated Date:", "Name Server:", "Registrant"]:
                    if line.strip().startswith(field):
                        key = field.strip(":").strip()
                        parsed.setdefault(key, []).append(line.split(":", 1)[-1].strip())
            return parsed
        except Exception as e:
            warn(f"WHOIS failed: {e}")
            return {}

    def subdomain_enum(self):
        info("Enumerating subdomains...")
        found = []
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append({"subdomain": fqdn, "ip": ip})
                info(f"  Found: {fqdn} -> {ip}")
            except socket.gaierror:
                pass
        return found

    def reverse_dns(self):
        info("Running reverse DNS lookup...")
        try:
            rev = dns.reversename.from_address(self.ip)
            answer = str(dns.resolver.resolve(rev, "PTR")[0])
            info(f"  PTR: {answer}")
            return answer
        except Exception:
            return None

    def run(self):
        self.results["dns_records"] = self.dns_lookup()
        self.results["whois"] = self.whois_lookup()
        self.results["subdomains"] = self.subdomain_enum()
        self.results["reverse_dns"] = self.reverse_dns()
        return self.results
```

---

## STAGE 3 — ACTIVE SCANNING MODULE

**File:** `modules/active_scan.py`

**Goal:** Port scanning, service detection, banner grabbing, OS fingerprinting.

### What it does:
- TCP port scan across specified range
- Service version detection using python-nmap
- Banner grabbing for open ports
- OS fingerprinting (requires root)

```python
# modules/active_scan.py
import nmap
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import info, warn, error
from config import TIMEOUT, MAX_THREADS

class ActiveScan:
    def __init__(self, ip, port_range="1-1024"):
        self.ip = ip
        self.port_range = port_range
        self.results = {}

    def nmap_scan(self):
        info(f"Running Nmap service scan on {self.ip} ports {self.port_range}...")
        nm = nmap.PortScanner()
        try:
            # -sV: version detection, -O: OS detection (needs root), --open: only open ports
            nm.scan(self.ip, self.port_range, arguments="-sV --open -T4")
            ports = []
            for proto in nm[self.ip].all_protocols():
                for port in nm[self.ip][proto]:
                    s = nm[self.ip][proto][port]
                    entry = {
                        "port": port,
                        "protocol": proto,
                        "state": s["state"],
                        "service": s["name"],
                        "product": s.get("product", ""),
                        "version": s.get("version", ""),
                        "extrainfo": s.get("extrainfo", ""),
                        "cpe": s.get("cpe", ""),
                    }
                    ports.append(entry)
                    info(f"  {port}/{proto} -> {s['name']} {s.get('product','')} {s.get('version','')}")
            return ports
        except Exception as e:
            error(f"Nmap scan failed: {e}")
            return []

    def banner_grab(self, port):
        try:
            s = socket.socket()
            s.settimeout(TIMEOUT)
            s.connect((self.ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            return banner
        except Exception:
            return ""

    def run(self):
        open_ports = self.nmap_scan()
        info("Attempting banner grabs on open ports...")
        for entry in open_ports:
            if entry["state"] == "open":
                banner = self.banner_grab(entry["port"])
                entry["banner"] = banner
                if banner:
                    info(f"  Banner [{entry['port']}]: {banner[:80]}")
        self.results["open_ports"] = open_ports
        self.results["total_open"] = len(open_ports)
        return self.results
```

---

## STAGE 4 — WEB ENUMERATION MODULE

**File:** `modules/web_enum.py`

**Goal:** Analyze HTTP security headers, detect technologies, find hidden directories.

### What it does:
- HTTP/HTTPS connectivity check
- Security header analysis (X-Frame-Options, CSP, HSTS, etc.)
- Technology fingerprinting via response headers
- Directory brute-force enumeration
- Robots.txt and sitemap.xml retrieval

```python
# modules/web_enum.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from utils.logger import info, warn, error
from config import TIMEOUT

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

COMMON_DIRS = [
    "admin", "login", "dashboard", "api", "backup", "config",
    "uploads", "images", "static", "js", "css", "includes",
    "phpmyadmin", "wp-admin", "wp-login.php", ".git", ".env",
    "robots.txt", "sitemap.xml", "readme.md", "changelog.txt",
    "test", "dev", "old", "temp", "tmp", "logs", "db",
]

class WebEnum:
    def __init__(self, target):
        self.target = target
        self.base_url = None
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "R3CON-X/1.0 Security Scanner"})

    def detect_base_url(self):
        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.target}"
            try:
                r = self.session.get(url, timeout=TIMEOUT, verify=False)
                info(f"  Web service reachable at {url} (HTTP {r.status_code})")
                self.base_url = url
                return r
            except Exception:
                pass
        warn("No web service detected on HTTP/HTTPS.")
        return None

    def check_headers(self, response):
        info("Analyzing security headers...")
        present = {}
        missing = []
        for header in SECURITY_HEADERS:
            val = response.headers.get(header)
            if val:
                present[header] = val
                info(f"  [PRESENT] {header}: {val}")
            else:
                missing.append(header)
                warn(f"  [MISSING] {header}")
        return {"present": present, "missing": missing}

    def fingerprint_tech(self, response):
        info("Fingerprinting web technologies...")
        tech = []
        server = response.headers.get("Server", "")
        powered = response.headers.get("X-Powered-By", "")
        if server:
            tech.append(f"Server: {server}")
            info(f"  Server: {server}")
        if powered:
            tech.append(f"X-Powered-By: {powered}")
            info(f"  X-Powered-By: {powered}")
        return tech

    def dir_enum(self):
        if not self.base_url:
            return []
        info("Running directory enumeration...")
        found = []
        for path in COMMON_DIRS:
            url = urljoin(self.base_url + "/", path)
            try:
                r = self.session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    found.append({"url": url, "status": r.status_code})
                    info(f"  [{r.status_code}] {url}")
            except Exception:
                pass
        return found

    def get_robots(self):
        if not self.base_url:
            return ""
        try:
            r = self.session.get(f"{self.base_url}/robots.txt", timeout=TIMEOUT, verify=False)
            if r.status_code == 200:
                info("  robots.txt found.")
                return r.text[:2000]
        except Exception:
            pass
        return ""

    def run(self):
        import urllib3
        urllib3.disable_warnings()

        response = self.detect_base_url()
        if response:
            self.results["base_url"] = self.base_url
            self.results["status_code"] = response.status_code
            self.results["headers"] = self.check_headers(response)
            self.results["technologies"] = self.fingerprint_tech(response)
            self.results["robots_txt"] = self.get_robots()
        self.results["directories"] = self.dir_enum()
        return self.results
```

---

## STAGE 5 — CVE CORRELATION ENGINE

**File:** `modules/cve_engine.py`

**Goal:** Map detected service versions to known CVEs using the NVD API.

### What it does:
- Queries NVD (National Vulnerability Database) API
- Searches by keyword: product name + version
- Retrieves CVE ID, description, CVSS score, severity
- Caches results to avoid duplicate API calls

```python
# modules/cve_engine.py
import requests
import time
from utils.logger import info, warn, error
from config import NVD_API_URL, NVD_API_KEY, TIMEOUT

class CVEEngine:
    def __init__(self, active_scan_results):
        self.ports = active_scan_results.get("open_ports", [])
        self.cache = {}
        self.vulnerabilities = []

    def query_nvd(self, keyword):
        if keyword in self.cache:
            return self.cache[keyword]

        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        try:
            r = requests.get(NVD_API_URL, params=params, headers=headers, timeout=TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                cves = []
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d["lang"] == "en":
                            desc = d["value"]
                            break
                    metrics = cve.get("metrics", {})
                    score = 0.0
                    severity = "NONE"
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if key in metrics and metrics[key]:
                            m = metrics[key][0].get("cvssData", {})
                            score = m.get("baseScore", 0.0)
                            severity = m.get("baseSeverity", "NONE")
                            break
                    cves.append({
                        "cve_id": cve_id,
                        "description": desc[:300],
                        "score": score,
                        "severity": severity,
                        "keyword": keyword,
                    })
                self.cache[keyword] = cves
                time.sleep(0.6)  # Respect NVD rate limit (6 req/sec without API key)
                return cves
        except Exception as e:
            warn(f"NVD query failed for '{keyword}': {e}")
        return []

    def run(self):
        info("Correlating services with CVE database...")
        for port_entry in self.ports:
            product = port_entry.get("product", "").strip()
            version = port_entry.get("version", "").strip()
            service = port_entry.get("service", "").strip()

            if not product and not service:
                continue

            keyword = f"{product} {version}".strip() if product else service
            info(f"  Querying CVEs for: {keyword}")
            cves = self.query_nvd(keyword)
            for cve in cves:
                cve["port"] = port_entry["port"]
                cve["service"] = service
                self.vulnerabilities.append(cve)
                info(f"    {cve['cve_id']} | CVSS: {cve['score']} | {cve['severity']}")

        if not self.vulnerabilities:
            warn("No CVEs found for detected services.")
        else:
            info(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        return self.vulnerabilities
```

---

## STAGE 6 — RISK ANALYSIS ENGINE

**File:** `modules/risk_engine.py`

**Goal:** Categorize and prioritize vulnerabilities by severity. Produce a risk summary.

```python
# modules/risk_engine.py
from utils.logger import info, warn
from config import RISK_LEVELS
from tabulate import tabulate
from colorama import Fore, Style

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

class RiskEngine:
    def __init__(self, vulnerabilities):
        self.vulns = vulnerabilities
        self.summary = {level: [] for level in SEVERITY_ORDER}

    def classify(self):
        for vuln in self.vulns:
            score = vuln.get("score", 0.0)
            assigned = "NONE"
            for level, (low, high) in RISK_LEVELS.items():
                if low <= score <= high:
                    assigned = level
                    break
            vuln["risk_level"] = assigned
            self.summary[assigned].append(vuln)

    def print_summary(self):
        color_map = {
            "CRITICAL": Fore.RED,
            "HIGH":     Fore.MAGENTA,
            "MEDIUM":   Fore.YELLOW,
            "LOW":      Fore.CYAN,
            "NONE":     Fore.WHITE,
        }
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  VULNERABILITY RISK SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        rows = []
        for level in SEVERITY_ORDER:
            count = len(self.summary[level])
            color = color_map[level]
            rows.append([f"{color}{level}{Style.RESET_ALL}", count])
        print(tabulate(rows, headers=["Risk Level", "Count"], tablefmt="rounded_outline"))

        if self.summary["CRITICAL"]:
            print(f"\n{Fore.RED}[!] CRITICAL Vulnerabilities:{Style.RESET_ALL}")
            for v in self.summary["CRITICAL"]:
                print(f"    {v['cve_id']} | Port {v['port']} | CVSS {v['score']}")

    def get_top_risks(self, n=10):
        sorted_vulns = sorted(self.vulns, key=lambda x: x.get("score", 0), reverse=True)
        return sorted_vulns[:n]

    def run(self):
        self.classify()
        self.print_summary()
        return {
            "counts": {level: len(self.summary[level]) for level in SEVERITY_ORDER},
            "top_risks": self.get_top_risks(),
            "all": self.vulns,
        }
```

---

## STAGE 7 — REPORT GENERATION MODULE

**File:** `modules/report_gen.py`

**Goal:** Generate a professional PDF report + JSON data dump.

```python
# modules/report_gen.py
import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, red, orange, yellow, green, grey, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from utils.logger import info

SEVERITY_COLORS = {
    "CRITICAL": HexColor("#FF0000"),
    "HIGH":     HexColor("#FF6600"),
    "MEDIUM":   HexColor("#FFC300"),
    "LOW":      HexColor("#00AAFF"),
    "NONE":     HexColor("#AAAAAA"),
}

class ReportGenerator:
    def __init__(self, scan_results, output_dir):
        self.data = scan_results
        self.output_dir = output_dir
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = self.data["target"].replace(".", "_")
        self.pdf_path = os.path.join(output_dir, f"R3CONX_{target_safe}_{ts}.pdf")
        self.json_path = os.path.join(output_dir, f"R3CONX_{target_safe}_{ts}.json")
        self.styles = getSampleStyleSheet()

    def save_json(self):
        with open(self.json_path, "w") as f:
            json.dump(self.data, f, indent=4)
        info(f"JSON report saved: {self.json_path}")

    def build_pdf(self):
        doc = SimpleDocTemplate(
            self.pdf_path, pagesize=A4,
            leftMargin=0.75*inch, rightMargin=0.75*inch,
            topMargin=0.75*inch, bottomMargin=0.75*inch
        )
        story = []
        styles = self.styles

        # Title
        title_style = ParagraphStyle("Title", fontSize=22, textColor=HexColor("#CC0000"),
                                     alignment=TA_CENTER, spaceAfter=6, fontName="Helvetica-Bold")
        story.append(Paragraph("R3CON-X Security Assessment Report", title_style))
        story.append(HRFlowable(width="100%", thickness=2, color=HexColor("#CC0000")))
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles["Heading1"]))
        risk_counts = self.data.get("risk_summary", {}).get("counts", {})
        summary_data = [
            ["Target", self.data.get("target", "N/A")],
            ["IP Address", self.data.get("ip", "N/A")],
            ["Scan Date", self.data.get("timestamp", "N/A")],
            ["Open Ports", str(self.data.get("active_scan", {}).get("total_open", 0))],
            ["Total Vulnerabilities", str(len(self.data.get("vulnerabilities", [])))],
            ["Critical", str(risk_counts.get("CRITICAL", 0))],
            ["High", str(risk_counts.get("HIGH", 0))],
            ["Medium", str(risk_counts.get("MEDIUM", 0))],
            ["Low", str(risk_counts.get("LOW", 0))],
        ]
        t = Table(summary_data, colWidths=[2.5*inch, 4*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (0, -1), white),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("BACKGROUND", (1, 0), (1, -1), HexColor("#F5F5F5")),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
            ("ROWBACKGROUNDS", (1, 0), (1, -1), [HexColor("#FFFFFF"), HexColor("#F5F5F5")]),
        ]))
        story.append(t)
        story.append(Spacer(1, 16))

        # Open Ports Section
        story.append(Paragraph("Open Ports & Services", styles["Heading1"]))
        ports = self.data.get("active_scan", {}).get("open_ports", [])
        if ports:
            port_data = [["Port", "Protocol", "Service", "Product", "Version"]]
            for p in ports:
                port_data.append([
                    str(p.get("port", "")),
                    p.get("protocol", ""),
                    p.get("service", ""),
                    p.get("product", ""),
                    p.get("version", ""),
                ])
            pt = Table(port_data, colWidths=[0.7*inch, 0.9*inch, 1.2*inch, 2*inch, 1.7*inch])
            pt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#CC0000")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), HexColor("#F9F9F9")]),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
            ]))
            story.append(pt)
        else:
            story.append(Paragraph("No open ports detected.", styles["Normal"]))
        story.append(Spacer(1, 16))

        # Vulnerability Section
        story.append(Paragraph("Vulnerability Findings", styles["Heading1"]))
        vulns = self.data.get("risk_summary", {}).get("top_risks", [])
        if vulns:
            vuln_data = [["CVE ID", "Port", "CVSS", "Severity", "Description"]]
            for v in vulns:
                sev = v.get("risk_level", v.get("severity", "NONE"))
                vuln_data.append([
                    v.get("cve_id", ""),
                    str(v.get("port", "")),
                    str(v.get("score", "")),
                    sev,
                    Paragraph(v.get("description", "")[:200], styles["Normal"]),
                ])
            vt = Table(vuln_data, colWidths=[1.3*inch, 0.6*inch, 0.7*inch, 1*inch, 2.9*inch])
            vt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#CC0000")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), HexColor("#FFF8F8")]),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(vt)
        else:
            story.append(Paragraph("No vulnerabilities found.", styles["Normal"]))
        story.append(Spacer(1, 16))

        # Remediation Section
        story.append(Paragraph("Remediation Recommendations", styles["Heading1"]))
        recs = [
            "1. Patch all services with CRITICAL/HIGH CVEs immediately.",
            "2. Disable or restrict unnecessary open ports and services.",
            "3. Implement missing HTTP security headers (CSP, HSTS, X-Frame-Options).",
            "4. Regularly update all web server components and frameworks.",
            "5. Conduct periodic vulnerability assessments after any infrastructure change.",
            "6. Restrict administrative interfaces to internal networks only.",
            "7. Enable web application firewall (WAF) rules for exposed services.",
        ]
        for rec in recs:
            story.append(Paragraph(rec, styles["Normal"]))
        story.append(Spacer(1, 8))

        # Footer
        story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#CC0000")))
        footer_style = ParagraphStyle("Footer", fontSize=9, textColor=grey,
                                      alignment=TA_CENTER, spaceBefore=6)
        story.append(Paragraph(
            "R3CON-X | For Authorized Security Testing Only | Confidential",
            footer_style
        ))

        doc.build(story)
        info(f"PDF report saved: {self.pdf_path}")

    def run(self):
        os.makedirs(self.output_dir, exist_ok=True)
        self.save_json()
        self.build_pdf()
```

---

## STAGE 8 — INTEGRATION & TESTING

### 8.1 Initialize all module files
```bash
touch ~/Desktop/reconX/modules/__init__.py
touch ~/Desktop/reconX/utils/__init__.py
```

### 8.2 Test each module individually
```bash
# Test passive recon only
python3 -c "
from modules.passive_recon import PassiveRecon
pr = PassiveRecon('example.com', '93.184.216.34')
print(pr.run())
"

# Test active scan only (localhost is safe)
python3 -c "
from modules.active_scan import ActiveScan
s = ActiveScan('127.0.0.1', '22-443')
print(s.run())
"

# Test web enum only
python3 -c "
from modules.web_enum import WebEnum
w = WebEnum('example.com')
print(w.run())
"
```

### 8.3 Full Run Against a Safe Target
```bash
# Use scanme.nmap.org (Nmap's official test target)
python3 main.py -t scanme.nmap.org --ports 1-1000
```

### 8.4 Run Against Localhost
```bash
python3 main.py -t 127.0.0.1 --ports 20-8080
```

---

## STAGE 9 — CLI ENHANCEMENTS

### 9.1 Add --help output customization
Already handled by argparse in main.py.

### 9.2 Add scan profiles
Extend args in main.py:
```python
parser.add_argument("--profile", choices=["quick","full","web-only"],
                    default="full", help="Scan profile")
```
Then map profiles to port ranges and module toggles.

### 9.3 Add color-coded live progress
Use `tqdm` for progress bars:
```bash
pip install tqdm
```
```python
from tqdm import tqdm
for path in tqdm(COMMON_DIRS, desc="Dir Enum"):
    ...
```

---

## STAGE 10 — FINAL CHECKLIST BEFORE SUBMISSION

```
[ ] All modules imported correctly in main.py
[ ] requirements.txt is complete and accurate
[ ] Output directory is auto-created
[ ] PDF report generates without errors
[ ] JSON report is valid JSON
[ ] Tested on at least one authorized target (scanme.nmap.org)
[ ] No hardcoded credentials or API keys committed
[ ] Banner displays on startup
[ ] --help shows correct usage
[ ] Logging writes to output/ directory
```

---

## QUICK REFERENCE — RUN COMMANDS

```bash
# Basic scan
python3 main.py -t <TARGET_IP_OR_DOMAIN>

# Full scan with custom port range
python3 main.py -t 192.168.1.1 --ports 1-65535

# Skip passive recon (faster)
python3 main.py -t example.com --skip-passive

# Skip web enumeration
python3 main.py -t 192.168.1.1 --skip-web

# Custom output directory
python3 main.py -t example.com -o /tmp/reports
```

---

## DEPENDENCY MAP

```
main.py
 ├── utils/banner.py        (colorama)
 ├── utils/logger.py        (colorama, logging)
 ├── utils/validator.py     (socket, re)
 ├── modules/passive_recon  (dnspython, subprocess/whois)
 ├── modules/active_scan    (python-nmap, socket)
 ├── modules/web_enum       (requests, beautifulsoup4)
 ├── modules/cve_engine     (requests → NVD API)
 ├── modules/risk_engine    (tabulate, colorama)
 └── modules/report_gen     (reportlab, json)
```

---

*R3CON-X Development Guide | For Authorized Security Testing Only*
