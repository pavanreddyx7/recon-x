# R3CON-X — Installation & Usage Guide

> **Reconnaissance & Vulnerability Intelligence Framework**  
> Automated 7-stage pipeline: passive recon → active scanning → web enumeration → CVE correlation → risk analysis → reporting.

---

## Requirements

| Dependency | Version |
|------------|---------|
| Python     | 3.10+   |
| Nmap       | 7.0+    |
| Nikto      | 2.0+    |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/pavanreddyx7/recon-x.git
cd recon-x
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install System Tools (Kali / Debian / Ubuntu)

```bash
sudo apt update
sudo apt install nmap nikto -y
```

---

## Usage

> `sudo` is required for Nmap port scanning.

### Basic Scan

```bash
sudo python3 main.py -t <target>
```

### Scan Examples

```bash
# Single IP
sudo python3 main.py -t 192.168.1.1

# Domain
sudo python3 main.py -t example.com

# Subnet
sudo python3 main.py -t 10.0.0.0/24

# Multiple targets from file
sudo python3 main.py -T targets.txt
```

---

## Scan Profiles

```bash
# Quick scan — top 100 ports, fast
sudo python3 main.py -t example.com --profile quick

# Standard scan — ports 1-1024, all modules (default)
sudo python3 main.py -t example.com --profile standard

# Full scan — all 65535 ports, deep analysis
sudo python3 main.py -t example.com --profile full

# Stealth scan — low-noise, slow
sudo python3 main.py -t example.com --profile stealth
```

---

## Web Application Scan

```bash
# Scan only web ports
sudo python3 main.py -t example.com --ports 80,443,8080,8443,8000,8888,3000,5000

# Skip passive recon and CVE lookup (faster)
sudo python3 main.py -t example.com --ports 80,443 --skip-passive --skip-cve

# Authenticated web scan (with session cookie)
sudo python3 main.py -t example.com --auth-cookie "session=abc123"

# Scan through Burp Suite proxy
sudo python3 main.py -t example.com --proxy http://127.0.0.1:8080
```

---

## All Options

| Flag | Description |
|------|-------------|
| `-t TARGET` | Single target — IP, domain, CIDR, or URL |
| `-T FILE` | File with one target per line |
| `-o DIR` | Output directory (default: `output/`) |
| `--ports RANGE` | Custom port range e.g. `80,443` or `1-1000` |
| `--profile` | `quick` / `standard` / `full` / `stealth` |
| `--skip-passive` | Skip passive reconnaissance (WHOIS, DNS) |
| `--skip-web` | Skip web enumeration |
| `--skip-cve` | Skip CVE lookup — offline mode |
| `--proxy URL` | Route traffic through HTTP/HTTPS proxy |
| `--auth-cookie` | Session cookie for authenticated scans |
| `--notify-slack` | Send CRITICAL findings to Slack webhook |
| `-v` | Verbose / debug output |

---

## Output Reports

All reports are saved to the `output/` directory after each scan:

| Format   | Description |
|----------|-------------|
| PDF      | Full formatted report |
| HTML     | Interactive web report |
| JSON     | Machine-readable full results |
| Markdown | Summary report |
| CSV      | CVE findings export |
| SARIF    | IDE/CI integration format |

```bash
# Reports saved to:
output/R3CONX_<target>_<timestamp>.pdf
output/R3CONX_<target>_<timestamp>.html
output/R3CONX_<target>_<timestamp>.json
output/R3CONX_<target>_<timestamp>.md
output/R3CONX_<target>_<timestamp>_cve.csv
output/R3CONX_<target>_<timestamp>.sarif
```

---

## Scan Pipeline (7 Stages)

```
STAGE 1 · Input Validation       — target parsing, DNS resolution
STAGE 2 · Passive Reconnaissance — WHOIS, DNS records, subdomain hints
STAGE 3 · Active Scanning        — Nmap port scan, service detection, OS guess
STAGE 4 · Web Enumeration        — headers, TLS, dirs, cookies, CORS, WAF, Nikto
STAGE 5 · CVE Correlation        — NVD API lookup per service/version
STAGE 6 · Risk Analysis          — CVSS scoring, attack chains, remediation plan
STAGE 7 · Report Generation      — PDF, HTML, JSON, Markdown, CSV, SARIF
```

---

## Common Command Combinations

```bash
# Fast web-only recon with verbose output
sudo python3 main.py -t example.com --ports 80,443 --skip-passive --skip-cve -v

# Full deep scan with Slack alert
sudo python3 main.py -t example.com --profile full --notify-slack https://hooks.slack.com/...

# Offline scan (no internet needed)
sudo python3 main.py -t 192.168.1.1 --skip-cve --skip-passive

# Save results to custom folder
sudo python3 main.py -t example.com -o /home/user/scans/
```

---

## Legal Disclaimer

> This tool is intended for **authorized security testing only**.  
> Do not use against systems you do not own or have explicit written permission to test.  
> Unauthorized scanning may be illegal in your jurisdiction.
