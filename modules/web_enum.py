"""
Stage 4 — Web Enumeration
Full HTTP/HTTPS surface analysis without active exploitation.

Sub-engines:
  ConnectivityProbe   — HTTP/HTTPS detection, redirect chain, baseline fingerprint
  TLSInspector        — Certificate details, expiry, SANs, TLS version
  HeaderAnalyzer      — Security header audit with severity scoring
  TechFingerprinter   — CMS, framework, server, CDN detection
  WAFDetector         — Web Application Firewall identification
  CORSAnalyzer        — CORS policy misconfiguration checks
  CookieAuditor       — Cookie flag analysis (Secure/HttpOnly/SameSite)
  ContentDiscovery    — Concurrent directory & sensitive-file brute-force
  RobotsSitemapParser — robots.txt disallow extraction + sitemap URLs
  HTTPMethodProber    — Dangerous HTTP method enumeration
"""
from __future__ import annotations

import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich import box

from utils.logger import log
from utils.decorators import RateLimiter
from config import cfg

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
_console = Console(highlight=False)
_api_limiter = RateLimiter(calls=10, period=1.0)


# ══════════════════════════════════════════════════════════════════════════════
# Data models
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RedirectHop:
    url:    str
    status: int


@dataclass
class TLSCert:
    subject:       str       = ""
    issuer:        str       = ""
    not_before:    str       = ""
    not_after:     str       = ""
    days_remaining: int      = 0
    expired:       bool      = False
    san:           list[str] = field(default_factory=list)
    serial:        str       = ""
    tls_version:   str       = ""
    cipher:        str       = ""
    self_signed:   bool      = False


@dataclass
class HeaderFinding:
    header:   str
    present:  bool
    value:    str    = ""
    severity: str    = ""   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    message:  str    = ""


@dataclass
class DirectoryHit:
    url:         str
    status:      int
    size:        int      = 0
    redirect_to: str      = ""
    sensitive:   bool     = False
    note:        str      = ""


@dataclass
class CookieFinding:
    name:      str
    secure:    bool  = False
    http_only: bool  = False
    same_site: str   = ""
    issues:    list[str] = field(default_factory=list)


@dataclass
class CORSFinding:
    origin_tested:    str  = ""
    acao_header:      str  = ""
    acac_header:      str  = ""
    wildcard:         bool = False
    reflects_origin:  bool = False
    allows_creds:     bool = False
    severity:         str  = ""
    detail:           str  = ""


@dataclass
class WebResult:
    target:          str
    base_url:        str               = ""
    scheme:          str               = ""
    status_code:     int               = 0
    server:          str               = ""
    redirect_chain:  list[RedirectHop] = field(default_factory=list)
    tls:             TLSCert           = field(default_factory=TLSCert)
    headers:         list[HeaderFinding] = field(default_factory=list)
    header_score:    int               = 0   # 0-100
    technologies:    dict[str, list[str]] = field(default_factory=dict)
    waf:             str               = ""
    cors:            CORSFinding       = field(default_factory=CORSFinding)
    cookies:         list[CookieFinding] = field(default_factory=list)
    directories:     list[DirectoryHit] = field(default_factory=list)
    sensitive_files: list[DirectoryHit] = field(default_factory=list)
    robots_txt:      str               = ""
    disallowed_paths: list[str]        = field(default_factory=list)
    sitemap_urls:    list[str]         = field(default_factory=list)
    allowed_methods: list[str]         = field(default_factory=list)
    dangerous_methods: list[str]       = field(default_factory=list)
    page_title:      str               = ""
    meta_generator:  str               = ""
    nikto_findings:  list[str]         = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ══════════════════════════════════════════════════════════════════════════════
# Shared HTTP session (persistent connections, retry on transient errors)
# ══════════════════════════════════════════════════════════════════════════════

def _build_session() -> requests.Session:
    import os as _os
    s = requests.Session()
    s.headers.update({
        "User-Agent":      cfg.web.user_agent,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection":      "keep-alive",
    })
    # Proxy support (--proxy flag sets RECONX_PROXY env var)
    proxy = _os.environ.get("RECONX_PROXY", "")
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    # Authenticated scan cookie (--auth-cookie flag sets RECONX_AUTH_COOKIE)
    cookie = _os.environ.get("RECONX_AUTH_COOKIE", "")
    if cookie:
        for pair in cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, _, val = pair.partition("=")
                s.cookies.set(name.strip(), val.strip())
    adapter = HTTPAdapter(
        max_retries=Retry(
            total=1,
            connect=0,          # no retry on connection failure — fail fast
            read=1,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"],
        ),
        pool_connections=20,
        pool_maxsize=cfg.web.dir_threads,
    )
    s.mount("http://",  adapter)
    s.mount("https://", adapter)
    return s


# ══════════════════════════════════════════════════════════════════════════════
# Connectivity Probe
# ══════════════════════════════════════════════════════════════════════════════

class ConnectivityProbe:
    def __init__(self, target: str, session: requests.Session):
        self.target  = target
        self.session = session

    def detect(self) -> tuple[str, requests.Response] | tuple[None, None]:
        """Try HTTPS first, then HTTP. Returns (base_url, response)."""
        # (connect_timeout, read_timeout) — fast connect fail, normal read window
        _probe_timeout = (4, cfg.web.timeout)
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}"
            try:
                r = self.session.get(
                    url,
                    timeout=_probe_timeout,
                    verify=False,
                    allow_redirects=True,
                )
                log.info(f"  Web service: {url}  →  HTTP {r.status_code}")
                return url, r
            except requests.exceptions.SSLError:
                try:
                    r = self.session.get(url, timeout=_probe_timeout,
                                         verify=False, allow_redirects=True)
                    return url, r
                except Exception:
                    continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception as e:
                log.debug(f"  {scheme} probe failed: {e}")
                continue
        return None, None

    def redirect_chain(self, url: str) -> list[RedirectHop]:
        """Capture full redirect chain."""
        hops: list[RedirectHop] = []
        try:
            r = self.session.get(url, timeout=cfg.web.timeout,
                                  verify=False, allow_redirects=False)
            hops.append(RedirectHop(url=url, status=r.status_code))
            followed = 0
            while r.is_redirect and followed < cfg.web.max_redirects:
                next_url = r.headers.get("Location", "")
                if not next_url.startswith("http"):
                    next_url = urljoin(url, next_url)
                r = self.session.get(next_url, timeout=cfg.web.timeout,
                                      verify=False, allow_redirects=False)
                hops.append(RedirectHop(url=next_url, status=r.status_code))
                url = next_url
                followed += 1
        except Exception:
            pass
        return hops


# ══════════════════════════════════════════════════════════════════════════════
# TLS Inspector
# ══════════════════════════════════════════════════════════════════════════════

class TLSInspector:
    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port

    def inspect(self) -> TLSCert:
        cert = TLSCert()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((self.host, self.port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    raw       = ssock.getpeercert()
                    cert.tls_version = ssock.version() or ""
                    cert.cipher      = ssock.cipher()[0] if ssock.cipher() else ""

            if not raw:
                return cert

            # Subject
            subj = dict(x[0] for x in raw.get("subject", []))
            cert.subject = subj.get("commonName", "")

            # Issuer
            iss = dict(x[0] for x in raw.get("issuer", []))
            cert.issuer = iss.get("organizationName", iss.get("commonName", ""))

            # Self-signed check
            cert.self_signed = (cert.subject == cert.issuer)

            # Dates
            fmt = "%b %d %H:%M:%S %Y %Z"
            nb  = raw.get("notBefore", "")
            na  = raw.get("notAfter",  "")
            cert.not_before = nb
            cert.not_after  = na
            if na:
                expiry = datetime.strptime(na, fmt).replace(tzinfo=timezone.utc)
                now    = datetime.now(timezone.utc)
                cert.days_remaining = (expiry - now).days
                cert.expired        = cert.days_remaining < 0

            # SANs
            san_list = raw.get("subjectAltName", [])
            cert.san = [v for _, v in san_list]

            # Serial
            cert.serial = str(raw.get("serialNumber", ""))

            # Logging
            log.info(f"  TLS version  : {cert.tls_version}  cipher: {cert.cipher}")
            log.info(f"  Subject      : {cert.subject}")
            log.info(f"  Issuer       : {cert.issuer}")
            log.info(f"  Expires      : {cert.not_after}  ({cert.days_remaining} days)")
            log.info(f"  SANs         : {', '.join(cert.san[:5])}"
                     + ("…" if len(cert.san) > 5 else ""))
            if cert.expired:
                log.warn("  CERTIFICATE EXPIRED")
            elif cert.days_remaining < 30:
                log.warn(f"  Certificate expires in {cert.days_remaining} days!")
            if cert.self_signed:
                log.warn("  Self-signed certificate detected")

        except (ssl.SSLError, socket.error) as e:
            log.warn(f"  TLS inspection failed: {e}")
        except Exception as e:
            log.debug(f"  TLS parse error: {e}")

        return cert


# ══════════════════════════════════════════════════════════════════════════════
# Security Header Analyzer
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class _HeaderRule:
    name:     str
    severity: str
    message:  str
    check:    Any = None   # callable(value) -> bool for presence check


_HEADER_RULES: list[_HeaderRule] = [
    _HeaderRule("Strict-Transport-Security",  "HIGH",     "HSTS missing — HTTPS downgrade possible"),
    _HeaderRule("Content-Security-Policy",    "HIGH",     "CSP absent — XSS mitigation disabled"),
    _HeaderRule("X-Frame-Options",            "MEDIUM",   "Clickjacking protection missing"),
    _HeaderRule("X-Content-Type-Options",     "MEDIUM",   "MIME sniffing not prevented"),
    _HeaderRule("Referrer-Policy",            "LOW",      "Referrer leakage risk"),
    _HeaderRule("Permissions-Policy",         "LOW",      "Browser feature access uncontrolled"),
    _HeaderRule("X-XSS-Protection",           "LOW",      "Legacy XSS filter not set (deprecated but still audited)"),
    _HeaderRule("Cache-Control",              "INFO",     "Caching policy undefined"),
    _HeaderRule("Cross-Origin-Opener-Policy", "MEDIUM",   "COOP not set — cross-origin isolation missing"),
    _HeaderRule("Cross-Origin-Resource-Policy","MEDIUM",  "CORP not set"),
]

# Headers that should NOT be present (information disclosure)
_LEAK_HEADERS = ["X-Powered-By", "Server", "X-AspNet-Version",
                 "X-AspNetMvc-Version", "X-Generator"]

_SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}

class HeaderAnalyzer:
    def __init__(self, response: requests.Response):
        self.headers = response.headers

    def analyze(self) -> tuple[list[HeaderFinding], int]:
        findings: list[HeaderFinding] = []
        deductions = 0

        for rule in _HEADER_RULES:
            val = self.headers.get(rule.name, "")
            present = bool(val)
            f = HeaderFinding(
                header   = rule.name,
                present  = present,
                value    = val[:200],
                severity = "" if present else rule.severity,
                message  = "" if present else rule.message,
            )
            findings.append(f)
            if not present:
                deductions += _SEVERITY_WEIGHT.get(rule.severity, 0)
                log.warn(f"  [{rule.severity}] MISSING: {rule.name} — {rule.message}")
            else:
                log.info(f"  [OK]  {rule.name}: {val[:80]}")

        # Leak headers
        for h in _LEAK_HEADERS:
            val = self.headers.get(h, "")
            if val:
                findings.append(HeaderFinding(
                    header="!" + h, present=True, value=val[:200],
                    severity="MEDIUM",
                    message=f"Information disclosure: {h} reveals '{val}'",
                ))
                log.warn(f"  [MEDIUM] EXPOSED: {h}: {val}")

        score = max(0, 100 - deductions)
        return findings, score


# ══════════════════════════════════════════════════════════════════════════════
# Technology Fingerprinter
# ══════════════════════════════════════════════════════════════════════════════

_TECH_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "Server": [
        ("Apache",       r"Apache"),
        ("Nginx",        r"nginx"),
        ("IIS",          r"Microsoft-IIS"),
        ("LiteSpeed",    r"LiteSpeed"),
        ("Caddy",        r"Caddy"),
        ("Gunicorn",     r"gunicorn"),
        ("Tomcat",       r"Apache-Coyote|Tomcat"),
        ("OpenResty",    r"openresty"),
    ],
    "Framework": [
        ("Django",       r"csrftoken|djdt"),
        ("Laravel",      r"laravel_session|XSRF-TOKEN"),
        ("Rails",        r"_rails_session"),
        ("Express",      r"X-Powered-By.*Express"),
        ("ASP.NET",      r"ASP\.NET|__VIEWSTATE"),
        ("Spring",       r"JSESSIONID"),
        ("Flask",        r"Werkzeug"),
        ("WordPress",    r"wp-content|wp-includes|WordPress"),
        ("Drupal",       r"Drupal\.settings|drupal"),
        ("Joomla",       r"joomla|mosConfig"),
        ("Magento",      r"Mage\.Cookies|magento"),
        ("Shopify",      r"shopify|cdn\.shopify"),
        ("Ghost",        r"x-ghost-cache"),
        ("Strapi",       r"strapi"),
    ],
    "CDN": [
        ("Cloudflare",   r"CF-RAY|__cfduid|cloudflare"),
        ("AWS CloudFront",r"X-Cache.*CloudFront|via.*cloudfront"),
        ("Fastly",       r"X-Fastly|fastly"),
        ("Akamai",       r"X-Check-Cacheable|akamai"),
        ("Azure CDN",    r"X-Azure-Ref|azureedge"),
    ],
    "Security": [
        ("ModSecurity",  r"Mod_Security|NOYB"),
        ("Sucuri WAF",   r"sucuri"),
        ("Incapsula",    r"X-Iinfo|incap_ses"),
        ("AWS WAF",      r"AWS"),
    ],
}

class TechFingerprinter:
    def __init__(self, response: requests.Response, html: str = ""):
        self.resp    = response
        self.html    = html
        self.headers = response.headers

    def fingerprint(self) -> tuple[dict[str, list[str]], str, str]:
        """Returns (tech_dict, page_title, meta_generator)."""
        found: dict[str, list[str]] = {}

        # Combine all response text for pattern matching
        haystack = (
            " ".join(f"{k}: {v}" for k, v in self.headers.items()) + " " + self.html
        )

        for category, patterns in _TECH_SIGNATURES.items():
            for name, pattern in patterns:
                if re.search(pattern, haystack, re.I):
                    found.setdefault(category, [])
                    if name not in found[category]:
                        found[category].append(name)
                        log.info(f"  [TECH] {category} → {name}")

        # Server header
        server = self.headers.get("Server", "")
        if server and "Server" not in found:
            found["Server"] = [server]

        # Parse HTML for title and meta generator
        title, generator = "", ""
        if self.html:
            soup = BeautifulSoup(self.html, "html.parser")
            title_tag = soup.find("title")
            if title_tag:
                title = title_tag.get_text(strip=True)[:200]

            gen_tag = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
            if gen_tag and gen_tag.get("content"):
                generator = gen_tag["content"][:200]
                log.info(f"  Meta generator: {generator}")

        return found, title, generator


# ══════════════════════════════════════════════════════════════════════════════
# WAF Detector
# ══════════════════════════════════════════════════════════════════════════════

_WAF_SIGNATURES: list[tuple[str, str, str]] = [
    # (name, header, value_pattern)
    ("Cloudflare",        "Server",           r"cloudflare"),
    ("Cloudflare",        "CF-RAY",           r".+"),
    ("AWS WAF",           "X-AMZ-CF-ID",      r".+"),
    ("Imperva/Incapsula", "X-Iinfo",          r".+"),
    ("Imperva/Incapsula", "X-CDN",            r"Imperva"),
    ("Sucuri WAF",        "X-Sucuri-ID",      r".+"),
    ("F5 BIG-IP ASM",     "X-WA-Info",        r".+"),
    ("ModSecurity",       "X-Powered-By",     r""),
    ("Barracuda",         "Set-Cookie",       r"barra_counter_session"),
    ("Akamai",            "X-Akamai-Session", r".+"),
    ("Fortinet",          "FORTIWAFSID",      r".+"),
    ("Radware",           "X-SL-CompState",   r".+"),
    ("StackPath",         "X-SP-CC",          r".+"),
    ("Reblaze",           "rbzid",            r".+"),
]

class WAFDetector:
    def __init__(self, session: requests.Session, base_url: str):
        self.session  = session
        self.base_url = base_url

    def detect(self) -> str:
        try:
            # Normal request
            r = self.session.get(self.base_url, timeout=cfg.web.timeout, verify=False)
            for name, header, pattern in _WAF_SIGNATURES:
                val = r.headers.get(header, "")
                if val and (not pattern or re.search(pattern, val, re.I)):
                    log.info(f"  WAF detected: {name}  ({header}: {val[:60]})")
                    return name

            # Probe with a malicious-looking payload (triggers WAF block)
            probe_url = self.base_url + "/?id=1'%20OR%20'1'='1"
            rp = self.session.get(probe_url, timeout=cfg.web.timeout, verify=False)
            if rp.status_code in (403, 406, 429, 503):
                log.info(f"  WAF suspected — probe returned HTTP {rp.status_code}")
                return f"Unknown WAF (HTTP {rp.status_code} on probe)"

        except Exception as e:
            log.debug(f"  WAF detection error: {e}")

        log.info("  No WAF detected")
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# CORS Analyzer
# ══════════════════════════════════════════════════════════════════════════════

class CORSAnalyzer:
    def __init__(self, session: requests.Session, base_url: str):
        self.session  = session
        self.base_url = base_url

    def analyze(self) -> CORSFinding:
        finding = CORSFinding()
        test_origins = [
            "https://evil.r3conx.io",
            "null",
            f"https://{urlparse(self.base_url).hostname}.evil.io",
        ]

        for origin in test_origins:
            try:
                r = self.session.get(
                    self.base_url,
                    headers={"Origin": origin},
                    timeout=cfg.web.timeout,
                    verify=False,
                )
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")

                if not acao:
                    continue

                finding.origin_tested   = origin
                finding.acao_header     = acao
                finding.acac_header     = acac
                finding.wildcard        = acao == "*"
                finding.reflects_origin = acao == origin
                finding.allows_creds    = acac.lower() == "true"

                if finding.reflects_origin and finding.allows_creds:
                    finding.severity = "CRITICAL"
                    finding.detail   = "CORS reflects arbitrary origin with credentials — full cross-site request forgery possible"
                elif finding.reflects_origin:
                    finding.severity = "HIGH"
                    finding.detail   = "CORS reflects arbitrary origin — cross-site data theft possible"
                elif finding.wildcard and finding.allows_creds:
                    finding.severity = "HIGH"
                    finding.detail   = "CORS wildcard with credentials (browser ignores ACAC but misconfigured)"
                elif finding.wildcard:
                    finding.severity = "MEDIUM"
                    finding.detail   = "CORS wildcard — any origin may read public responses"
                else:
                    finding.severity = "INFO"
                    finding.detail   = f"CORS restricted to: {acao}"

                if finding.severity in ("CRITICAL", "HIGH"):
                    log.warn(f"  [{finding.severity}] CORS: {finding.detail}")
                else:
                    log.info(f"  CORS: {finding.detail}")
                break

            except Exception:
                continue

        return finding


# ══════════════════════════════════════════════════════════════════════════════
# Cookie Auditor
# ══════════════════════════════════════════════════════════════════════════════

class CookieAuditor:
    def __init__(self, response: requests.Response):
        self.response = response

    def audit(self) -> list[CookieFinding]:
        findings: list[CookieFinding] = []
        # requests.CaseInsensitiveDict has no get_all(); urllib3 raw headers do
        raw_cookies = (
            self.response.raw.headers.getlist("Set-Cookie")
            if hasattr(self.response.raw, "headers")
            and hasattr(self.response.raw.headers, "getlist")
            else []
        )

        for raw in raw_cookies:
            parts    = [p.strip() for p in raw.split(";")]
            name     = parts[0].split("=")[0].strip() if parts else "unknown"
            attrs    = {p.split("=")[0].lower().strip() for p in parts[1:]}
            samesite = next(
                (p.split("=")[1].strip() for p in parts[1:]
                 if p.lower().strip().startswith("samesite")),
                ""
            )

            cf = CookieFinding(
                name      = name,
                secure    = "secure"   in attrs,
                http_only = "httponly" in attrs,
                same_site = samesite,
            )

            if not cf.secure:
                cf.issues.append("Missing Secure flag — cookie sent over HTTP")
            if not cf.http_only:
                cf.issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
            if not samesite:
                cf.issues.append("Missing SameSite — CSRF risk")
            elif samesite.lower() == "none" and not cf.secure:
                cf.issues.append("SameSite=None without Secure is invalid")

            findings.append(cf)
            status = "[green]OK[/green]" if not cf.issues else "[yellow]ISSUES[/yellow]"
            log.info(f"  Cookie {status}: {name}  Secure={cf.secure} HttpOnly={cf.http_only} SameSite={samesite or '—'}")

        return findings


# ══════════════════════════════════════════════════════════════════════════════
# Content Discovery (directory + sensitive-file brute-force)
# ══════════════════════════════════════════════════════════════════════════════

_DIR_WORDLIST: list[str] = [
    # ── Admin / Login ────────────────────────────────────────────────────────
    "admin","administrator","admin.php","admin.html","admin.asp","admin.aspx",
    "admin/login","admin/index","admin/dashboard","admin/users","admin/config",
    "login","login.php","login.html","login.asp","login.aspx","signin","sign-in",
    "dashboard","manage","management","manager","panel","control","console","portal",
    "controlpanel","control-panel","siteadmin","site-admin","webadmin","web-admin",
    "wp-admin","wp-login.php","wp-config.php","wp-json","xmlrpc.php","wp-cron.php",
    "phpmyadmin","pma","myadmin","mysql","dbadmin","db","mysqladmin","pgadmin",
    "adminer","adminer.php","cpanel","webmail","roundcube","squirrelmail","horde",
    "magento","mage","Magento_Backend","backend","backoffice","back-office",
    # ── API ──────────────────────────────────────────────────────────────────
    "api","api/v1","api/v2","api/v3","api/v4","api/index","api/status",
    "api/users","api/user","api/login","api/auth","api/token","api/keys",
    "rest","rest/v1","rest/v2","graphql","graphiql","gql",
    "swagger","swagger-ui","swagger-ui.html","swagger.json","swagger.yaml",
    "api-docs","openapi.json","openapi.yaml","redoc","redoc.html",
    "v1","v2","v3","v1/api","v2/api",
    "rpc","jsonrpc","xmlrpc","soap","wsdl","service.asmx","service.svc",
    # ── Dev / Staging ────────────────────────────────────────────────────────
    "dev","development","staging","stage","test","testing","testsite",
    "beta","alpha","qa","uat","demo","sandbox","local","preview","preprod",
    "internal","intranet","private","hidden","secret","temp","tmp",
    # ── Sensitive config / secrets ───────────────────────────────────────────
    ".env",".env.backup",".env.local",".env.production",".env.development",
    ".env.staging",".env.test",".env.example",".env.sample","env.js","env.json",
    ".git",".git/config",".git/HEAD",".git/index",".git/COMMIT_EDITMSG",
    ".git/logs/HEAD",".git/refs/heads/master",".git/refs/heads/main",
    ".svn",".svn/entries",".svn/wc.db",".hg",".hg/hgrc",".bzr",".bzrignore",
    ".htaccess",".htpasswd",".htpasswd.bak",
    "web.config","applicationHost.config","IIS.config",
    "config","config.php","config.inc.php","configuration.php","configure.php",
    "config.yml","config.yaml","config.json","config.xml","config.ini","config.cfg",
    "settings.py","settings.php","settings.yml","settings.json","settings.local.php",
    "database.yml","database.php","database.json","db.php","db.yml",
    "wp-config.php","wp-config-sample.php","LocalSettings.php","parameters.yml",
    "application.properties","application.yml","application.yaml",
    "secrets.yml","secrets.json","credentials.json","credentials.xml",
    "key.pem","private.key","server.key","id_rsa","id_rsa.pub","known_hosts",
    ".npmrc",".yarnrc",".docker/config.json","docker-credentials",
    "phpinfo.php","info.php","test.php","i.php","check.php","probe.php",
    "install.php","setup.php","upgrade.php","update.php","migrate.php",
    # ── Backup / Archive ─────────────────────────────────────────────────────
    "backup","backups","backup.php","backup.zip","backup.tar.gz","backup.tar",
    "backup.sql","backup.db","backup.bak","db.sql","dump.sql","database.sql",
    "site.zip","website.zip","www.zip","html.zip","source.zip","code.zip",
    "old","old.php","bak","bak.php","orig","original","_old","_bak","_backup",
    "archive","archives","data.zip","export.sql","full-backup.zip",
    # ── Logs / Debug ─────────────────────────────────────────────────────────
    "logs","log","logs/","error.log","access.log","debug.log","app.log",
    "application.log","server.log","system.log","php_error.log","laravel.log",
    "logs/error.log","logs/access.log","logs/debug.log","logs/app.log",
    "log/error.log","log/access.log","storage/logs/laravel.log",
    "var/log","var/logs","tmp/logs","tmp/log",
    # ── Upload / Files ───────────────────────────────────────────────────────
    "upload","uploads","file","files","media","content","data","attachments",
    "static","assets","public","resources","storage","store","warehouse",
    "images","img","pics","pictures","photos","thumbnails","thumb",
    "js","css","fonts","font","icons","icon","svg","videos","video","audio",
    "vendor","node_modules","bower_components","lib","libs","library","libraries",
    "dist","build","compiled","bundle","bundles","min","minified",
    # ── Framework / CMS paths ────────────────────────────────────────────────
    # WordPress
    "wp-content","wp-content/uploads","wp-includes","wp-json/wp/v2/users",
    # Laravel / Symfony / Django
    "public/storage","storage/app/public","artisan","console",
    "_profiler","_wdt","app_dev.php","app.php",
    "__debugbar","__clockwork","telescope","horizon",
    # Rails
    "rails/info","rails/info/properties","rails/mailers","rails/routes",
    # Node
    "package.json","package-lock.json","yarn.lock",".nvmrc",
    # Python
    "requirements.txt","Pipfile","Pipfile.lock","pyproject.toml","setup.py",
    # PHP
    "composer.json","composer.lock","artisan","phpunit.xml",
    # Java
    "WEB-INF/web.xml","WEB-INF/classes","META-INF/MANIFEST.MF",
    "struts.xml","applicationContext.xml","spring","spring-security.xml",
    # .NET
    "App_Data","App_Code","bin/web.config","Global.asax","Web.Debug.config",
    # ── Spring Boot Actuator ──────────────────────────────────────────────────
    "actuator","actuator/health","actuator/env","actuator/mappings",
    "actuator/beans","actuator/info","actuator/metrics","actuator/dump",
    "actuator/trace","actuator/loggers","actuator/heapdump","actuator/threaddump",
    "actuator/shutdown","actuator/refresh","actuator/restart",
    # ── Cloud / Container / DevOps ───────────────────────────────────────────
    "jenkins","jenkins/api/json","gitlab","github",
    ".travis.yml","circle.yml",".circleci/config.yml","Dockerfile",
    "docker-compose.yml","docker-compose.override.yml",
    "kubernetes","k8s","helm","terraform","ansible","chef","puppet",
    "Jenkinsfile","Makefile","Gruntfile.js","Gulpfile.js","webpack.config.js",
    ".github/workflows","Vagrantfile","Procfile",
    # ── Monitoring / Infra ───────────────────────────────────────────────────
    "grafana","kibana","prometheus","alertmanager","consul","vault",
    "portainer","rancher","traefik","nginx-status","server-status","server-info",
    "metrics","health","healthz","readyz","livez","status","ping","alive",
    "_health","_status","_metrics","health-check","healthcheck",
    # ── OIDC / SSO ───────────────────────────────────────────────────────────
    ".well-known/openid-configuration",".well-known/jwks.json",
    ".well-known/security.txt",".well-known/oauth-authorization-server",
    "oauth","oauth/token","oauth/authorize","oauth2","openid","saml","sso",
    "auth","auth/login","auth/token","auth/callback","auth/logout",
    "connect/token","connect/authorize","connect/userinfo",
    # ── Standard well-known files ────────────────────────────────────────────
    "robots.txt","sitemap.xml","sitemap.txt","sitemap_index.xml","humans.txt",
    "security.txt","ads.txt","app-ads.txt","sellers.json",
    "favicon.ico","apple-touch-icon.png","browserconfig.xml","manifest.json",
    "crossdomain.xml","clientaccesspolicy.xml","BingSiteAuth.xml",
    # ── Documentation / Leaks ────────────────────────────────────────────────
    "docs","doc","documentation","wiki","wiki/","confluence","readme",
    "README.md","README.txt","CHANGELOG.md","CHANGELOG","RELEASE_NOTES.md",
    "LICENSE","TODO","INSTALL","COPYING","AUTHORS","CONTRIBUTORS",
    "swagger/index.html","help","faq","support",
    # ── E-commerce / App-specific ────────────────────────────────────────────
    "shop","store","cart","checkout","orders","order","invoice","payment",
    "account","accounts","profile","user","users","register","signup","sign-up",
    "forgot-password","reset-password","change-password","2fa","mfa",
    "crm","erp","hr","hrm","ldap","directory",
    # ── Search / Data exposure ───────────────────────────────────────────────
    "search","elasticsearch","solr","kibana","_cat/indices","_cluster/health",
    "redis","memcache","mongodb","couchdb","_all_dbs","_utils",
    # ── Misc high-value ──────────────────────────────────────────────────────
    "cgi-bin","cgi-bin/admin.cgi","cgi-bin/printenv","cgi-bin/test-cgi",
    "server","server-status","server-info","nginx_status","fpm-status",
    "trace","debug","error","exception","stack","stacktrace",
    ".DS_Store","Thumbs.db","desktop.ini",
    "sitemap","feed","rss","atom","rss.xml","atom.xml","feed.xml",
]

_SENSITIVE_INDICATORS = {
    ".env", ".git", ".svn", ".htpasswd", "web.config", "phpinfo",
    "backup", ".sql", "password", "secret", "private", "credentials",
    "token", ".key", ".pem", "config.php", "database",
}

_INTERESTING_STATUS = {200, 201, 301, 302, 307, 401, 403}


class ContentDiscovery:
    def __init__(self, session: requests.Session, base_url: str,
                 threads: int = cfg.web.dir_threads):
        self.session  = session
        self.base_url = base_url.rstrip("/")
        self.threads  = threads
        self._lock    = threading.Lock()

    def _probe(self, path: str) -> DirectoryHit | None:
        url = f"{self.base_url}/{path}"
        try:
            r = self.session.get(
                url, timeout=5.0, verify=False,
                allow_redirects=False,
            )
            if r.status_code not in _INTERESTING_STATUS:
                return None

            redirect_to = r.headers.get("Location", "") if r.is_redirect else ""
            size        = len(r.content)
            sensitive   = any(s in path.lower() for s in _SENSITIVE_INDICATORS)

            note = ""
            if r.status_code == 401:
                note = "Auth required"
            elif r.status_code == 403:
                note = "Access forbidden (exists)"
            elif sensitive and r.status_code == 200:
                note = "SENSITIVE FILE EXPOSED"

            return DirectoryHit(
                url=url, status=r.status_code,
                size=size, redirect_to=redirect_to,
                sensitive=sensitive, note=note,
            )
        except Exception:
            return None

    def run(self, progress: Progress | None = None) -> tuple[list[DirectoryHit], list[DirectoryHit]]:
        hits: list[DirectoryHit]      = []
        sensitive: list[DirectoryHit] = []

        task = None
        if progress:
            task = progress.add_task(
                "  [cyan]Directory brute-force[/cyan]",
                total=len(_DIR_WORDLIST),
            )

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe, p): p for p in _DIR_WORDLIST}
            for fut in as_completed(futures):
                hit = fut.result()
                if hit:
                    with self._lock:
                        hits.append(hit)
                        if hit.sensitive:
                            sensitive.append(hit)
                        sev  = "[red]SENSITIVE[/red]" if hit.sensitive else f"HTTP {hit.status}"
                        log.info(f"  [{sev}] {hit.url}  ({hit.size}B)  {hit.note}")
                if progress and task is not None:
                    progress.advance(task)

        if progress and task is not None:
            progress.update(task, description=f"  [green]Dir brute-force done — {len(hits)} found[/green]")

        return hits, sensitive


# ══════════════════════════════════════════════════════════════════════════════
# Robots / Sitemap Parser
# ══════════════════════════════════════════════════════════════════════════════

class RobotsSitemapParser:
    def __init__(self, session: requests.Session, base_url: str):
        self.session  = session
        self.base_url = base_url

    def parse_robots(self) -> tuple[str, list[str]]:
        url = f"{self.base_url}/robots.txt"
        try:
            r = self.session.get(url, timeout=cfg.web.timeout, verify=False)
            if r.status_code != 200:
                return "", []
            text = r.text
            disallowed = re.findall(r"^Disallow:\s*(.+)", text, re.I | re.M)
            disallowed = [d.strip() for d in disallowed if d.strip() and d.strip() != "/"]
            log.info(f"  robots.txt: {len(disallowed)} Disallow entries")
            for d in disallowed[:10]:
                log.info(f"    Disallow: {d}")
            return text[:3000], disallowed
        except Exception:
            return "", []

    def parse_sitemap(self) -> list[str]:
        urls: list[str] = []
        for path in ("sitemap.xml", "sitemap_index.xml", "sitemap.txt"):
            try:
                r = self.session.get(f"{self.base_url}/{path}",
                                      timeout=cfg.web.timeout, verify=False)
                if r.status_code != 200:
                    continue
                found = re.findall(r"<loc>(.*?)</loc>", r.text, re.I)
                urls.extend(found[:50])
                log.info(f"  sitemap.xml: {len(found)} URLs found")
                break
            except Exception:
                continue
        return urls


# ══════════════════════════════════════════════════════════════════════════════
# HTTP Method Prober
# ══════════════════════════════════════════════════════════════════════════════

_ALL_METHODS   = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD","TRACE","CONNECT"]
_DANGEROUS     = {"PUT","DELETE","TRACE","CONNECT"}

class HTTPMethodProber:
    def __init__(self, session: requests.Session, base_url: str):
        self.session  = session
        self.base_url = base_url

    def probe(self) -> tuple[list[str], list[str]]:
        allowed:   list[str] = []
        dangerous: list[str] = []

        # OPTIONS first — server may declare allowed methods
        try:
            r = self.session.options(self.base_url, timeout=cfg.web.timeout, verify=False)
            opts = r.headers.get("Allow", "")
            if opts:
                declared = [m.strip() for m in opts.split(",")]
                log.info(f"  OPTIONS Allow: {', '.join(declared)}")
                for m in declared:
                    allowed.append(m)
                    if m.upper() in _DANGEROUS:
                        dangerous.append(m)
                        log.warn(f"  [HIGH] Dangerous method enabled: {m}")
                return allowed, dangerous
        except Exception:
            pass

        # Manual probe for each method
        for method in _ALL_METHODS:
            try:
                r = self.session.request(
                    method, self.base_url,
                    timeout=cfg.web.timeout, verify=False,
                )
                if r.status_code not in (405, 501):
                    allowed.append(method)
                    if method in _DANGEROUS:
                        dangerous.append(method)
                        log.warn(f"  [HIGH] Dangerous method active: {method} → HTTP {r.status_code}")
            except Exception:
                pass

        return allowed, dangerous


# ══════════════════════════════════════════════════════════════════════════════
# Output tables
# ══════════════════════════════════════════════════════════════════════════════

def _print_header_table(findings: list[HeaderFinding], score: int) -> None:
    score_colour = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
    t = Table(
        title=f"Security Headers  (score: [{score_colour}]{score}/100[/{score_colour}])",
        box=box.ROUNDED, border_style="cyan", header_style="bold cyan",
    )
    t.add_column("Header",   style="bold white",  overflow="fold", width=35)
    t.add_column("Status",   width=8)
    t.add_column("Severity", width=10)
    t.add_column("Detail",   overflow="fold")

    sev_col = {"CRITICAL":"red","HIGH":"magenta","MEDIUM":"yellow","LOW":"cyan","INFO":"dim","":"green"}
    for f in findings:
        status  = "[green]OK[/green]"   if f.present else "[red]MISSING[/red]"
        sc      = sev_col.get(f.severity, "white")
        sev_str = f"[{sc}]{f.severity}[/{sc}]" if f.severity else ""
        t.add_row(f.header, status, sev_str, f.message or f.value[:80])
    _console.print(t)


def _print_dir_table(hits: list[DirectoryHit]) -> None:
    if not hits:
        return
    hits_sorted = sorted(hits, key=lambda h: (not h.sensitive, h.status))
    t = Table(title=f"Discovered Paths ({len(hits)})",
              box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
    t.add_column("Status",  width=8)
    t.add_column("Size",    width=8, style="dim")
    t.add_column("URL",     overflow="fold")
    t.add_column("Note",    overflow="fold")

    for h in hits_sorted[:60]:
        sc = {"200":"green","401":"yellow","403":"yellow","301":"cyan","302":"cyan"}.get(str(h.status),"white")
        note_col = f"[red]{h.note}[/red]" if h.sensitive else h.note
        t.add_row(f"[{sc}]{h.status}[/{sc}]", str(h.size), h.url, note_col)
    _console.print(t)


def _print_tls_table(tls: TLSCert) -> None:
    if not tls.subject:
        return
    t = Table(title="TLS Certificate", box=box.ROUNDED,
              border_style="cyan", header_style="bold cyan")
    t.add_column("Field",  style="bold white", width=18)
    t.add_column("Value",  overflow="fold")

    exp_str = f"{tls.days_remaining}d"
    exp_col = "red" if tls.expired else ("yellow" if tls.days_remaining < 30 else "green")
    t.add_row("Subject",     tls.subject)
    t.add_row("Issuer",      tls.issuer)
    t.add_row("TLS Version", tls.tls_version)
    t.add_row("Cipher",      tls.cipher)
    t.add_row("Not Before",  tls.not_before)
    t.add_row("Not After",   tls.not_after)
    t.add_row("Days Left",   f"[{exp_col}]{exp_str}[/{exp_col}]")
    t.add_row("Self-Signed", "[red]YES[/red]" if tls.self_signed else "[green]NO[/green]")
    t.add_row("SANs",        ", ".join(tls.san[:8]) + ("…" if len(tls.san) > 8 else ""))
    _console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

class WebEnum:
    """
    Orchestrates all web enumeration sub-engines against the target.
    """

    def __init__(self, target: str):
        self.target  = target
        self.session = _build_session()

    def run(self) -> dict:
        result  = WebResult(target=self.target)

        # ── Connectivity ──────────────────────────────────────────────────────
        probe = ConnectivityProbe(self.target, self.session)
        base_url, response = probe.detect()

        if not base_url or response is None:
            log.warn("No web service detected — skipping web enumeration.")
            return result.to_dict()

        result.base_url    = base_url
        result.scheme      = urlparse(base_url).scheme
        result.status_code = response.status_code
        result.server      = response.headers.get("Server", "")
        result.redirect_chain = probe.redirect_chain(base_url)

        html = response.text

        progress = Progress(
            SpinnerColumn("dots2"),
            TextColumn("{task.description}"),
            BarColumn(bar_width=26, style="cyan", complete_style="green"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=_console,
            transient=False,
        )

        with progress:

            # ── TLS inspection ────────────────────────────────────────────────
            if result.scheme == "https":
                t = progress.add_task("  [cyan]TLS inspection[/cyan]", total=None)
                host = urlparse(base_url).hostname or self.target
                result.tls = TLSInspector(host).inspect()
                progress.update(t, total=1, completed=1,
                                description="  [green]TLS done[/green]")

            # ── Security headers ──────────────────────────────────────────────
            t = progress.add_task("  [cyan]Security header analysis[/cyan]", total=None)
            result.headers, result.header_score = HeaderAnalyzer(response).analyze()
            progress.update(t, total=1, completed=1,
                            description=f"  [green]Headers done (score {result.header_score}/100)[/green]")

            # ── Technology fingerprinting ─────────────────────────────────────
            t = progress.add_task("  [cyan]Technology fingerprinting[/cyan]", total=None)
            result.technologies, result.page_title, result.meta_generator = \
                TechFingerprinter(response, html).fingerprint()
            progress.update(t, total=1, completed=1,
                            description="  [green]Tech fingerprinting done[/green]")

            # ── WAF detection ─────────────────────────────────────────────────
            t = progress.add_task("  [cyan]WAF detection[/cyan]", total=None)
            result.waf = WAFDetector(self.session, base_url).detect()
            progress.update(t, total=1, completed=1,
                            description="  [green]WAF detection done[/green]")

            # ── CORS analysis ─────────────────────────────────────────────────
            t = progress.add_task("  [cyan]CORS analysis[/cyan]", total=None)
            result.cors = CORSAnalyzer(self.session, base_url).analyze()
            progress.update(t, total=1, completed=1,
                            description="  [green]CORS done[/green]")

            # ── Cookie audit ──────────────────────────────────────────────────
            t = progress.add_task("  [cyan]Cookie audit[/cyan]", total=None)
            result.cookies = CookieAuditor(response).audit()
            progress.update(t, total=1, completed=1,
                            description="  [green]Cookie audit done[/green]")

            # ── robots.txt + sitemap ──────────────────────────────────────────
            t = progress.add_task("  [cyan]Robots.txt / Sitemap[/cyan]", total=None)
            rsp = RobotsSitemapParser(self.session, base_url)
            result.robots_txt, result.disallowed_paths = rsp.parse_robots()
            result.sitemap_urls = rsp.parse_sitemap()
            progress.update(t, total=1, completed=1,
                            description="  [green]Robots/Sitemap done[/green]")

            # ── HTTP method probing ───────────────────────────────────────────
            t = progress.add_task("  [cyan]HTTP method probing[/cyan]", total=None)
            result.allowed_methods, result.dangerous_methods = \
                HTTPMethodProber(self.session, base_url).probe()
            progress.update(t, total=1, completed=1,
                            description="  [green]HTTP methods done[/green]")

            # ── Directory brute-force ─────────────────────────────────────────
            disc = ContentDiscovery(self.session, base_url)
            all_hits, sens = disc.run(progress)
            result.directories     = all_hits
            result.sensitive_files = sens

            # ── Nikto (optional — only if installed) ──────────────────────────
            import shutil, subprocess, json as _json
            if shutil.which("nikto"):
                t = progress.add_task("  [cyan]Nikto vulnerability scan[/cyan]", total=None)
                try:
                    proc = subprocess.run(
                        ["nikto", "-h", base_url, "-Format", "json",
                         "-nointeractive", "-timeout", "5", "-Tuning", "x6"],
                        capture_output=True, text=True, timeout=120,
                    )
                    # Nikto JSON output is one object per line
                    nikto_findings: list[str] = []
                    for line in proc.stdout.splitlines():
                        line = line.strip()
                        if not line.startswith("{"):
                            continue
                        try:
                            obj = _json.loads(line)
                            for vuln in obj.get("vulnerabilities", []):
                                msg = vuln.get("msg", "")
                                if msg:
                                    nikto_findings.append(msg)
                                    log.warn(f"  [Nikto] {msg[:120]}")
                        except _json.JSONDecodeError:
                            pass
                    result.nikto_findings = nikto_findings
                    progress.update(t, total=1, completed=1,
                                    description=f"  [green]Nikto done — {len(nikto_findings)} findings[/green]")
                except Exception as e:
                    log.warn(f"  Nikto failed: {e}")
                    progress.update(t, total=1, completed=1,
                                    description="  [yellow]Nikto failed[/yellow]")

        # ── Print result tables ───────────────────────────────────────────────
        _print_tls_table(result.tls)
        _print_header_table(result.headers, result.header_score)
        _print_dir_table(result.directories)

        log.success(
            f"Web enum complete — "
            f"headers={result.header_score}/100  "
            f"dirs={len(result.directories)}  "
            f"sensitive={len(result.sensitive_files)}  "
            f"waf={result.waf or 'none'}"
        )

        return result.to_dict()
