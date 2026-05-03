"""
Stage 5 — CVE Correlation Engine
Maps discovered services → CVEs with full CVSS v3 metrics.

Sub-components:
  NVDClient       — NVD API v2 with pagination, retry, rate-limiting
  CVECache        — SQLite-backed TTL cache (avoids duplicate API calls)
  CPEMatcher      — CPE-string-based precise CVE lookup (from Nmap output)
  KeywordMatcher  — Product+version keyword fallback
  ExploitChecker  — Detects exploit references (ExploitDB, Metasploit, PoC-in-GitHub)
  CVSSParser      — Full CVSS v3.1/v3.0/v2.0 vector + metric extraction
  Deduplicator    — Cross-port CVE deduplication with port-list merging
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field, asdict
from itertools import zip_longest

import requests
from rich.console import Console
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich import box

from utils.logger import log
from utils.decorators import retry, RateLimiter
from utils.exceptions import CVELookupError, RateLimitError
from config import cfg

_console  = Console(highlight=False)
_DB_PATH  = os.path.join(cfg.output_dir, ".cve_cache.db")


# ══════════════════════════════════════════════════════════════════════════════
# Data models
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CVSSMetrics:
    version:               str   = ""
    vector_string:         str   = ""
    base_score:            float = 0.0
    base_severity:         str   = ""
    # v3 specific
    attack_vector:         str   = ""   # NETWORK | ADJACENT | LOCAL | PHYSICAL
    attack_complexity:     str   = ""   # LOW | HIGH
    privileges_required:   str   = ""   # NONE | LOW | HIGH
    user_interaction:      str   = ""   # NONE | REQUIRED
    scope:                 str   = ""   # UNCHANGED | CHANGED
    confidentiality_impact:str   = ""   # NONE | LOW | HIGH
    integrity_impact:      str   = ""   # NONE | LOW | HIGH
    availability_impact:   str   = ""   # NONE | LOW | HIGH
    exploitability_score:  float = 0.0
    impact_score:          float = 0.0


@dataclass
class ExploitRef:
    source:    str    # 'exploitdb' | 'metasploit' | 'github' | 'packetstorm' | 'other'
    url:       str
    label:     str


@dataclass
class CVERecord:
    cve_id:          str
    description:     str               = ""
    published:       str               = ""
    last_modified:   str               = ""
    cvss:            CVSSMetrics       = field(default_factory=CVSSMetrics)
    cwe:             list[str]         = field(default_factory=list)
    references:      list[str]         = field(default_factory=list)
    exploits:        list[ExploitRef]  = field(default_factory=list)
    has_exploit:     bool              = False
    # correlation metadata
    matched_port:    int               = 0
    matched_ports:   list[int]         = field(default_factory=list)
    matched_service: str               = ""
    matched_product: str               = ""
    matched_version: str               = ""
    match_source:    str               = ""   # 'cpe' | 'keyword'
    risk_level:      str               = ""   # filled by RiskEngine

    @property
    def score(self) -> float:
        return self.cvss.base_score

    @property
    def severity(self) -> str:
        return self.cvss.base_severity or cfg.risk.classify(self.score)

    @property
    def network_exploitable(self) -> bool:
        return self.cvss.attack_vector == "NETWORK"

    @property
    def no_auth_required(self) -> bool:
        return self.cvss.privileges_required == "NONE"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"]               = self.score
        d["severity"]            = self.severity
        d["network_exploitable"] = self.network_exploitable
        d["no_auth_required"]    = self.no_auth_required
        return d


# ══════════════════════════════════════════════════════════════════════════════
# SQLite CVE Cache
# ══════════════════════════════════════════════════════════════════════════════

class CVECache:
    """
    Thread-safe SQLite cache.
    Key   = SHA-256 of the query string.
    Value = JSON-serialised API response.
    TTL   = cfg.cve.cache_ttl seconds (default 1 hour).
    """

    def __init__(self, db_path: str = _DB_PATH, ttl: int = cfg.cve.cache_ttl):
        self._path = db_path
        self._ttl  = ttl
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key       TEXT PRIMARY KEY,
                    value     TEXT NOT NULL,
                    cached_at INTEGER NOT NULL
                )
            """)
            conn.commit()
            conn.close()

    def _key(self, query: str) -> str:
        return hashlib.sha256(query.encode()).hexdigest()

    def get(self, query: str) -> list[dict] | None:
        k = self._key(query)
        with self._lock:
            conn = self._connect()
            row  = conn.execute(
                "SELECT value, cached_at FROM cache WHERE key = ?", (k,)
            ).fetchone()
            conn.close()

        if not row:
            return None
        value, cached_at = row
        age = int(time.time()) - cached_at
        if age > self._ttl:
            self.delete(query)
            return None
        log.debug(f"Cache HIT: {query[:60]}  (age {age}s)")
        return json.loads(value)

    def set(self, query: str, data: list[dict]) -> None:
        k = self._key(query)
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT OR REPLACE INTO cache(key, value, cached_at) VALUES (?,?,?)",
                (k, json.dumps(data), int(time.time())),
            )
            conn.commit()
            conn.close()

    def delete(self, query: str) -> None:
        k = self._key(query)
        with self._lock:
            conn = self._connect()
            conn.execute("DELETE FROM cache WHERE key = ?", (k,))
            conn.commit()
            conn.close()

    def purge_expired(self) -> int:
        threshold = int(time.time()) - self._ttl
        with self._lock:
            conn = self._connect()
            cur  = conn.execute(
                "DELETE FROM cache WHERE cached_at < ?", (threshold,)
            )
            count = cur.rowcount
            conn.commit()
            conn.close()
        return count


# ══════════════════════════════════════════════════════════════════════════════
# NVD API v2 Client
# ══════════════════════════════════════════════════════════════════════════════

class NVDClient:
    """
    NVD CVE API 2.0 client.
    Rate limits: 5 req/30s without API key, 50 req/30s with key.
    Implements pagination (resultsPerPage max=2000), retry, and caching.
    """

    _BASE = cfg.cve.api_url
    _PER_PAGE = min(cfg.cve.results_per_page, 20)

    def __init__(self, cache: CVECache):
        self._cache   = cache
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": cfg.web.user_agent})
        if cfg.cve.api_key:
            self._session.headers["apiKey"] = cfg.cve.api_key

        # Rate limiter: 5/30s without key, 50/30s with key
        rps = cfg.cve.rate_limit_rps if cfg.cve.api_key else 0.15
        self._limiter = RateLimiter(calls=1, period=1.0 / rps)

    @retry(max_attempts=4, delay=3.0, backoff=2.0,
           exceptions=(requests.RequestException, CVELookupError))
    def _get(self, params: dict) -> dict:
        cache_key = json.dumps(params, sort_keys=True)
        cached    = self._cache.get(cache_key)
        if cached is not None:
            return {"vulnerabilities": cached, "__cached": True}

        self._limiter(lambda: None)()   # apply rate limit

        try:
            r = self._session.get(
                self._BASE, params=params,
                timeout=cfg.web.timeout,
            )
        except requests.exceptions.Timeout:
            raise CVELookupError("NVD API timed out")
        except requests.exceptions.ConnectionError as e:
            raise CVELookupError("NVD API unreachable", detail=str(e))

        if r.status_code == 403:
            raise CVELookupError("NVD API key invalid or IP blocked")
        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", 30))
            log.warn(f"  NVD rate-limited — sleeping {retry_after}s")
            time.sleep(retry_after)
            raise RateLimitError("NVD rate limit hit")
        if r.status_code != 200:
            raise CVELookupError(f"NVD API returned HTTP {r.status_code}")

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        self._cache.set(cache_key, vulns)
        return data

    def query_cpe(self, cpe_string: str) -> list[dict]:
        """Precise lookup by CPE URI — best accuracy."""
        params = {
            "cpeName":        cpe_string,
            "resultsPerPage": self._PER_PAGE,
            "startIndex":     0,
        }
        try:
            data = self._get(params)
            return data.get("vulnerabilities", [])
        except CVELookupError as e:
            log.warn(f"  NVD CPE query failed: {e}")
            return []

    def query_keyword(self, keyword: str) -> list[dict]:
        """Keyword-based lookup — broader, used as fallback."""
        params = {
            "keywordSearch":  keyword,
            "resultsPerPage": self._PER_PAGE,
            "startIndex":     0,
        }
        try:
            data = self._get(params)
            return data.get("vulnerabilities", [])
        except CVELookupError as e:
            log.warn(f"  NVD keyword query failed: {e}")
            return []

    def query_cve_id(self, cve_id: str) -> dict | None:
        """Fetch a single CVE by ID."""
        params = {"cveId": cve_id}
        try:
            data  = self._get(params)
            vulns = data.get("vulnerabilities", [])
            return vulns[0] if vulns else None
        except CVELookupError:
            return None


# ══════════════════════════════════════════════════════════════════════════════
# CVSS Parser
# ══════════════════════════════════════════════════════════════════════════════

# Maps CVSS v3 vector abbreviations to full names
_AV_MAP  = {"N":"NETWORK","A":"ADJACENT","L":"LOCAL","P":"PHYSICAL"}
_AC_MAP  = {"L":"LOW","H":"HIGH"}
_PR_MAP  = {"N":"NONE","L":"LOW","H":"HIGH"}
_UI_MAP  = {"N":"NONE","R":"REQUIRED"}
_SC_MAP  = {"U":"UNCHANGED","C":"CHANGED"}
_IMP_MAP = {"N":"NONE","L":"LOW","H":"HIGH"}

class CVSSParser:
    @staticmethod
    def parse(metrics_block: dict) -> CVSSMetrics:
        """
        Extract CVSS metrics from the NVD 'metrics' block.
        Prefers v3.1 > v3.0 > v2.0.
        """
        m = CVSSMetrics()

        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics_block.get(key, [])
            if not entries:
                continue
            entry     = entries[0]
            data      = entry.get("cvssData", {})
            m.version = data.get("version", "")
            m.vector_string         = data.get("vectorString", "")
            m.base_score            = float(data.get("baseScore", 0.0))
            m.base_severity         = data.get("baseSeverity", "").upper()
            m.exploitability_score  = float(entry.get("exploitabilityScore", 0.0))
            m.impact_score          = float(entry.get("impactScore", 0.0))

            if key in ("cvssMetricV31", "cvssMetricV30"):
                m.attack_vector          = data.get("attackVector", "")
                m.attack_complexity      = data.get("attackComplexity", "")
                m.privileges_required    = data.get("privilegesRequired", "")
                m.user_interaction       = data.get("userInteraction", "")
                m.scope                  = data.get("scope", "")
                m.confidentiality_impact = data.get("confidentialityImpact", "")
                m.integrity_impact       = data.get("integrityImpact", "")
                m.availability_impact    = data.get("availabilityImpact", "")
            else:
                # v2: parse from vector string AV:N/AC:L/...
                v = m.vector_string
                def _v2(tag: str, mp: dict) -> str:
                    match = re.search(rf"{tag}:([A-Z])", v)
                    return mp.get(match.group(1), "") if match else ""
                m.attack_vector          = _v2("AV",  _AV_MAP)
                m.attack_complexity      = _v2("AC",  _AC_MAP)
                m.privileges_required    = _v2("Au",  {"N":"NONE","S":"LOW","M":"HIGH"})
                m.confidentiality_impact = _v2("C",   _IMP_MAP)
                m.integrity_impact       = _v2("I",   _IMP_MAP)
                m.availability_impact    = _v2("A",   _IMP_MAP)
            break

        return m


# ══════════════════════════════════════════════════════════════════════════════
# Exploit Checker
# ══════════════════════════════════════════════════════════════════════════════

_EXPLOIT_SOURCES = {
    "exploit-db.com":        "exploitdb",
    "exploitdb.com":         "exploitdb",
    "metasploit.com":        "metasploit",
    "rapid7.com/db":         "metasploit",
    "github.com":            "github",
    "packetstormsecurity":   "packetstorm",
    "0day.today":            "0day",
    "vulhub":                "vulhub",
    "seclists.org":          "seclists",
}

class ExploitChecker:
    @staticmethod
    def extract(refs: list[dict]) -> tuple[list[ExploitRef], bool]:
        exploits: list[ExploitRef] = []
        for ref in refs:
            url  = ref.get("url", "")
            tags = [t.lower() for t in ref.get("tags", [])]

            # Tag-based detection
            is_exploit = any(t in tags for t in
                             ("exploit", "third-party-advisory", "vdb-entry"))

            # URL-based detection
            source = next(
                (v for k, v in _EXPLOIT_SOURCES.items() if k in url.lower()),
                ""
            )
            if source or is_exploit:
                exploits.append(ExploitRef(
                    source=source or "other",
                    url=url,
                    label=ref.get("source", "")[:60],
                ))

        return exploits, bool(exploits)


# ══════════════════════════════════════════════════════════════════════════════
# CPE Matcher
# ══════════════════════════════════════════════════════════════════════════════

class CPEMatcher:
    """
    Uses CPE strings from Nmap (e.g. 'cpe:/a:apache:http_server:2.4.51')
    to perform precise NVD CPE-based lookups.
    """

    def __init__(self, client: NVDClient):
        self._client = client

    def match(self, port_entry: dict) -> list[CVERecord]:
        cpes = port_entry.get("cpe", [])
        if not cpes:
            return []

        all_records: list[CVERecord] = []
        for cpe in cpes:
            if not cpe.startswith("cpe:"):
                continue
            log.debug(f"  CPE lookup: {cpe}")
            raw = self._client.query_cpe(cpe)
            for item in raw:
                rec = _parse_nvd_item(item, port_entry, match_source="cpe")
                if rec:
                    all_records.append(rec)

        return all_records


# ══════════════════════════════════════════════════════════════════════════════
# Keyword Matcher (fallback)
# ══════════════════════════════════════════════════════════════════════════════

# Products that produce too many false positives with generic version strings
_SKIP_KEYWORDS = {"tcpwrapped", "unknown", "generic", ""}

class KeywordMatcher:
    def __init__(self, client: NVDClient):
        self._client = client

    def _build_keyword(self, port_entry: dict) -> str | None:
        product = port_entry.get("product", "").strip()
        version = port_entry.get("version", "").strip()
        service = port_entry.get("service", "").strip()

        # Prefer product+version, fall back to product, then service
        if product.lower() not in _SKIP_KEYWORDS:
            return f"{product} {version}".strip() if version else product
        if service.lower() not in _SKIP_KEYWORDS:
            return service
        return None

    def match(self, port_entry: dict) -> list[CVERecord]:
        keyword = self._build_keyword(port_entry)
        if not keyword:
            return []

        log.debug(f"  Keyword lookup: {keyword!r}")
        raw = self._client.query_keyword(keyword)
        return [
            rec for item in raw
            if (rec := _parse_nvd_item(item, port_entry, match_source="keyword"))
        ]


# ══════════════════════════════════════════════════════════════════════════════
# Version range filter — eliminates false positives
# ══════════════════════════════════════════════════════════════════════════════

class VersionFilter:
    """
    Checks whether a detected product version falls inside a CVE's affected
    version ranges as declared in NVD configurations/CPE match criteria.
    Eliminates false positives like IIS-10 getting CVEs that only affect IIS-5.
    If no range data is present the CVE passes through (safe default).
    """

    @staticmethod
    def _parse(v: str) -> tuple[int, ...]:
        parts: list[int] = []
        for seg in re.split(r"[.\-_]", v.strip()):
            m = re.match(r"(\d+)", seg)
            if m:
                parts.append(int(m.group(1)))
            else:
                break
        return tuple(parts)

    @classmethod
    def _cmp(cls, a: tuple[int, ...], b: tuple[int, ...]) -> int:
        for x, y in zip_longest(a, b, fillvalue=0):
            if x < y: return -1
            if x > y: return  1
        return 0

    @classmethod
    def is_affected(cls, detected: str, item: dict) -> bool:
        """
        True  → version is in an affected range, or no range data available.
        False → range data exists and detected version is outside all ranges.
        """
        if not detected:
            return True
        det = cls._parse(detected)
        if not det:
            return True

        configurations = item.get("cve", {}).get("configurations", [])
        if not configurations:
            return True

        any_range = False
        for cfg_node in configurations:
            for node in cfg_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", True):
                        continue
                    vsi = match.get("versionStartIncluding", "")
                    vse = match.get("versionStartExcluding", "")
                    vei = match.get("versionEndIncluding",   "")
                    vee = match.get("versionEndExcluding",   "")
                    if not any((vsi, vse, vei, vee)):
                        continue
                    any_range = True
                    lo_ok = (cls._cmp(det, cls._parse(vsi)) >= 0 if vsi else
                             cls._cmp(det, cls._parse(vse)) >  0 if vse else True)
                    hi_ok = (cls._cmp(det, cls._parse(vei)) <= 0 if vei else
                             cls._cmp(det, cls._parse(vee)) <  0 if vee else True)
                    if lo_ok and hi_ok:
                        return True

        return not any_range   # range data found → no match → not affected


# ══════════════════════════════════════════════════════════════════════════════
# NVD item parser (shared)
# ══════════════════════════════════════════════════════════════════════════════

def _parse_nvd_item(item: dict, port_entry: dict,
                    match_source: str = "keyword") -> CVERecord | None:
    """Convert a raw NVD API vulnerability item → CVERecord."""
    cve_data = item.get("cve", {})
    cve_id   = cve_data.get("id", "")
    if not cve_id:
        return None

    # Version-range filter — drop CVEs that don't affect the detected version
    detected_ver = port_entry.get("version", "")
    if detected_ver and not VersionFilter.is_affected(detected_ver, item):
        log.debug(f"  Filtered {cve_id} — v{detected_ver} outside affected range")
        return None

    # English description
    desc = next(
        (d["value"] for d in cve_data.get("descriptions", [])
         if d.get("lang") == "en"),
        ""
    )

    # CWE
    cwe_list = [
        w.get("value", "")
        for weakness in cve_data.get("weaknesses", [])
        for w in weakness.get("description", [])
        if w.get("lang") == "en"
    ]

    # References
    refs_raw = cve_data.get("references", [])
    ref_urls = [r.get("url", "") for r in refs_raw]

    # Exploits
    exploits, has_exploit = ExploitChecker.extract(refs_raw)

    # CVSS
    cvss = CVSSParser.parse(cve_data.get("metrics", {}))

    # Skip entries with no CVSS score
    if cvss.base_score == 0.0:
        return None

    port = port_entry.get("port", 0)
    return CVERecord(
        cve_id          = cve_id,
        description     = desc[:500],
        published       = cve_data.get("published", ""),
        last_modified   = cve_data.get("lastModified", ""),
        cvss            = cvss,
        cwe             = cwe_list,
        references      = ref_urls[:10],
        exploits        = exploits,
        has_exploit     = has_exploit,
        matched_port    = port,
        matched_ports   = [port],
        matched_service = port_entry.get("service", ""),
        matched_product = port_entry.get("product", ""),
        matched_version = port_entry.get("version", ""),
        match_source    = match_source,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Deduplicator
# ══════════════════════════════════════════════════════════════════════════════

class Deduplicator:
    """
    Merge duplicate CVE IDs that appear across multiple ports.
    Keeps the highest-confidence record and merges port lists.
    Prefers 'cpe' match_source over 'keyword'.
    """

    @staticmethod
    def deduplicate(records: list[CVERecord]) -> list[CVERecord]:
        seen: dict[str, CVERecord] = {}
        for rec in records:
            existing = seen.get(rec.cve_id)
            if existing is None:
                seen[rec.cve_id] = rec
            else:
                # Merge port lists
                merged_ports = list(set(existing.matched_ports + rec.matched_ports))
                existing.matched_ports = merged_ports
                # Prefer CPE match
                if rec.match_source == "cpe" and existing.match_source == "keyword":
                    rec.matched_ports = merged_ports
                    seen[rec.cve_id]  = rec

        return sorted(seen.values(), key=lambda r: r.score, reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# Output tables
# ══════════════════════════════════════════════════════════════════════════════

def _print_cve_table(records: list[CVERecord]) -> None:
    if not records:
        log.warn("No CVEs found for discovered services.")
        return

    sev_col = {
        "CRITICAL": "red",
        "HIGH":     "magenta",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
        "NONE":     "dim",
    }

    t = Table(
        title=f"CVE Findings ({len(records)} unique)",
        box=box.ROUNDED, border_style="red",
        header_style="bold red", show_lines=True,
    )
    t.add_column("CVE ID",    style="bold white", width=18, no_wrap=True)
    t.add_column("Score",     width=7)
    t.add_column("Severity",  width=10)
    t.add_column("Port(s)",   width=12)
    t.add_column("Product",   width=18)
    t.add_column("AV",        width=8)
    t.add_column("Exploit",   width=8)
    t.add_column("Description", overflow="fold")

    for rec in records[:40]:
        sc   = sev_col.get(rec.severity, "white")
        av   = rec.cvss.attack_vector[:3] if rec.cvss.attack_vector else "—"
        av_c = "red" if av == "NET" else "yellow" if av == "ADJ" else "white"
        exp  = "[red]YES[/red]" if rec.has_exploit else "[dim]no[/dim]"
        ports_str = ",".join(str(p) for p in sorted(rec.matched_ports))

        t.add_row(
            rec.cve_id,
            f"[{sc}]{rec.score:.1f}[/{sc}]",
            f"[{sc}]{rec.severity}[/{sc}]",
            ports_str,
            f"{rec.matched_product[:16]}",
            f"[{av_c}]{av}[/{av_c}]",
            exp,
            rec.description[:120],
        )

    _console.print(t)

    # Exploit summary
    with_exploit = [r for r in records if r.has_exploit]
    if with_exploit:
        log.warn(f"  {len(with_exploit)} CVE(s) have known exploits — prioritise immediately.")
        for r in with_exploit[:5]:
            for ex in r.exploits[:2]:
                log.warn(f"    {r.cve_id} [{ex.source}] {ex.url}")


def _print_stats(records: list[CVERecord]) -> None:
    from collections import Counter
    sev_counts  = Counter(r.severity for r in records)
    av_counts   = Counter(r.cvss.attack_vector for r in records if r.cvss.attack_vector)
    src_counts  = Counter(r.match_source for r in records)
    exploit_cnt = sum(1 for r in records if r.has_exploit)

    t = Table(title="Correlation Statistics", box=box.SIMPLE,
              border_style="cyan", header_style="bold cyan")
    t.add_column("Metric",  style="bold white", width=28)
    t.add_column("Value",   style="cyan")

    t.add_row("Total CVEs",         str(len(records)))
    t.add_row("With Known Exploit", f"[red]{exploit_cnt}[/red]" if exploit_cnt else "0")
    t.add_row("Network Exploitable",
              str(sum(1 for r in records if r.network_exploitable)))
    t.add_row("No Auth Required",
              str(sum(1 for r in records if r.no_auth_required)))
    t.add_section()
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","NONE"]:
        n = sev_counts.get(sev, 0)
        colour = {"CRITICAL":"red","HIGH":"magenta","MEDIUM":"yellow","LOW":"cyan"}.get(sev,"dim")
        t.add_row(f"  {sev}", f"[{colour}]{n}[/{colour}]")
    t.add_section()
    for av, n in av_counts.most_common():
        t.add_row(f"  AV:{av[:3]}", str(n))
    t.add_section()
    for src, n in src_counts.items():
        t.add_row(f"  Source: {src}", str(n))

    _console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

class CVEEngine:
    """
    Correlates active-scan + web-enum results → CVE records via NVD API v2.

    Strategy per port / web-tech entry:
      1. CPE lookup  (high precision — uses Nmap CPE string)
      2. Keyword fallback  (broader — product + version)
    Results are deduplicated, sorted by CVSS score, and returned.
    """

    def __init__(self, active_scan_results: dict, web_results: dict | None = None):
        self._ports  = active_scan_results.get("open_ports", [])
        self._cache  = CVECache()
        self._client = NVDClient(self._cache)
        self._cpe    = CPEMatcher(self._client)
        self._kw     = KeywordMatcher(self._client)
        self._web_entries = self._build_web_port_entries(web_results or {})

    @staticmethod
    def _build_web_port_entries(web: dict) -> list[dict]:
        """Synthesise port-style dicts from web-detected tech for NVD lookup."""
        entries: list[dict] = []
        scheme = web.get("scheme", "http")
        port   = 443 if scheme == "https" else 80
        seen: set[tuple[str, str]] = set()

        def _add(product: str, version: str = "") -> None:
            key = (product.strip().lower(), version.strip())
            if not product.strip() or key in seen:
                return
            seen.add(key)
            entries.append({"port": port, "service": scheme,
                            "product": product.strip(), "version": version.strip(), "cpe": []})

        # Server header "Product/version"
        server = web.get("server", "")
        if server:
            p, _, v = server.partition("/")
            _add(p.strip(), v.strip())

        # Leak-header findings (!X-Powered-By, !X-AspNet-Version, etc.)
        aspnet_ver = ""
        for h in web.get("headers", []):
            hdr = h.get("header", "")
            val = h.get("value", "")
            if not hdr.startswith("!") or not val:
                continue
            name = hdr[1:]
            if name == "X-Powered-By":
                _add(val)
            elif name == "X-AspNet-Version":
                aspnet_ver = val
            elif name in ("X-Generator", "X-AspNetMvc-Version"):
                _add(name.replace("X-", ""), val)

        if aspnet_ver:
            _add("ASP.NET", aspnet_ver)

        # Technologies dict — add remaining entries not already seen
        for names in web.get("technologies", {}).values():
            for name in names:
                if not any(name.lower() in k[0] for k in seen):
                    _add(name)

        return entries

    def _correlate_port(self, port_entry: dict) -> list[CVERecord]:
        """Run CPE then keyword matching for a single port."""
        records: list[CVERecord] = []

        # Phase A: CPE
        if port_entry.get("cpe"):
            cpe_records = self._cpe.match(port_entry)
            records.extend(cpe_records)
            log.info(
                f"  Port {port_entry.get('port')} CPE → {len(cpe_records)} CVE(s)"
            )

        # Phase B: Keyword fallback (only if CPE found nothing)
        if not records:
            kw_records = self._kw.match(port_entry)
            records.extend(kw_records)
            if kw_records:
                log.info(
                    f"  Port {port_entry.get('port')} Keyword → {len(kw_records)} CVE(s)"
                )

        return records

    def run(self) -> list[dict]:
        all_entries = self._ports + self._web_entries

        if not all_entries:
            log.warn("No open ports to correlate — skipping CVE lookup.")
            return []

        # Purge stale cache entries
        expired = self._cache.purge_expired()
        if expired:
            log.debug(f"  Purged {expired} expired cache entries")

        port_count = len(self._ports)
        web_count  = len(self._web_entries)
        log.info(f"Correlating {port_count} port(s) + {web_count} web tech(s) against NVD…")
        api_mode = "authenticated" if cfg.cve.api_key else "anonymous (5 req/30s)"
        log.info(f"NVD API mode: {api_mode}")

        all_records: list[CVERecord] = []

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
            task = progress.add_task(
                "  [cyan]CVE correlation[/cyan]",
                total=len(all_entries),
            )

            # Sequential to respect NVD rate limits precisely
            for port_entry in all_entries:
                svc = port_entry.get("service", "?")
                prd = port_entry.get("product", "")
                ver = port_entry.get("version", "")
                log.info(
                    f"  Querying: port {port_entry.get('port')}  "
                    f"{svc} {prd} {ver}".strip()
                )
                records = self._correlate_port(port_entry)
                all_records.extend(records)
                progress.advance(task)

            progress.update(task,
                            description=f"  [green]CVE correlation done — {len(all_records)} raw hits[/green]")

        # Deduplicate
        unique = Deduplicator.deduplicate(all_records)
        log.info(f"After deduplication: {len(unique)} unique CVE(s)")

        # Print tables
        _print_cve_table(unique)
        _print_stats(unique)

        log.success(
            f"CVE correlation complete — "
            f"{len(unique)} unique CVEs, "
            f"{sum(1 for r in unique if r.has_exploit)} with known exploits"
        )

        return [r.to_dict() for r in unique]
