"""
R3CON-X global configuration.
Values are resolved in order: YAML file → environment variable → hard-coded default.
Import the singleton: `from config import cfg`
"""
from __future__ import annotations

import os
import yaml
from dataclasses import dataclass, field, asdict
from typing import Any

from utils.exceptions import ConfigError


# ── Helpers ───────────────────────────────────────────────────────────────────
def _env(key: str, default: Any) -> Any:
    """Return env-var value cast to the same type as *default*, or default."""
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return type(default)(val)
    except (ValueError, TypeError):
        return val


# ── Sub-configs ───────────────────────────────────────────────────────────────
@dataclass
class NetworkCfg:
    port_range:   str   = "1-1024"
    max_threads:  int   = 150
    timeout:      float = 8.0
    banner_bytes: int   = 2048
    top_ports:    int   = 100     # used by 'quick' profile


@dataclass
class WebCfg:
    user_agent:    str   = "R3CON-X/2.0 (Authorized Security Assessment)"
    max_redirects: int   = 5
    verify_ssl:    bool  = False
    timeout:       float = 10.0
    dir_threads:   int   = 30


@dataclass
class CVECfg:
    api_url:      str   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key:      str   = ""       # set RECONX_NVD_KEY env-var or in config.yaml
    results_per_page: int = 5
    rate_limit_rps: float = 5.0   # requests/sec (10 with API key)
    cache_ttl:    int   = 3600    # seconds to cache NVD responses


@dataclass
class ReportCfg:
    formats:   list[str] = field(default_factory=lambda: ["pdf", "json"])
    company:   str        = "R3CON-X Assessment"
    logo_path: str        = ""


@dataclass
class RiskThreshold:
    low:      tuple[float, float] = (0.1,  3.9)
    medium:   tuple[float, float] = (4.0,  6.9)
    high:     tuple[float, float] = (7.0,  8.9)
    critical: tuple[float, float] = (9.0, 10.0)

    def classify(self, score: float) -> str:
        if   score >= self.critical[0]: return "CRITICAL"
        elif score >= self.high[0]:     return "HIGH"
        elif score >= self.medium[0]:   return "MEDIUM"
        elif score >= self.low[0]:      return "LOW"
        else:                           return "NONE"


# ── Root config ───────────────────────────────────────────────────────────────
@dataclass
class Config:
    base_dir:   str = field(default_factory=lambda: os.path.dirname(os.path.abspath(__file__)))
    output_dir: str = ""

    network:   NetworkCfg    = field(default_factory=NetworkCfg)
    web:       WebCfg        = field(default_factory=WebCfg)
    cve:       CVECfg        = field(default_factory=CVECfg)
    report:    ReportCfg     = field(default_factory=ReportCfg)
    risk:      RiskThreshold = field(default_factory=RiskThreshold)

    # Scan profiles — override specific keys per profile
    profiles: dict[str, dict] = field(default_factory=lambda: {
        "quick":    {"port_range": "1-100",   "skip_passive": True,  "skip_web": True},
        "standard": {"port_range": "1-1024",  "skip_passive": False, "skip_web": False},
        "full":     {"port_range": "1-65535", "skip_passive": False, "skip_web": False},
        "stealth":  {"port_range": "1-1024",  "skip_passive": False, "skip_web": False,
                     "nmap_flags": "-sS -T2 --data-length 15"},
    })

    SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")

    def __post_init__(self) -> None:
        if not self.output_dir:
            self.output_dir = os.path.join(self.base_dir, "output")
        # Env-var overrides
        self.cve.api_key        = _env("RECONX_NVD_KEY",    self.cve.api_key)
        self.network.max_threads = _env("RECONX_THREADS",   self.network.max_threads)
        self.network.timeout     = _env("RECONX_TIMEOUT",   self.network.timeout)
        os.makedirs(self.output_dir, exist_ok=True)

    # ── YAML loader ───────────────────────────────────────────────────────────
    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        """Load from a YAML file, deep-merge into defaults."""
        try:
            with open(path) as f:
                data: dict = yaml.safe_load(f) or {}
        except FileNotFoundError:
            raise ConfigError(f"Config file not found: {path}")
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in {path}", detail=str(e))

        inst = cls()
        for section, sub_cfg in [
            ("network", inst.network),
            ("web",     inst.web),
            ("cve",     inst.cve),
            ("report",  inst.report),
        ]:
            for k, v in data.get(section, {}).items():
                if hasattr(sub_cfg, k):
                    setattr(sub_cfg, k, v)

        if "output_dir" in data:
            inst.output_dir = data["output_dir"]

        return inst

    def profile_flags(self, profile: str) -> dict:
        """Return the skip/flag overrides for a named profile."""
        return self.profiles.get(profile, self.profiles["standard"])

    def as_dict(self) -> dict:
        return asdict(self)


# ── Singleton ─────────────────────────────────────────────────────────────────
_YAML_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
cfg = Config.from_yaml(_YAML_PATH) if os.path.exists(_YAML_PATH) else Config()

# ── Backward-compat flat constants ────────────────────────────────────────────
OUTPUT_DIR     = cfg.output_dir
PORT_RANGE     = cfg.network.port_range
TIMEOUT        = cfg.network.timeout
MAX_THREADS    = cfg.network.max_threads
NVD_API_URL    = cfg.cve.api_url
NVD_API_KEY    = cfg.cve.api_key
SEVERITY_ORDER = list(cfg.SEVERITY_ORDER)
