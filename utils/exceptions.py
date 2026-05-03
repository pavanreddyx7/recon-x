"""
R3CON-X custom exception hierarchy.
Every module raises a specific subclass so the pipeline can react precisely.
"""
from __future__ import annotations


class R3ConXError(Exception):
    """Base class — all framework exceptions inherit from here."""
    exit_code: int = 1

    def __init__(self, message: str, *, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail

    def __str__(self) -> str:
        return f"{super().__str__()}{f' — {self.detail}' if self.detail else ''}"


# ── Input / validation ────────────────────────────────────────────────────────
class ValidationError(R3ConXError):
    """Raised when the target fails format or policy checks."""
    exit_code = 2


class UnreachableTargetError(R3ConXError):
    """Raised when the target does not respond to any probe."""
    exit_code = 3


# ── Network / scanning ────────────────────────────────────────────────────────
class ScanError(R3ConXError):
    """Raised when an active scan stage fails critically."""
    exit_code = 10


class PortScanError(ScanError):
    """Nmap or raw-socket port scan failure."""


class BannerGrabError(ScanError):
    """Banner grab timed out or returned unusable data."""


# ── Passive recon ─────────────────────────────────────────────────────────────
class PassiveReconError(R3ConXError):
    """DNS / WHOIS / OSINT collection failure."""
    exit_code = 20


class DNSError(PassiveReconError):
    """DNS resolver failure."""


class WHOISError(PassiveReconError):
    """WHOIS lookup failure."""


# ── Web enumeration ───────────────────────────────────────────────────────────
class WebEnumError(R3ConXError):
    """Web enumeration / HTTP analysis failure."""
    exit_code = 30


# ── CVE / intelligence ────────────────────────────────────────────────────────
class CVELookupError(R3ConXError):
    """NVD API or CVE correlation failure."""
    exit_code = 40


class RateLimitError(CVELookupError):
    """API rate-limit hit."""


# ── Reporting ─────────────────────────────────────────────────────────────────
class ReportError(R3ConXError):
    """Report generation failure."""
    exit_code = 50


# ── Configuration ─────────────────────────────────────────────────────────────
class ConfigError(R3ConXError):
    """Invalid or missing configuration."""
    exit_code = 60
