"""
Advanced target validator.
Supports IPv4, IPv6, CIDR ranges, bare domains, and http(s):// URLs.
Performs scope policy checks, DNS resolution, and optional reachability probes.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterator

from utils.exceptions import ValidationError
from utils.logger import log


# ── Types ─────────────────────────────────────────────────────────────────────
class TargetKind(Enum):
    IPV4   = auto()
    IPV6   = auto()
    CIDR   = auto()
    DOMAIN = auto()


@dataclass(frozen=True)
class Target:
    raw:        str
    kind:       TargetKind
    host:       str                  # cleaned host / network string
    ip:         str         = ""     # resolved IP (empty for CIDR)
    is_private: bool        = False
    extra:      dict        = field(default_factory=dict, compare=False)

    def __str__(self) -> str:
        return self.host

    def iter_hosts(self) -> Iterator[str]:
        """Expand a CIDR into individual host IPs (max 256 for safety)."""
        if self.kind is TargetKind.CIDR:
            net = ipaddress.ip_network(self.host, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 256:
                raise ValidationError(
                    f"CIDR {self.host} contains {len(hosts)} hosts — limit is 256."
                )
            for h in hosts:
                yield str(h)
        else:
            yield self.ip or self.host


# ── Internal helpers ──────────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_STRIP_SCHEME = re.compile(r"^https?://", re.I)
_STRIP_PATH   = re.compile(r"[/?#].*$")

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private(addr: str) -> bool:
    try:
        obj = ipaddress.ip_address(addr)
        return any(obj in net for net in _RFC1918)
    except ValueError:
        return False


def _clean(raw: str) -> str:
    """Strip scheme, trailing path/query, whitespace, trailing dots."""
    s = raw.strip()
    s = _STRIP_SCHEME.sub("", s)
    s = _STRIP_PATH.sub("", s)
    return s.rstrip(".")


# ── Public API ────────────────────────────────────────────────────────────────
def parse_target(raw: str) -> Target:
    """
    Parse and validate a target string into a `Target` dataclass.

    Accepted forms:
      • 192.168.1.1          IPv4
      • 2001:db8::1          IPv6
      • 10.0.0.0/24          CIDR
      • example.com          domain
      • https://example.com  URL (scheme/path stripped)
    """
    host = _clean(raw)
    if not host:
        raise ValidationError("Target cannot be empty.")

    # ── CIDR ─────────────────────────────────────────────────────────────────
    if "/" in host:
        try:
            net = ipaddress.ip_network(host, strict=False)
            log.info(f"Target parsed as CIDR network: {net}")
            return Target(raw=raw, kind=TargetKind.CIDR, host=str(net))
        except ValueError:
            raise ValidationError(f"Invalid CIDR notation: '{host}'")

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    try:
        ipaddress.IPv4Address(host)
        private = _is_private(host)
        if private:
            log.warn(f"'{host}' is a private/loopback address — confirm you are authorised.")
        else:
            log.info(f"Target parsed as IPv4: {host}")
        return Target(raw=raw, kind=TargetKind.IPV4, host=host, ip=host, is_private=private)
    except ValueError:
        pass

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    try:
        ipaddress.IPv6Address(host)
        log.info(f"Target parsed as IPv6: {host}")
        return Target(raw=raw, kind=TargetKind.IPV6, host=host, ip=host,
                      is_private=_is_private(host))
    except ValueError:
        pass

    # ── Domain ────────────────────────────────────────────────────────────────
    if _DOMAIN_RE.match(host):
        log.info(f"Target parsed as domain: {host}")
        ip = _resolve(host)
        priv = _is_private(ip) if ip else False
        return Target(raw=raw, kind=TargetKind.DOMAIN, host=host, ip=ip or "", is_private=priv)

    raise ValidationError(
        f"'{raw}' is not a valid IPv4, IPv6, CIDR, or domain.",
        detail="Strip any http:// prefix and do not include paths.",
    )


def resolve_domain(domain: str) -> str:
    """Resolve domain → IP. Raises ValidationError on failure."""
    ip = _resolve(domain)
    if not ip:
        raise ValidationError(f"DNS resolution failed for '{domain}'.")
    return ip


def _resolve(domain: str) -> str | None:
    try:
        ip = socket.gethostbyname(domain)
        log.info(f"DNS: {domain} → {ip}")
        return ip
    except socket.gaierror as e:
        log.warn(f"DNS resolution failed for '{domain}': {e}")
        return None


def probe_reachability(
    host: str,
    ports: tuple[int, ...] = (80, 443, 22, 8080),
    timeout: float = 3.0,
) -> bool:
    """
    Try each port in `ports` and return True on first successful TCP connect.
    Never raises — failures are logged and False is returned.
    """
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                log.success(f"Host {host} is reachable (port {port} open).")
                return True
        except OSError:
            continue
    log.warn(f"Host {host} did not respond to any probe ports {ports}.")
    return False


# ── Convenience alias ─────────────────────────────────────────────────────────
validate_target  = parse_target
check_reachability = probe_reachability
