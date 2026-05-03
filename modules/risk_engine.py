"""
Stage 6 — Risk Analysis Engine
Transforms raw CVE records into a prioritised, actionable risk picture.

Sub-components:
  MultiFactorScorer   — CVSS + exploit bonus + exposure + auth + scope weights
  EPSSClient          — Real EPSS scores via FIRST.org API (heuristic fallback)
  AttackSurfaceMapper — Groups findings by attack vector and service cluster
  ChainDetector       — Identifies compound vulnerability chains across ports
  RemediationPlanner  — Generates prioritised, time-estimated remediation tasks
  RiskMatrix          — 5×5 Likelihood × Impact heat-map
  RiskEngine          — Orchestrator, returns fully enriched summary dict
"""
from __future__ import annotations

import math
import statistics
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any

import requests

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from utils.logger import log
from config import cfg

_console = Console(highlight=False)


# ══════════════════════════════════════════════════════════════════════════════
# Data models
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RiskScore:
    """Enriched risk score — multi-factor, beyond raw CVSS."""
    cve_id:            str
    cvss_score:        float
    severity:          str
    # Bonus / penalty multipliers
    exploit_bonus:     float = 0.0   # +1.5 if known exploit exists
    network_bonus:     float = 0.0   # +1.0 if AV:NETWORK
    noauth_bonus:      float = 0.0   # +0.8 if PR:NONE
    scope_bonus:       float = 0.0   # +0.5 if Scope:CHANGED
    noui_bonus:        float = 0.0   # +0.4 if UI:NONE
    age_penalty:       float = 0.0   # -0.3 per year old (max -1.5)
    epss_score:        float = 0.0   # 0.0–1.0 exploit probability estimate
    composite_score:   float = 0.0   # final weighted score (0–15 scale)
    risk_tier:         str   = ""    # CRITICAL | HIGH | MEDIUM | LOW | NONE
    priority_rank:     int   = 0     # 1 = highest priority

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackPath:
    """A sequence of ports/services that form an escalation chain."""
    path_id:      int
    steps:        list[dict]    = field(default_factory=list)
    description:  str           = ""
    impact:       str           = ""
    likelihood:   str           = ""


@dataclass
class RemediationTask:
    priority:       int
    cve_id:         str
    title:          str
    action:         str
    effort:         str     # IMMEDIATE | SHORT | MEDIUM | LONG
    effort_days:    int     # estimated days
    affected_ports: list[int] = field(default_factory=list)
    references:     list[str] = field(default_factory=list)


@dataclass
class RiskSummary:
    counts:           dict[str, int]         = field(default_factory=dict)
    top_risks:        list[dict]             = field(default_factory=list)
    risk_scores:      list[dict]             = field(default_factory=dict)  # type: ignore
    attack_surface:   dict[str, Any]         = field(default_factory=dict)
    attack_paths:     list[dict]             = field(default_factory=list)
    remediation_plan: list[dict]             = field(default_factory=list)
    statistics:       dict[str, Any]         = field(default_factory=dict)
    overall_risk:     str                    = ""
    risk_score:       float                  = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════════════
# Multi-Factor Scorer
# ══════════════════════════════════════════════════════════════════════════════

_TIER_THRESHOLDS = [
    ("CRITICAL", 11.0),
    ("HIGH",      8.0),
    ("MEDIUM",    5.0),
    ("LOW",       2.0),
    ("NONE",      0.0),
]


class MultiFactorScorer:
    """
    Composite score = CVSS_base
                    + exploit_bonus   (1.5 if known public exploit)
                    + network_bonus   (1.0 if AV:NETWORK)
                    + noauth_bonus    (0.8 if PR:NONE)
                    + scope_bonus     (0.5 if Scope:CHANGED)
                    + noui_bonus      (0.4 if UI:NONE)
                    - age_penalty     (0.3/year, max 1.5 for very old CVEs)

    Scale: 0 – 15  (exceeds CVSS 10.0 intentionally — exploit presence matters)
    """

    def score(self, vuln: dict) -> RiskScore:
        cvss_score  = float(vuln.get("score", vuln.get("cvss", {}).get("base_score", 0.0)))
        severity    = vuln.get("severity", cfg.risk.classify(cvss_score))
        has_exploit = vuln.get("has_exploit", False)
        cvss        = vuln.get("cvss", {})
        av          = cvss.get("attack_vector", "")
        pr          = cvss.get("privileges_required", "")
        scope       = cvss.get("scope", "")
        ui          = cvss.get("user_interaction", "")
        published   = vuln.get("published", "")

        # Bonuses
        exploit_bonus = 1.5 if has_exploit else 0.0
        network_bonus = 1.0 if av == "NETWORK" else (0.5 if av == "ADJACENT" else 0.0)
        noauth_bonus  = 0.8 if pr == "NONE"    else (0.3 if pr == "LOW"     else 0.0)
        scope_bonus   = 0.5 if scope == "CHANGED" else 0.0
        noui_bonus    = 0.4 if ui == "NONE"    else 0.0

        # Age penalty — older CVEs with no patch urgency score slightly lower
        age_penalty = 0.0
        if published:
            try:
                year  = int(published[:4])
                from datetime import datetime
                age   = max(0, datetime.now().year - year)
                age_penalty = min(1.5, age * 0.2)
            except (ValueError, IndexError):
                pass

        composite = (
            cvss_score
            + exploit_bonus
            + network_bonus
            + noauth_bonus
            + scope_bonus
            + noui_bonus
            - age_penalty
        )
        composite = round(max(0.0, composite), 2)

        # Tier classification on composite scale
        tier = "NONE"
        for label, threshold in _TIER_THRESHOLDS:
            if composite >= threshold:
                tier = label
                break

        return RiskScore(
            cve_id          = vuln.get("cve_id", ""),
            cvss_score      = cvss_score,
            severity        = severity,
            exploit_bonus   = exploit_bonus,
            network_bonus   = network_bonus,
            noauth_bonus    = noauth_bonus,
            scope_bonus     = scope_bonus,
            noui_bonus      = noui_bonus,
            age_penalty     = age_penalty,
            composite_score = composite,
            risk_tier       = tier,
        )

    def score_all(self, vulns: list[dict]) -> list[RiskScore]:
        scores = [self.score(v) for v in vulns]
        scores.sort(key=lambda s: s.composite_score, reverse=True)
        for i, s in enumerate(scores, 1):
            s.priority_rank = i
        return scores


# ══════════════════════════════════════════════════════════════════════════════
# EPSS Estimator
# ══════════════════════════════════════════════════════════════════════════════

class EPSSClient:
    """
    Fetches real EPSS scores from the FIRST.org API in a single batched request.
    Falls back to a local sigmoid heuristic if the API is unreachable.

    API: https://api.first.org/data/v1/epss?cve=CVE-XXXX,CVE-YYYY,...
    """

    _API = "https://api.first.org/data/v1/epss"
    _TIMEOUT = 10

    # ── Heuristic fallback weights ────────────────────────────────────────────
    _W = {
        "base": -3.5, "score": 0.30, "av_net": 1.20, "av_adj": 0.60,
        "pr_none": 0.90, "pr_low": 0.40, "no_ui": 0.50,
        "exploit": 2.50, "scope": 0.40, "old_cve": 0.30,
    }

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1.0 / (1.0 + math.exp(-max(-500, min(500, x))))

    def _heuristic(self, rs: RiskScore, vuln: dict) -> float:
        w = self._W
        cvss  = vuln.get("cvss", {})
        av    = cvss.get("attack_vector", "")
        pr    = cvss.get("privileges_required", "")
        ui    = cvss.get("user_interaction", "REQUIRED")
        scope = cvss.get("scope", "")
        pub   = vuln.get("published", "")
        logit = (w["base"] + w["score"] * rs.cvss_score
                 + (w["av_net"] if av == "NETWORK" else w["av_adj"] if av == "ADJACENT" else 0)
                 + (w["pr_none"] if pr == "NONE" else w["pr_low"] if pr == "LOW" else 0)
                 + (w["no_ui"] if ui == "NONE" else 0)
                 + (w["exploit"] if vuln.get("has_exploit") else 0)
                 + (w["scope"] if scope == "CHANGED" else 0))
        try:
            if pub and int(pub[:4]) < 2020:
                logit += w["old_cve"]
        except (ValueError, IndexError):
            pass
        return round(self._sigmoid(logit), 4)

    def fetch_batch(self, cve_ids: list[str]) -> dict[str, float]:
        """Return {cve_id: epss_score} via one API call for up to 2 000 CVEs."""
        if not cve_ids:
            return {}
        try:
            resp = requests.get(
                self._API,
                params={"cve": ",".join(cve_ids)},
                timeout=self._TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            return {row["cve"]: float(row.get("epss", 0)) for row in data if "cve" in row}
        except Exception as e:
            log.warn(f"  EPSS API unavailable ({e}) — using heuristic fallback")
            return {}

    def annotate(self, scores: list[RiskScore], vulns: list[dict]) -> None:
        vuln_map  = {v.get("cve_id", ""): v for v in vulns}
        cve_ids   = [rs.cve_id for rs in scores if rs.cve_id]
        api_scores = self.fetch_batch(cve_ids)

        for rs in scores:
            if rs.cve_id in api_scores:
                rs.epss_score = round(api_scores[rs.cve_id], 4)
            else:
                rs.epss_score = self._heuristic(rs, vuln_map.get(rs.cve_id, {}))


# ══════════════════════════════════════════════════════════════════════════════
# Attack Surface Mapper
# ══════════════════════════════════════════════════════════════════════════════

class AttackSurfaceMapper:
    """
    Groups vulnerabilities by:
      - Attack vector (NETWORK / LOCAL / PHYSICAL)
      - Service cluster (web, database, remote-access, mail, etc.)
      - Port exposure
    """

    _SERVICE_CLUSTERS = {
        "web":           {80, 443, 8080, 8443, 8000, 3000, 4443, 9000},
        "database":      {1433, 1521, 3306, 5432, 5984, 6379, 27017, 9200},
        "remote-access": {22, 23, 3389, 5900, 5985, 5986, 2222},
        "mail":          {25, 110, 143, 465, 587, 993, 995},
        "file-transfer": {21, 69, 2049, 445, 139},
        "dns":           {53},
        "monitoring":    {161, 162, 9090, 9100, 3000},
        "management":    {8888, 9000, 9090, 4848, 7001, 7002},
    }

    def map(self, vulns: list[dict], scores: list[RiskScore]) -> dict[str, Any]:
        score_map = {s.cve_id: s for s in scores}

        by_vector:  defaultdict[str, list[str]] = defaultdict(list)
        by_cluster: defaultdict[str, list[str]] = defaultdict(list)
        by_port:    defaultdict[int, list[str]] = defaultdict(list)

        for v in vulns:
            cve_id = v.get("cve_id", "")
            av     = v.get("cvss", {}).get("attack_vector", "UNKNOWN")
            ports  = v.get("matched_ports", [v.get("matched_port", 0)])

            by_vector[av].append(cve_id)

            for port in ports:
                by_port[port].append(cve_id)
                cluster = next(
                    (c for c, ps in self._SERVICE_CLUSTERS.items() if port in ps),
                    "other"
                )
                by_cluster[cluster].append(cve_id)

        # Network-reachable critical/high count (most dangerous)
        net_critical = sum(
            1 for v in vulns
            if v.get("cvss", {}).get("attack_vector") == "NETWORK"
            and score_map.get(v.get("cve_id", ""), RiskScore("", 0, "")).risk_tier
                in ("CRITICAL", "HIGH")
        )

        return {
            "by_attack_vector":  dict(by_vector),
            "by_service_cluster": {k: list(set(v)) for k, v in by_cluster.items()},
            "by_port":           {str(p): list(set(c)) for p, c in by_port.items()},
            "network_critical_count": net_critical,
            "exposed_clusters":  [c for c in by_cluster if by_cluster[c]],
        }


# ══════════════════════════════════════════════════════════════════════════════
# Attack Chain Detector
# ══════════════════════════════════════════════════════════════════════════════

class ChainDetector:
    """
    Identifies plausible multi-step exploitation chains.

    Chain patterns:
      Recon → Initial Access → Privilege Escalation → Lateral Movement
      e.g.  open SSH (no auth) → local priv-esc CVE → pivot via SMB
    """

    _CHAIN_PATTERNS = [
        {
            "id": "initial_rce_then_privesc",
            "description": "Remote code execution followed by local privilege escalation",
            "step1": lambda v: (v.get("cvss", {}).get("attack_vector") == "NETWORK"
                                and float(v.get("score", 0)) >= 9.0),
            "step2": lambda v: (v.get("cvss", {}).get("attack_vector") == "LOCAL"
                                and v.get("cvss", {}).get("privileges_required") != "NONE"),
            "impact": "Full system compromise — remote → root",
            "likelihood": "HIGH" if True else "LOW",
        },
        {
            "id": "web_to_db",
            "description": "Web service compromise leading to database access",
            "step1": lambda v: v.get("matched_service", "") in ("http", "https", "http-alt"),
            "step2": lambda v: v.get("matched_service", "") in ("mysql", "postgresql", "mongodb", "redis"),
            "impact": "Data exfiltration — web layer → database",
            "likelihood": "MEDIUM",
        },
        {
            "id": "auth_bypass_then_admin",
            "description": "Authentication bypass enabling administrative access",
            "step1": lambda v: (v.get("cvss", {}).get("privileges_required") == "NONE"
                                and float(v.get("score", 0)) >= 7.0),
            "step2": lambda v: (v.get("cvss", {}).get("scope") == "CHANGED"),
            "impact": "Privilege escalation — no-auth exploit → scope change",
            "likelihood": "HIGH",
        },
    ]

    def detect(self, vulns: list[dict]) -> list[AttackPath]:
        paths: list[AttackPath] = []

        for idx, pattern in enumerate(self._CHAIN_PATTERNS, 1):
            step1_hits = [v for v in vulns if pattern["step1"](v)]
            step2_hits = [v for v in vulns if pattern["step2"](v)]

            if step1_hits and step2_hits:
                path = AttackPath(
                    path_id=idx,
                    description=pattern["description"],
                    impact=pattern["impact"],
                    likelihood=pattern["likelihood"],
                    steps=[
                        {
                            "step": 1,
                            "cve":  step1_hits[0].get("cve_id", ""),
                            "port": step1_hits[0].get("matched_port", 0),
                            "action": "Initial exploit via network-accessible service",
                        },
                        {
                            "step": 2,
                            "cve":  step2_hits[0].get("cve_id", ""),
                            "port": step2_hits[0].get("matched_port", 0),
                            "action": pattern["description"].split(" followed by ")[-1]
                                      if " followed by " in pattern["description"]
                                      else "Secondary exploitation",
                        },
                    ],
                )
                paths.append(path)
                log.warn(
                    f"  [CHAIN] {pattern['description']}  "
                    f"({step1_hits[0].get('cve_id')} → {step2_hits[0].get('cve_id')})"
                )

        return paths


# ══════════════════════════════════════════════════════════════════════════════
# Remediation Planner
# ══════════════════════════════════════════════════════════════════════════════

_REMEDIATION_TEMPLATES = {
    "patch": "Apply vendor security patch for {product} to address {cve_id}.",
    "disable": "Disable or restrict access to the vulnerable service on port {port}.",
    "config": "Review and harden configuration to eliminate {cve_id} exposure.",
    "upgrade": "Upgrade {product} to a non-vulnerable version (see vendor advisory).",
    "firewall": "Apply firewall rules to restrict access to port {port} from untrusted sources.",
    "waf": "Deploy or update WAF rules to detect and block exploitation attempts for {cve_id}.",
    "isolate": "Network-isolate the service on port {port} until patched.",
}

_EFFORT_MAP = {
    "CRITICAL": ("IMMEDIATE", 1),
    "HIGH":     ("SHORT",     7),
    "MEDIUM":   ("MEDIUM",   30),
    "LOW":      ("LONG",     90),
    "NONE":     ("LONG",    180),
}


class RemediationPlanner:
    def plan(self, vulns: list[dict], scores: list[RiskScore]) -> list[RemediationTask]:
        score_map = {s.cve_id: s for s in scores}
        tasks: list[RemediationTask] = []
        priority = 1

        # Sort by composite score descending
        sorted_vulns = sorted(
            vulns,
            key=lambda v: score_map.get(v.get("cve_id", ""), RiskScore("", 0, "")).composite_score,
            reverse=True,
        )

        for vuln in sorted_vulns:
            cve_id  = vuln.get("cve_id", "")
            product = vuln.get("matched_product", "the service")
            port    = vuln.get("matched_port", 0)
            ports   = vuln.get("matched_ports", [port])
            tier    = score_map.get(cve_id, RiskScore("", 0, "")).risk_tier or vuln.get("severity", "LOW")
            effort, days = _EFFORT_MAP.get(tier, ("LONG", 90))

            # Choose remediation type
            has_exploit = vuln.get("has_exploit", False)
            av          = vuln.get("cvss", {}).get("attack_vector", "")

            if has_exploit and av == "NETWORK":
                rtype = "isolate"
            elif av == "NETWORK":
                rtype = "firewall"
            elif product and product.lower() not in ("", "unknown"):
                rtype = "patch"
            else:
                rtype = "config"

            action = _REMEDIATION_TEMPLATES[rtype].format(
                cve_id=cve_id, product=product or "service", port=port
            )

            tasks.append(RemediationTask(
                priority       = priority,
                cve_id         = cve_id,
                title          = f"[{tier}] {cve_id} — {product or 'Service'} on port {port}",
                action         = action,
                effort         = effort,
                effort_days    = days,
                affected_ports = ports,
                references     = vuln.get("references", [])[:3],
            ))
            priority += 1

        return tasks


# ══════════════════════════════════════════════════════════════════════════════
# Risk Matrix (5×5 Likelihood × Impact)
# ══════════════════════════════════════════════════════════════════════════════

_LIKELIHOOD_LEVELS = ["Rare", "Unlikely", "Possible", "Likely", "Almost Certain"]
_IMPACT_LEVELS     = ["Negligible", "Minor", "Moderate", "Major", "Critical"]

_RISK_MATRIX_LABELS = [
    # Impact →          Neg     Min     Mod     Maj     Crit
    ["LOW",    "LOW",    "MED",  "HIGH", "HIGH" ],  # Rare
    ["LOW",    "LOW",    "MED",  "HIGH", "HIGH" ],  # Unlikely
    ["LOW",    "MED",    "HIGH", "HIGH", "CRIT" ],  # Possible
    ["MED",    "HIGH",   "HIGH", "CRIT", "CRIT" ],  # Likely
    ["HIGH",   "HIGH",   "CRIT", "CRIT", "CRIT" ],  # Almost Certain
]

_CELL_COLOUR = {
    "LOW":  "cyan",
    "MED":  "yellow",
    "HIGH": "magenta",
    "CRIT": "red",
}


def _epss_to_likelihood(epss: float) -> int:
    """Map EPSS 0–1 to likelihood index 0–4."""
    if epss >= 0.70: return 4
    if epss >= 0.40: return 3
    if epss >= 0.20: return 2
    if epss >= 0.05: return 1
    return 0


def _score_to_impact(score: float) -> int:
    """Map CVSS score to impact index 0–4."""
    if score >= 9.0: return 4
    if score >= 7.0: return 3
    if score >= 5.0: return 2
    if score >= 3.0: return 1
    return 0


# ══════════════════════════════════════════════════════════════════════════════
# Overall Risk Calculator
# ══════════════════════════════════════════════════════════════════════════════

def _overall_risk(scores: list[RiskScore]) -> tuple[str, float]:
    """
    Aggregate risk = weighted average of composite scores,
    boosted by critical/exploit count.
    """
    if not scores:
        return "NONE", 0.0

    weights = {"CRITICAL": 4.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5, "NONE": 0.1}
    total_w, total_wv = 0.0, 0.0
    for s in scores:
        w         = weights.get(s.risk_tier, 0.1)
        total_w  += w
        total_wv += w * s.composite_score

    agg = round(total_wv / total_w, 2) if total_w else 0.0

    if   agg >= 11.0: return "CRITICAL", agg
    elif agg >= 8.0:  return "HIGH",     agg
    elif agg >= 5.0:  return "MEDIUM",   agg
    elif agg >= 2.0:  return "LOW",      agg
    else:             return "NONE",     agg


# ══════════════════════════════════════════════════════════════════════════════
# Output — Rich tables
# ══════════════════════════════════════════════════════════════════════════════

_SEV_COL = {
    "CRITICAL": "red", "HIGH": "magenta",
    "MEDIUM": "yellow", "LOW": "cyan", "NONE": "dim",
}


def _print_risk_matrix(scores: list[RiskScore]) -> None:
    t = Table(
        title="Risk Matrix  (Likelihood × Impact)",
        box=box.ROUNDED, border_style="cyan",
        header_style="bold cyan", show_lines=True,
    )
    t.add_column("Likelihood \\ Impact", style="bold white", width=18)
    for imp in _IMPACT_LEVELS:
        t.add_column(imp, width=12, justify="center")

    # Count CVEs per cell
    cell_counts: dict[tuple[int, int], int] = defaultdict(int)
    for s in scores:
        li = _epss_to_likelihood(s.epss_score)
        ii = _score_to_impact(s.cvss_score)
        cell_counts[(li, ii)] += 1

    for li, lbl in enumerate(_LIKELIHOOD_LEVELS):
        row = [lbl]
        for ii in range(len(_IMPACT_LEVELS)):
            label  = _RISK_MATRIX_LABELS[li][ii]
            colour = _CELL_COLOUR[label]
            count  = cell_counts.get((li, ii), 0)
            cell   = f"[{colour}]{label}[/{colour}]"
            if count:
                cell += f"\n[bold white]{count} CVE[/bold white]"
            row.append(cell)
        t.add_row(*row)
    _console.print(t)


def _print_top_risks(scores: list[RiskScore], vulns: list[dict]) -> None:
    vuln_map = {v.get("cve_id", ""): v for v in vulns}
    top      = scores[:15]

    t = Table(
        title="Top Prioritised Risks",
        box=box.ROUNDED, border_style="red",
        header_style="bold red", show_lines=True,
    )
    t.add_column("#",       width=4,  style="dim")
    t.add_column("CVE ID",  width=18, style="bold white", no_wrap=True)
    t.add_column("CVSS",    width=6)
    t.add_column("Comp.",   width=6)
    t.add_column("EPSS",    width=6)
    t.add_column("Tier",    width=10)
    t.add_column("Exploit", width=8)
    t.add_column("AV",      width=8)
    t.add_column("Ports",   width=12)
    t.add_column("Service", width=14)

    for rs in top:
        v    = vuln_map.get(rs.cve_id, {})
        sc   = _SEV_COL.get(rs.risk_tier, "white")
        av   = v.get("cvss", {}).get("attack_vector", "")[:3]
        avc  = "red" if av == "NET" else "yellow" if av == "ADJ" else "white"
        exp  = "[red]✔[/red]" if v.get("has_exploit") else "[dim]✗[/dim]"
        ports_str = ",".join(str(p) for p in sorted(v.get("matched_ports", [])))

        t.add_row(
            str(rs.priority_rank),
            rs.cve_id,
            f"[{sc}]{rs.cvss_score:.1f}[/{sc}]",
            f"[{sc}]{rs.composite_score:.1f}[/{sc}]",
            f"{rs.epss_score:.3f}",
            f"[{sc}]{rs.risk_tier}[/{sc}]",
            exp,
            f"[{avc}]{av}[/{avc}]",
            ports_str or "—",
            v.get("matched_service", "—")[:13],
        )
    _console.print(t)


def _print_remediation_table(tasks: list[RemediationTask]) -> None:
    t = Table(
        title="Remediation Plan",
        box=box.ROUNDED, border_style="green",
        header_style="bold green", show_lines=False,
    )
    t.add_column("#",       width=4)
    t.add_column("CVE",     width=18, style="bold white", no_wrap=True)
    t.add_column("Effort",  width=12)
    t.add_column("Days",    width=6)
    t.add_column("Ports",   width=10)
    t.add_column("Action",  overflow="fold")

    eff_col = {"IMMEDIATE":"red","SHORT":"magenta","MEDIUM":"yellow","LONG":"cyan"}

    for task in tasks[:20]:
        ec    = eff_col.get(task.effort, "white")
        ports = ",".join(str(p) for p in task.affected_ports)
        t.add_row(
            str(task.priority),
            task.cve_id,
            f"[{ec}]{task.effort}[/{ec}]",
            str(task.effort_days),
            ports or "—",
            task.action[:120],
        )
    _console.print(t)


def _print_attack_surface(surface: dict[str, Any]) -> None:
    t = Table(
        title="Attack Surface Overview",
        box=box.ROUNDED, border_style="cyan",
        header_style="bold cyan",
    )
    t.add_column("Category",  style="bold white", width=22)
    t.add_column("Details",   overflow="fold")

    by_av = surface.get("by_attack_vector", {})
    for av, cves in by_av.items():
        sc = "red" if av == "NETWORK" else "yellow" if av == "ADJACENT" else "white"
        t.add_row(
            f"[{sc}]AV:{av[:3]}[/{sc}]",
            f"{len(cves)} CVE(s) — {', '.join(cves[:5])}{'…' if len(cves) > 5 else ''}",
        )

    t.add_section()
    for cluster, cves in surface.get("by_service_cluster", {}).items():
        t.add_row(f"Cluster: {cluster}", f"{len(cves)} CVE(s)")

    net_crit = surface.get("network_critical_count", 0)
    t.add_section()
    col = "red" if net_crit > 0 else "green"
    t.add_row("Network CRIT/HIGH", f"[{col}]{net_crit}[/{col}]")
    _console.print(t)


def _print_chain_table(paths: list[AttackPath]) -> None:
    if not paths:
        return
    t = Table(
        title="Detected Attack Chains",
        box=box.ROUNDED, border_style="red",
        header_style="bold red",
    )
    t.add_column("Chain",       width=4)
    t.add_column("Likelihood",  width=10)
    t.add_column("Impact",      overflow="fold", width=40)
    t.add_column("Steps",       overflow="fold")

    for p in paths:
        steps_str = " → ".join(
            f"[{s.get('cve', '?')}] port {s.get('port', '?')}"
            for s in p.steps
        )
        lc = "red" if p.likelihood == "HIGH" else "yellow"
        t.add_row(
            str(p.path_id),
            f"[{lc}]{p.likelihood}[/{lc}]",
            p.impact,
            steps_str,
        )
    _console.print(t)


def _print_overall_banner(overall: str, score: float, counts: dict[str, int]) -> None:
    col = _SEV_COL.get(overall, "white")
    lines = [
        f"[bold {col}]Overall Risk: {overall}  (score {score:.2f})[/bold {col}]",
        "",
    ]
    for sev in cfg.SEVERITY_ORDER:
        n  = counts.get(sev, 0)
        sc = _SEV_COL.get(sev, "white")
        bar = "█" * min(n, 30)
        lines.append(f"  [{sc}]{sev:<10}[/{sc}]  [{sc}]{bar}[/{sc}]  {n}")

    _console.print(Panel(
        "\n".join(lines),
        title="[bold white]Risk Analysis Summary[/bold white]",
        border_style=col,
        box=box.DOUBLE_EDGE,
        expand=True,
    ))


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

class RiskEngine:
    """
    Transforms CVE records into a fully enriched, prioritised risk summary.
    """

    def __init__(self, vulnerabilities: list[dict]):
        self._vulns = vulnerabilities

    def run(self) -> dict:
        if not self._vulns:
            log.warn("No vulnerabilities to analyse.")
            return RiskSummary().to_dict()

        log.info(f"Analysing {len(self._vulns)} vulnerability record(s)...")

        # ── Step 1: Multi-factor scoring ──────────────────────────────────────
        scorer = MultiFactorScorer()
        scores = scorer.score_all(self._vulns)
        log.info(f"  Multi-factor scoring complete — {len(scores)} records")

        # ── Step 2: EPSS estimation ───────────────────────────────────────────
        EPSSClient().annotate(scores, self._vulns)
        log.info("  EPSS scores fetched")

        # ── Step 3: Attack surface mapping ────────────────────────────────────
        surface = AttackSurfaceMapper().map(self._vulns, scores)
        log.info(f"  Attack surface: {surface.get('exposed_clusters', [])} clusters exposed")

        # ── Step 4: Attack chain detection ────────────────────────────────────
        chains = ChainDetector().detect(self._vulns)
        log.info(f"  {len(chains)} attack chain(s) detected")

        # ── Step 5: Remediation plan ──────────────────────────────────────────
        tasks = RemediationPlanner().plan(self._vulns, scores)
        log.info(f"  {len(tasks)} remediation task(s) generated")

        # ── Step 6: Severity counts ───────────────────────────────────────────
        counts: dict[str, int] = {s: 0 for s in cfg.SEVERITY_ORDER}
        for rs in scores:
            counts[rs.risk_tier] = counts.get(rs.risk_tier, 0) + 1

        # ── Step 7: Overall risk ──────────────────────────────────────────────
        overall, agg_score = _overall_risk(scores)

        # ── Statistics ────────────────────────────────────────────────────────
        cvss_vals = [rs.cvss_score for rs in scores if rs.cvss_score > 0]
        comp_vals = [rs.composite_score for rs in scores]
        epss_vals = [rs.epss_score for rs in scores]

        stats = {
            "total":               len(scores),
            "with_exploit":        sum(1 for v in self._vulns if v.get("has_exploit")),
            "network_exploitable": sum(1 for v in self._vulns
                                       if v.get("cvss", {}).get("attack_vector") == "NETWORK"),
            "no_auth_required":    sum(1 for v in self._vulns
                                       if v.get("cvss", {}).get("privileges_required") == "NONE"),
            "cvss_mean":           round(statistics.mean(cvss_vals), 2) if cvss_vals else 0.0,
            "cvss_max":            max(cvss_vals, default=0.0),
            "composite_mean":      round(statistics.mean(comp_vals), 2) if comp_vals else 0.0,
            "composite_max":       max(comp_vals, default=0.0),
            "epss_mean":           round(statistics.mean(epss_vals), 3) if epss_vals else 0.0,
            "epss_max":            max(epss_vals, default=0.0),
        }

        # ── Print output ──────────────────────────────────────────────────────
        _print_overall_banner(overall, agg_score, counts)
        _print_risk_matrix(scores)
        _print_top_risks(scores, self._vulns)
        _print_attack_surface(surface)
        _print_chain_table(chains)
        _print_remediation_table(tasks)

        log.success(
            f"Risk analysis complete — overall={overall}  "
            f"score={agg_score:.2f}  "
            f"critical={counts.get('CRITICAL',0)}  "
            f"high={counts.get('HIGH',0)}"
        )

        summary = RiskSummary(
            counts           = counts,
            top_risks        = [asdict(s) for s in scores[:20]],
            risk_scores      = [asdict(s) for s in scores],
            attack_surface   = surface,
            attack_paths     = [asdict(p) for p in chains],
            remediation_plan = [asdict(t) for t in tasks],
            statistics       = stats,
            overall_risk     = overall,
            risk_score       = agg_score,
        )
        return summary.to_dict()
