"""
Stage 7 — Report Generation
Produces five output formats from the shared ScanResult dict.

Builders:
  PDFBuilder      — ReportLab Platypus: cover page, TOC, charts, headers/footers
  HTMLBuilder     — Self-contained HTML with embedded CSS, severity colour coding
  JSONExporter    — Clean structured JSON dump with report metadata
  MarkdownExporter— GitHub-flavoured Markdown for CI/CD pipelines
  CSVExporter     — CVE findings CSV for ticketing system import
  ReportGenerator — Orchestrator: runs all enabled builders, prints index table
"""
from __future__ import annotations

import csv
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie

from rich.console import Console
from rich.table import Table as RichTable
from rich import box

from utils.logger import log
from utils.exceptions import ReportError
from config import cfg

_console = Console(highlight=False)

# ── Colour palette ────────────────────────────────────────────────────────────
_C = {
    "bg_dark":    colors.HexColor("#1A1A2E"),
    "bg_mid":     colors.HexColor("#16213E"),
    "accent":     colors.HexColor("#E94560"),
    "accent2":    colors.HexColor("#0F3460"),
    "CRITICAL":   colors.HexColor("#FF0000"),
    "HIGH":       colors.HexColor("#FF6B35"),
    "MEDIUM":     colors.HexColor("#FFD23F"),
    "LOW":        colors.HexColor("#06AED5"),
    "NONE":       colors.HexColor("#888888"),
    "white":      colors.white,
    "light_grey": colors.HexColor("#F5F5F5"),
    "mid_grey":   colors.HexColor("#CCCCCC"),
    "dark_grey":  colors.HexColor("#444444"),
    "green":      colors.HexColor("#28A745"),
    "text":       colors.HexColor("#222222"),
}

W, H = A4  # 595.28 × 841.89 pts


# ══════════════════════════════════════════════════════════════════════════════
# ReportLab custom styles
# ══════════════════════════════════════════════════════════════════════════════

def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    s = {}

    def ps(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    s["cover_title"]   = ps("cover_title",   fontSize=32, textColor=_C["white"],
                             alignment=TA_CENTER, fontName="Helvetica-Bold",
                             spaceAfter=8, leading=40)
    s["cover_sub"]     = ps("cover_sub",     fontSize=14, textColor=_C["accent"],
                             alignment=TA_CENTER, fontName="Helvetica", spaceAfter=4)
    s["cover_meta"]    = ps("cover_meta",    fontSize=10, textColor=_C["mid_grey"],
                             alignment=TA_CENTER, fontName="Helvetica")
    s["h1"]            = ps("h1",            fontSize=16, textColor=_C["accent"],
                             fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6,
                             borderPad=4)
    s["h2"]            = ps("h2",            fontSize=13, textColor=_C["accent2"],
                             fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
    s["h3"]            = ps("h3",            fontSize=11, textColor=_C["dark_grey"],
                             fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=3)
    s["body"]          = ps("body",          fontSize=9,  textColor=_C["text"],
                             leading=14, spaceAfter=4)
    s["body_small"]    = ps("body_small",    fontSize=8,  textColor=_C["dark_grey"],
                             leading=12)
    s["table_header"]  = ps("table_header",  fontSize=8,  textColor=_C["white"],
                             fontName="Helvetica-Bold", alignment=TA_CENTER)
    s["table_cell"]    = ps("table_cell",    fontSize=8,  textColor=_C["text"],
                             leading=12)
    s["severity_badge"] = ps("severity_badge", fontSize=8, fontName="Helvetica-Bold",
                              alignment=TA_CENTER, textColor=_C["white"])
    s["footer"]        = ps("footer",        fontSize=7,  textColor=_C["mid_grey"],
                             alignment=TA_CENTER)
    s["confidential"]  = ps("confidential",  fontSize=8,  textColor=_C["accent"],
                             alignment=TA_CENTER, fontName="Helvetica-Bold")
    s["toc_entry"]     = ps("toc_entry",     fontSize=9,  textColor=_C["text"],
                             leading=14)
    s["finding_label"] = ps("finding_label", fontSize=8,  textColor=_C["dark_grey"],
                             fontName="Helvetica-Bold")
    return s


# ══════════════════════════════════════════════════════════════════════════════
# ReportLab helpers
# ══════════════════════════════════════════════════════════════════════════════

def _sev_colour(severity: str) -> colors.Color:
    return _C.get(severity.upper(), _C["NONE"])


def _styled_table(data: list[list], col_widths: list[float],
                  _styles: dict, header: bool = True) -> Table:
    ts = [
        ("FONTNAME",  (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",  (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [_C["white"], _C["light_grey"]]),
        ("GRID",      (0,0), (-1,-1), 0.4, _C["mid_grey"]),
        ("VALIGN",    (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING",  (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING",   (0,0), (-1,-1), 3),
        ("BOTTOMPADDING",(0,0), (-1,-1), 3),
    ]
    if header:
        ts += [
            ("BACKGROUND",  (0,0), (-1,0), _C["bg_mid"]),
            ("TEXTCOLOR",   (0,0), (-1,0), _C["white"]),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,0), 8),
            ("ALIGN",       (0,0), (-1,0), "CENTER"),
        ]
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    t.setStyle(TableStyle(ts))
    return t


def _severity_bar(counts: dict[str, int], width: float = 380, height: float = 80) -> Drawing:
    """Horizontal bar chart — severity distribution."""
    d    = Drawing(width, height)
    sevs = [s for s in cfg.SEVERITY_ORDER if s != "NONE"]
    vals = [counts.get(s, 0) for s in sevs]
    total = max(sum(vals), 1)

    bar_h  = 12
    gap    = 8
    x_lbl  = 65
    x_bar  = x_lbl + 5
    max_w  = width - x_bar - 40

    for i, (sev, val) in enumerate(zip(sevs, vals)):
        y      = height - (i + 1) * (bar_h + gap)
        bw     = (val / total) * max_w
        colour = _sev_colour(sev)

        # Label
        d.add(String(x_lbl - 3, y + 2, sev[:4], fontSize=7,
                     fillColor=colors.HexColor("#444444"), textAnchor="end"))
        # Bar background
        d.add(Rect(x_bar, y, max_w, bar_h,
                   fillColor=colors.HexColor("#EEEEEE"), strokeColor=None))
        # Filled bar
        if bw > 0:
            d.add(Rect(x_bar, y, bw, bar_h,
                       fillColor=colour, strokeColor=None))
        # Count label
        d.add(String(x_bar + bw + 3, y + 2, str(val), fontSize=7,
                     fillColor=colors.HexColor("#222222")))

    return d


def _severity_pie(counts: dict[str, int], size: float = 120) -> Drawing:
    """Pie chart of severity distribution."""
    d    = Drawing(size, size)
    sevs = [(s, counts.get(s, 0)) for s in cfg.SEVERITY_ORDER if counts.get(s, 0)]
    if not sevs:
        return d

    pie = Pie()
    pie.x, pie.y = 10, 10
    pie.width = pie.height = size - 20
    pie.data   = [v for _, v in sevs]
    pie.labels = [f"{s}: {v}" for s, v in sevs]
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = colors.white
    for i, (sev, _) in enumerate(sevs):
        pie.slices[i].fillColor = _sev_colour(sev)
    pie.sideLabels = True
    pie.sideLabelsOffset = 0.05
    d.add(pie)
    return d


# ══════════════════════════════════════════════════════════════════════════════
# PDF Builder
# ══════════════════════════════════════════════════════════════════════════════

class _NumberedCanvas:
    """Mixin applied via BaseDocTemplate to draw header/footer on every page."""
    pass


class PDFBuilder:
    def __init__(self, data: dict, path: str):
        self._data  = data
        self._path  = path
        self._S     = _build_styles()
        self._story: list = []
        self._toc   = TableOfContents()
        self._toc.levelStyles = [
            ParagraphStyle("TOC1", fontSize=9, leading=14, leftIndent=0),
            ParagraphStyle("TOC2", fontSize=8, leading=12, leftIndent=12),
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _h1(self, text: str) -> None:
        key = text.replace(" ", "_")
        self._story.append(
            Paragraph(f'<a name="{key}"/>{text}', self._S["h1"])
        )
        self._story.append(HRFlowable(width="100%", thickness=1.5,
                                       color=_C["accent"], spaceAfter=6))

    def _h2(self, text: str) -> None:
        self._story.append(Paragraph(text, self._S["h2"]))

    def _body(self, text: str) -> None:
        self._story.append(Paragraph(text, self._S["body"]))

    def _space(self, h: float = 8) -> None:
        self._story.append(Spacer(1, h))

    def _pagebreak(self) -> None:
        self._story.append(PageBreak())

    def _kv_table(self, rows: list[tuple[str, str]]) -> None:
        data = [[Paragraph(k, self._S["finding_label"]),
                 Paragraph(str(v), self._S["body"])]
                for k, v in rows]
        t = Table(data, colWidths=[1.8 * inch, 4.7 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (0,-1), _C["light_grey"]),
            ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.4, _C["mid_grey"]),
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING", (0,0), (-1,-1), 5),
            ("TOPPADDING",  (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0),(-1,-1), 3),
        ]))
        self._story.append(t)

    # ── Page template (header + footer) ───────────────────────────────────────
    def _make_doc(self) -> BaseDocTemplate:
        doc = BaseDocTemplate(
            self._path, pagesize=A4,
            leftMargin=0.7*inch, rightMargin=0.7*inch,
            topMargin=1.0*inch,  bottomMargin=0.8*inch,
            title="R3CON-X Security Assessment Report",
            author="R3CON-X Framework",
        )

        def _header_footer(canvas, doc):
            canvas.saveState()
            # Header bar
            canvas.setFillColor(_C["bg_mid"])
            canvas.rect(0, H - 0.55*inch, W, 0.55*inch, fill=1, stroke=0)
            canvas.setFillColor(_C["accent"])
            canvas.setFont("Helvetica-Bold", 10)
            canvas.drawString(0.7*inch, H - 0.35*inch, "R3CON-X  Security Assessment Report")
            canvas.setFillColor(_C["mid_grey"])
            canvas.setFont("Helvetica", 8)
            target = self._data.get("meta", {}).get("target", "")
            canvas.drawRightString(W - 0.7*inch, H - 0.35*inch,
                                   f"Target: {target}  |  CONFIDENTIAL")
            # Footer
            canvas.setFillColor(_C["mid_grey"])
            canvas.rect(0, 0, W, 0.55*inch, fill=1, stroke=0)
            canvas.setFillColor(_C["white"])
            canvas.setFont("Helvetica", 7)
            ts = self._data.get("meta", {}).get("timestamp", "")
            canvas.drawString(0.7*inch, 0.22*inch,
                              f"Generated: {ts}  |  R3CON-X v2.0.0  |  For Authorized Use Only")
            canvas.drawRightString(W - 0.7*inch, 0.22*inch,
                                   f"Page {doc.page}")
            canvas.restoreState()

        frame = Frame(0.7*inch, 0.7*inch, W - 1.4*inch, H - 1.55*inch)
        doc.addPageTemplates([
            PageTemplate("main", frames=[frame], onPage=_header_footer)
        ])
        return doc

    # ── Cover page ────────────────────────────────────────────────────────────
    def _build_cover(self) -> None:
        meta    = self._data.get("meta", {})
        target  = meta.get("target", "N/A")
        ip      = meta.get("ip", "N/A")
        ts      = meta.get("timestamp", "N/A")
        profile = meta.get("profile", "N/A")

        # Dark background panel
        bg = Table(
            [[Paragraph("R3CON-X", self._S["cover_title"])],
             [Paragraph("Reconnaissance & Vulnerability Intelligence Report",
                         self._S["cover_sub"])],
             [Spacer(1, 20)],
             [Paragraph(f"Target: {target}", self._S["cover_meta"])],
             [Paragraph(f"IP Address: {ip}", self._S["cover_meta"])],
             [Paragraph(f"Scan Date: {ts}", self._S["cover_meta"])],
             [Paragraph(f"Profile: {profile}", self._S["cover_meta"])],
             [Spacer(1, 20)],
             [Paragraph("CONFIDENTIAL — For Authorized Use Only",
                         self._S["confidential"])],
             ],
            colWidths=[W - 1.4*inch],
        )
        bg.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), _C["bg_dark"]),
            ("TOPPADDING",   (0,0), (-1,-1), 14),
            ("BOTTOMPADDING",(0,0), (-1,-1), 14),
            ("LEFTPADDING",  (0,0), (-1,-1), 20),
            ("RIGHTPADDING", (0,0), (-1,-1), 20),
            ("BOX",          (0,0), (-1,-1), 2, _C["accent"]),
        ]))
        self._story.append(Spacer(1, 1.2*inch))
        self._story.append(bg)
        self._pagebreak()

    # ── Table of contents ─────────────────────────────────────────────────────
    def _build_toc(self) -> None:
        self._h1("Table of Contents")
        self._story.append(self._toc)
        self._pagebreak()

    # ── Executive summary ─────────────────────────────────────────────────────
    def _build_executive_summary(self) -> None:
        self._h1("1. Executive Summary")
        meta    = self._data.get("meta", {})
        risk    = self._data.get("risk_summary", {})
        counts  = risk.get("counts", {})
        overall = risk.get("overall_risk", "N/A")
        stats   = risk.get("statistics", {})
        vulns   = self._data.get("vulnerabilities", [])
        ports   = self._data.get("active_scan", {}).get("open_ports", [])

        col = _sev_colour(overall)
        self._body(
            f"This report presents the results of an automated security assessment "
            f"conducted against <b>{meta.get('target','N/A')}</b> "
            f"({meta.get('ip','N/A')}) on {meta.get('timestamp','N/A')}. "
            f"The overall risk rating for this target is "
            f"<font color='#{col.hexval()[2:]}'><b>{overall}</b></font>."
        )
        self._space()

        # Summary stats table
        sev_rows = []
        for sev in cfg.SEVERITY_ORDER:
            n   = counts.get(sev, 0)
            sc  = _sev_colour(sev)
            sev_rows.append([
                sev,
                Paragraph(str(n),
                          ParagraphStyle("_", fontName="Helvetica-Bold", fontSize=9,
                                         textColor=sc, alignment=TA_CENTER)),
            ])

        summary_data = [["Metric", "Value"]] + [
            ["Target",            meta.get("target", "—")],
            ["IP Address",        meta.get("ip", "—")],
            ["Scan Profile",      meta.get("profile", "—")],
            ["Port Range",        meta.get("ports", "—")],
            ["Open Ports",        str(len(ports))],
            ["Total CVEs",        str(len(vulns))],
            ["With Exploit",      str(stats.get("with_exploit", 0))],
            ["Network Exploitable",str(stats.get("network_exploitable", 0))],
            ["CVSS Mean / Max",   f"{stats.get('cvss_mean',0):.1f} / {stats.get('cvss_max',0):.1f}"],
            ["Composite Mean/Max",f"{stats.get('composite_mean',0):.1f} / {stats.get('composite_max',0):.1f}"],
        ]

        left  = _styled_table(summary_data, [2.0*inch, 3.0*inch], self._S)
        right = Table(
            [["Severity Distribution"]] + sev_rows,
            colWidths=[1.2*inch, 0.8*inch],
        )
        right.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), _C["bg_mid"]),
            ("TEXTCOLOR",   (0,0), (-1,0), _C["white"]),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("GRID",        (0,0), (-1,-1), 0.4, _C["mid_grey"]),
            ("ALIGN",       (1,0), (1,-1), "CENTER"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [_C["white"], _C["light_grey"]]),
            ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ]))

        wrap = Table([[left, right]], colWidths=[5.2*inch, 2.1*inch])
        wrap.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "TOP"),
                                   ("LEFTPADDING", (0,0), (-1,-1), 0),
                                   ("RIGHTPADDING", (0,0), (-1,-1), 6)]))
        self._story.append(wrap)
        self._space(10)

        # Severity bar chart
        self._h2("Severity Distribution")
        self._story.append(_severity_bar(counts))
        self._space()

    # ── Passive recon ─────────────────────────────────────────────────────────
    def _build_passive_recon(self) -> None:
        pr = self._data.get("passive_recon", {})
        if not pr:
            return
        self._pagebreak()
        self._h1("2. Passive Reconnaissance")

        # Zone transfer (critical — show first)
        zt = pr.get("zone_transfer", {})
        if zt.get("vulnerable"):
            self._story.append(
                Paragraph("🚨  ZONE TRANSFER SUCCEEDED — Critical DNS Misconfiguration",
                          ParagraphStyle("_crit", fontSize=10, fontName="Helvetica-Bold",
                                         textColor=_C["CRITICAL"]))
            )
            self._space()

        # DNSSEC + dangling CNAMEs
        dnssec = pr.get("dnssec_enabled", False)
        dangling = pr.get("dangling_cnames", [])
        self._story.append(
            Paragraph(
                f"DNSSEC: {'✓ Enabled' if dnssec else '✗ Not detected'}   "
                + (f"  |  Dangling CNAMEs: {', '.join(dangling)}" if dangling else ""),
                ParagraphStyle("_dns_meta", fontSize=8, textColor=_C["LOW"], leading=12),
            )
        )
        self._space()

        # Threat Intel
        threat = pr.get("threat_intel", {})
        if threat:
            self._h2("Threat Intelligence")
            score = threat.get("reputation_score", 100)
            hits  = threat.get("dnsbl_hits", [])
            self._story.append(
                Paragraph(
                    f"Reputation Score: {score}/100   "
                    + (f"DNSBL listed on: {', '.join(hits)}" if hits else "Not listed on any DNSBL"),
                    ParagraphStyle("_ti", fontSize=8, textColor=_C["HIGH"] if hits else _C["LOW"], leading=12),
                )
            )
            self._space()

        # ASN / GeoIP
        asn = pr.get("asn_geo", {})
        if asn.get("asn") or asn.get("org"):
            self._h2("ASN / GeoIP")
            rows = [["Field", "Value"]]
            for field, key in [
                ("ASN", "asn"), ("Network", "network_name"), ("Org / ISP", "org"),
                ("Location", "city"), ("Country", "country"), ("Timezone", "timezone"),
                ("Abuse Email", "abuse_email"),
            ]:
                val = asn.get(key, "")
                if val:
                    rows.append([field, str(val)[:80]])
            self._story.append(_styled_table(rows, [1.5*inch, 5.8*inch], self._S))
            self._space()

        # DNS Records
        dns = pr.get("dns_records", {})
        if dns:
            self._h2("DNS Records")
            rows = [["Type", "TTL", "Value"]]
            for rtype, recs in dns.items():
                for r in recs:
                    rows.append([rtype, str(r.get("ttl","")), r.get("value","")[:80]])
            self._story.append(_styled_table(rows, [0.6*inch, 0.6*inch, 6.1*inch], self._S))
            self._space()

        # Subdomains
        subs = pr.get("subdomains", [])
        if subs:
            self._h2(f"Subdomains ({len(subs)} found)")
            rows = [["FQDN", "IP", "Source", "Takeover Risk"]]
            for s in subs[:40]:
                rows.append([
                    s.get("fqdn",""), s.get("ip","—"), s.get("source",""),
                    s.get("takeover_service","") if s.get("takeover_risk") else "",
                ])
            self._story.append(_styled_table(rows, [3.0*inch, 1.3*inch, 1.0*inch, 1.5*inch], self._S))
            self._space()

        # Subdomain takeover risks
        takeovers = pr.get("takeover_risks", [])
        if takeovers:
            self._h2(f"Subdomain Takeover Risks ({len(takeovers)})")
            rows = [["Subdomain", "Vulnerable Service", "IP"]]
            for s in takeovers:
                rows.append([s.get("fqdn",""), s.get("takeover_service",""), s.get("ip","—")])
            self._story.append(_styled_table(rows, [3.2*inch, 2.4*inch, 1.7*inch], self._S))
            self._space()

        # WHOIS
        whois = pr.get("whois", {})
        if whois.get("registrar"):
            self._h2("WHOIS Information")
            skip = {"raw", "status"}
            rows: list = [["Field", "Value"]]
            for k, v in whois.items():
                if k in skip or not v:
                    continue
                if isinstance(v, list):
                    rows.append([k, ", ".join(str(x) for x in v[:5])])
                elif isinstance(v, bool):
                    rows.append([k, "Yes" if v else "No"])
                elif isinstance(v, int) and v >= 0:
                    rows.append([k, str(v)])
                elif isinstance(v, str) and v:
                    rows.append([k, v[:120]])
            self._story.append(_styled_table(rows, [1.8*inch, 5.5*inch], self._S))
            self._space()

        # Mail security
        ms = pr.get("mail_security", {})
        if ms:
            self._h2("Mail Security")
            checks = [
                ["SPF",     "OK" if ms.get("spf_valid") else "FAIL",     ms.get("spf_record","—")[:60]],
                ["DMARC",   "OK" if ms.get("dmarc_policy") not in ("","none") else "WARN", ms.get("dmarc_record","—")[:60]],
                ["DKIM",    "OK" if ms.get("dkim_selectors") else "WARN", ", ".join(ms.get("dkim_selectors",[])) or "—"],
                ["BIMI",    "OK" if ms.get("bimi_record") else "—",       ms.get("bimi_record","not configured")[:50]],
                ["MTA-STS", ms.get("mta_sts_policy","—") or "—",          ""],
                ["TLS-RPT", "OK" if ms.get("tls_rpt_record") else "—",    ""],
            ]
            self._story.append(_styled_table(
                [["Check", "Status", "Detail"]] + checks,
                [0.8*inch, 0.8*inch, 5.7*inch], self._S,
            ))
            for issue in ms.get("issues", []):
                self._story.append(
                    Paragraph(f"⚠  {issue}",
                              ParagraphStyle("_warn", fontSize=8, textColor=_C["HIGH"], leading=12))
                )
            self._space()

        # Wayback Machine
        wb = pr.get("wayback", {})
        if wb.get("total_urls", 0) > 0:
            self._h2("Wayback Machine History")
            self._story.append(Paragraph(
                f"Total captures: {wb['total_urls']}  |  "
                f"Unique paths: {len(wb.get('endpoints',[]))}  |  "
                f"First: {wb.get('oldest_snapshot','?')[:8]}  |  "
                f"Last: {wb.get('newest_snapshot','?')[:8]}",
                ParagraphStyle("_wb", fontSize=8, textColor=_C["LOW"], leading=12),
            ))
            eps = wb.get("endpoints", [])[:20]
            if eps:
                rows = [["#", "Historical Path"]] + [[str(i+1), p] for i, p in enumerate(eps)]
                self._story.append(_styled_table(rows, [0.4*inch, 6.9*inch], self._S))
            self._space()

    # ── Active scan ───────────────────────────────────────────────────────────
    def _build_active_scan(self) -> None:
        scan = self._data.get("active_scan", {})
        ports = scan.get("open_ports", [])
        self._pagebreak()
        self._h1("3. Active Scan Results")

        meta_rows = [
            ("Total Open Ports", str(scan.get("total_open", 0))),
            ("Hostname",         scan.get("hostname", "—")),
            ("MAC Address",      scan.get("mac", "—")),
            ("Vendor",           scan.get("vendor", "—")),
            ("Scan Time",        f"{scan.get('scan_time', 0)}s"),
        ]
        os_guesses = scan.get("os_guesses", [])
        if os_guesses:
            best = os_guesses[0]
            meta_rows.append(("OS Guess",
                              f"{best.get('name','')} ({best.get('accuracy','')}%)"))
        self._kv_table(meta_rows)
        self._space()

        if ports:
            self._h2("Open Ports & Services")
            rows = [["Port", "Proto", "State", "Service", "Product / Version",
                     "CPE", "Banner"]]
            for p in ports:
                cpe = p.get("cpe", [""])[0][:30] if p.get("cpe") else "—"
                banner = (p.get("banner","")[:35] + "…"
                          if len(p.get("banner","")) > 35
                          else p.get("banner","")) or "—"
                rows.append([
                    str(p.get("port","")),
                    p.get("protocol",""),
                    p.get("state",""),
                    p.get("service",""),
                    f"{p.get('product','')} {p.get('version','')}".strip() or "—",
                    cpe, banner,
                ])
            self._story.append(_styled_table(
                rows,
                [0.55*inch, 0.5*inch, 0.55*inch, 0.8*inch,
                 1.8*inch, 1.7*inch, 1.3*inch],
                self._S,
            ))

    # ── Web enumeration ───────────────────────────────────────────────────────
    def _build_web_enum(self) -> None:
        we = self._data.get("web_enum", {})
        if not we or not we.get("base_url"):
            return
        self._pagebreak()
        self._h1("4. Web Enumeration")

        self._kv_table([
            ("Base URL",      we.get("base_url", "—")),
            ("Status Code",   str(we.get("status_code", "—"))),
            ("Server",        we.get("server", "—")),
            ("Header Score",  f"{we.get('header_score', 0)}/100"),
            ("WAF",           we.get("waf", "None detected")),
            ("Page Title",    we.get("page_title", "—")),
            ("Meta Generator",we.get("meta_generator", "—")),
        ])
        self._space()

        # TLS
        tls = we.get("tls", {})
        if tls.get("subject"):
            self._h2("TLS Certificate")
            self._kv_table([
                ("Subject",       tls.get("subject","")),
                ("Issuer",        tls.get("issuer","")),
                ("TLS Version",   tls.get("tls_version","")),
                ("Cipher",        tls.get("cipher","")),
                ("Expires",       tls.get("not_after","")),
                ("Days Remaining",str(tls.get("days_remaining",""))),
                ("Self-Signed",   "YES ⚠" if tls.get("self_signed") else "No"),
            ])
            self._space()

        # Security headers
        hdrs = we.get("headers", [])
        if hdrs:
            self._h2("Security Headers")
            rows = [["Header", "Status", "Severity", "Detail"]]
            for h in hdrs:
                status = "OK" if h.get("present") else "MISSING"
                rows.append([
                    h.get("header","")[:35],
                    status,
                    h.get("severity","") if not h.get("present") else "",
                    (h.get("message") or h.get("value",""))[:60],
                ])
            self._story.append(_styled_table(
                rows, [2.2*inch, 0.7*inch, 0.8*inch, 3.6*inch], self._S
            ))
            self._space()

        # Sensitive files
        sens = we.get("sensitive_files", [])
        if sens:
            self._h2(f"Sensitive Files Exposed ({len(sens)})")
            rows = [["URL", "HTTP Status", "Note"]]
            for f in sens:
                rows.append([f.get("url","")[:60], str(f.get("status","")),
                             f.get("note","")[:40]])
            self._story.append(_styled_table(
                rows, [4.2*inch, 0.9*inch, 2.2*inch], self._S
            ))
            self._space()

        # CORS
        cors = we.get("cors", {})
        if cors.get("severity") in ("CRITICAL","HIGH"):
            self._story.append(
                Paragraph(
                    f"⚠  CORS Misconfiguration [{cors.get('severity','')}]: "
                    f"{cors.get('detail','')}",
                    ParagraphStyle("_cors", fontSize=8, textColor=_C["CRITICAL"],
                                   leading=12, fontName="Helvetica-Bold"),
                )
            )

    # ── CVE findings ──────────────────────────────────────────────────────────
    def _build_cve_findings(self) -> None:
        vulns = self._data.get("vulnerabilities", [])
        self._pagebreak()
        self._h1("5. Vulnerability Findings")

        if not vulns:
            self._body("No vulnerabilities were identified for the detected services.")
            return

        self._body(
            f"The CVE correlation engine identified <b>{len(vulns)}</b> unique "
            f"vulnerabilities across the discovered services. The table below "
            f"presents findings ordered by composite risk score."
        )
        self._space()

        rows = [["CVE ID","CVSS","Comp.","Severity","Exploit","AV","Port(s)","Description"]]
        for v in vulns[:50]:
            sev    = v.get("severity","NONE")
            sc     = _sev_colour(sev)
            exp    = "YES" if v.get("has_exploit") else "no"
            av     = v.get("cvss",{}).get("attack_vector","")[:3]
            ports  = ",".join(str(p) for p in v.get("matched_ports",[]))
            score  = v.get("score", v.get("cvss",{}).get("base_score",0))
            comp   = v.get("composite_score", score)

            rows.append([
                v.get("cve_id",""),
                f"{float(score):.1f}",
                f"{float(comp):.1f}" if comp else "—",
                Paragraph(sev, ParagraphStyle("_s", fontSize=7, textColor=sc,
                                              fontName="Helvetica-Bold",
                                              alignment=TA_CENTER)),
                exp, av, ports,
                v.get("description","")[:100],
            ])

        self._story.append(_styled_table(
            rows,
            [1.2*inch, 0.55*inch, 0.55*inch, 0.75*inch,
             0.55*inch, 0.45*inch, 0.65*inch, 3.0*inch],
            self._S,
        ))

    # ── Risk analysis ─────────────────────────────────────────────────────────
    def _build_risk_analysis(self) -> None:
        risk  = self._data.get("risk_summary", {})
        tasks = risk.get("remediation_plan", [])
        paths = risk.get("attack_paths", [])
        stats = risk.get("statistics", {})

        self._pagebreak()
        self._h1("6. Risk Analysis")

        self._kv_table([
            ("Overall Risk",    risk.get("overall_risk","—")),
            ("Risk Score",      f"{risk.get('risk_score',0):.2f}"),
            ("CVSS Mean",       f"{stats.get('cvss_mean',0):.2f}"),
            ("CVSS Max",        f"{stats.get('cvss_max',0):.2f}"),
            ("Composite Mean",  f"{stats.get('composite_mean',0):.2f}"),
            ("EPSS Max",        f"{stats.get('epss_max',0):.3f}"),
        ])
        self._space()

        if paths:
            self._h2("Attack Chains Detected")
            for p in paths:
                steps = " → ".join(
                    f"[{s.get('cve','?')}] port {s.get('port','?')}"
                    for s in p.get("steps",[])
                )
                self._story.append(
                    Paragraph(
                        f"<b>Chain {p.get('path_id','')}</b>  "
                        f"[{p.get('likelihood','')}]  {p.get('description','')} "
                        f"— Impact: {p.get('impact','')} — {steps}",
                        ParagraphStyle("_chain", fontSize=8, textColor=_C["HIGH"],
                                       leading=13, leftIndent=10),
                    )
                )
            self._space()

        if tasks:
            self._h2("Remediation Plan")
            rows = [["#","CVE ID","Effort","Days","Ports","Action"]]
            for t in tasks[:25]:
                eff_c = {
                    "IMMEDIATE": _C["CRITICAL"], "SHORT": _C["HIGH"],
                    "MEDIUM":    _C["MEDIUM"],   "LONG":  _C["LOW"],
                }.get(t.get("effort",""), _C["text"])
                rows.append([
                    str(t.get("priority","")),
                    t.get("cve_id",""),
                    Paragraph(t.get("effort",""),
                              ParagraphStyle("_e", fontSize=7, textColor=eff_c,
                                             fontName="Helvetica-Bold",
                                             alignment=TA_CENTER)),
                    str(t.get("effort_days","")),
                    ",".join(str(p) for p in t.get("affected_ports",[])),
                    t.get("action","")[:90],
                ])
            self._story.append(_styled_table(
                rows,
                [0.3*inch, 1.2*inch, 0.8*inch, 0.45*inch, 0.6*inch, 3.9*inch],
                self._S,
            ))

    # ── Appendix ──────────────────────────────────────────────────────────────
    def _build_appendix(self) -> None:
        self._pagebreak()
        self._h1("7. Appendix — Methodology & Scope")
        self._body(
            "R3CON-X performs a seven-stage automated assessment: "
            "(1) Input Validation, (2) Passive Reconnaissance, (3) Active Scanning, "
            "(4) Web Enumeration, (5) CVE Correlation via NVD API v2, "
            "(6) Multi-Factor Risk Analysis, (7) Report Generation."
        )
        self._space()
        self._body(
            "CVSS scores are sourced from the National Vulnerability Database (NVD). "
            "Composite risk scores extend CVSS with exploit availability, attack vector, "
            "privilege requirements, scope, and CVE age factors. "
            "EPSS values are estimated via a logistic regression heuristic."
        )
        self._space()
        self._body(
            "<b>Disclaimer:</b> This report was generated by an automated tool. "
            "Results should be validated by a qualified security professional. "
            "False positives may exist. All testing was conducted with explicit authorisation."
        )

    # ── Build ─────────────────────────────────────────────────────────────────
    def build(self) -> None:
        self._build_cover()
        self._h1("Table of Contents")
        self._story.append(self._toc)
        self._pagebreak()
        self._build_executive_summary()
        self._build_passive_recon()
        self._build_active_scan()
        self._build_web_enum()
        self._build_cve_findings()
        self._build_risk_analysis()
        self._build_appendix()

        doc = self._make_doc()
        try:
            doc.multiBuild(self._story)
        except Exception as e:
            raise ReportError(f"PDF build failed: {e}", detail=str(e))
        log.success(f"PDF report → {self._path}")


# ══════════════════════════════════════════════════════════════════════════════
# HTML Builder
# ══════════════════════════════════════════════════════════════════════════════

_SEV_HEX = {
    "CRITICAL": "#FF0000", "HIGH": "#FF6B35",
    "MEDIUM": "#FFD23F",   "LOW": "#06AED5",
    "NONE": "#888888",
}

_HTML_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,Arial,sans-serif;background:#0b0b14;color:#d4d4e8;font-size:13px;line-height:1.5}
a{color:#06aed5;text-decoration:none}a:hover{text-decoration:underline}
.header{background:linear-gradient(135deg,#12122a 0%,#1a1a3e 100%);border-bottom:3px solid #e94560;padding:22px 48px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100;box-shadow:0 2px 16px #000a}
.header h1{color:#fff;font-size:20px;font-weight:700;letter-spacing:-0.3px}
.header h1 span{color:#e94560}
.header .meta{color:#8888aa;font-size:11px;text-align:right;line-height:1.8}
.header .meta strong{color:#d4d4e8}
.toc{background:#12122a;border:1px solid #2a2a4e;border-radius:8px;padding:16px 24px;margin:0 auto 28px;max-width:900px}
.toc h3{color:#e94560;font-size:13px;margin-bottom:10px;text-transform:uppercase;letter-spacing:1px}
.toc ol{padding-left:20px;color:#888;font-size:12px;line-height:2}
.toc a{color:#06aed5}
.container{max-width:1180px;margin:0 auto;padding:32px 24px}
.section{background:#12122a;border-radius:10px;margin-bottom:28px;padding:26px 30px;border-left:4px solid #e94560;box-shadow:0 2px 8px #0005}
.section-blue{border-left-color:#06aed5}
.section-green{border-left-color:#22c55e}
.section-orange{border-left-color:#FF6B35}
h2{color:#fff;font-size:15px;font-weight:600;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #2a2a4e;display:flex;align-items:center;gap:8px}
h2::before{content:'';display:inline-block;width:4px;height:16px;background:#e94560;border-radius:2px}
h3{color:#06aed5;font-size:12px;font-weight:600;margin:18px 0 8px;text-transform:uppercase;letter-spacing:0.8px}
table{width:100%;border-collapse:collapse;font-size:12px;margin:10px 0;border-radius:6px;overflow:hidden}
thead{position:sticky;top:72px;z-index:10}
th{background:#1a1a3e;color:#e94560;padding:9px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.6px;white-space:nowrap}
td{padding:7px 12px;border-bottom:1px solid #1e1e38;vertical-align:top}
tr:nth-child(even) td{background:#0f0f22}
tr:hover td{background:#1a2040;transition:background 0.1s}
code{background:#1e1e38;padding:1px 5px;border-radius:3px;font-size:11px;color:#c8c8ff;font-family:monospace}
.badge{display:inline-block;padding:2px 9px;border-radius:12px;font-weight:700;font-size:10px;color:#fff;letter-spacing:0.4px;text-transform:uppercase}
/* Severity badges */
.sev-CRITICAL{background:#7f0000}.sev-HIGH{background:#b04000}.sev-MEDIUM{background:#7a5a00}.sev-LOW{background:#005a7a}.sev-NONE{background:#333}
/* Risk cards */
.risk-panel{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin:16px 0}
.risk-card{background:#1a1a3e;border-radius:8px;padding:18px 14px;text-align:center;border-top:3px solid;transition:transform 0.15s}
.risk-card:hover{transform:translateY(-2px)}
.risk-card .count{font-size:36px;font-weight:800;line-height:1}.risk-card .label{font-size:10px;color:#888;margin-top:6px;text-transform:uppercase;letter-spacing:1px}
/* Stat grid */
.stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:16px 0}
.stat-box{background:#1a1a3e;padding:16px;border-radius:8px;text-align:center;border:1px solid #2a2a4e}
.stat-box .val{font-size:26px;font-weight:800;color:#06aed5}
.stat-box .lbl{font-size:10px;color:#888;margin-top:4px;text-transform:uppercase;letter-spacing:0.8px}
/* Chart bars (pure CSS) */
.bar-chart{display:flex;align-items:flex-end;gap:10px;height:100px;padding:8px 0}
.bar{flex:1;border-radius:4px 4px 0 0;min-width:30px;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;font-size:10px;font-weight:700;color:#fff;padding-bottom:4px;transition:opacity 0.2s}
.bar:hover{opacity:0.85}
.bar-label{font-size:10px;color:#888;text-align:center;margin-top:4px;text-transform:uppercase}
.chart-wrap{margin:10px 0 4px}
/* Exploit indicators */
.exploit-yes{color:#FF4444;font-weight:700}.exploit-no{color:#555}
/* Misc */
.tag{display:inline-block;background:#1e1e38;border:1px solid #3a3a5e;padding:2px 8px;border-radius:4px;font-size:11px;color:#aaa;margin:2px}
.note{color:#888;font-size:11px;font-style:italic;padding:8px 0}
.alert{background:#1f0a0a;border:1px solid #7f0000;border-radius:6px;padding:10px 14px;margin:6px 0;font-size:12px}
.alert-warn{background:#1f1600;border-color:#7a5a00}
.alert-info{background:#0a0f1f;border-color:#005a7a}
.footer{text-align:center;color:#444;padding:36px;font-size:11px;border-top:1px solid #1e1e38;margin-top:40px;letter-spacing:0.4px}
pre{background:#0a0a16;padding:12px;border-radius:6px;overflow-x:auto;font-size:11px;color:#aaa;border:1px solid #2a2a4e}
.chain-item{background:#1a1a3e;border-left:3px solid #FF6B35;padding:12px 16px;margin:8px 0;border-radius:0 6px 6px 0}
.chain-item strong{color:#FF6B35}
/* Scrollable table wrapper */
.tbl-wrap{overflow-x:auto}
/* Sidebar nav dots */
.progress-ring{width:36px;height:36px;margin:0 auto 8px}
"""

class HTMLBuilder:
    def __init__(self, data: dict, path: str):
        self._data = data
        self._path = path

    def _badge(self, sev: str) -> str:
        col = _SEV_HEX.get(sev.upper(), "#888")
        return f'<span class="badge" style="background:{col}">{sev}</span>'

    def _section(self, title: str, content: str) -> str:
        return f'<div class="section"><h2>{title}</h2>{content}</div>'

    def _table(self, headers: list[str], rows: list[list[str]]) -> str:
        ths = "".join(f"<th>{h}</th>" for h in headers)
        trs = ""
        for r in rows:
            tds = "".join(f"<td>{c}</td>" for c in r)
            trs += f"<tr>{tds}</tr>"
        return f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"

    def _bar_chart(self, counts: dict) -> str:
        total = max(sum(counts.values()), 1)
        bars  = ""
        for sev in cfg.SEVERITY_ORDER:
            n   = counts.get(sev, 0)
            col = _SEV_HEX.get(sev, "#888")
            pct = int(n / total * 90) + 10 if n else 4
            bars += (
                f'<div style="display:flex;flex-direction:column;align-items:center;flex:1">'
                f'<div class="bar" style="background:{col};height:{pct}px;width:100%;'
                f'border-radius:4px 4px 0 0;display:flex;align-items:flex-start;'
                f'padding-top:4px;justify-content:center;font-size:11px;font-weight:700">'
                f'{"" if n == 0 else n}</div>'
                f'<div class="bar-label">{sev[:4]}</div></div>'
            )
        return f'<div class="bar-chart" style="display:flex;gap:8px;align-items:flex-end;height:110px">{bars}</div>'

    def build(self) -> None:
        meta    = self._data.get("meta", {})
        risk    = self._data.get("risk_summary", {})
        counts  = risk.get("counts", {})
        vulns   = self._data.get("vulnerabilities", [])
        ports   = self._data.get("active_scan", {}).get("open_ports", [])
        stats   = risk.get("statistics", {})
        overall = risk.get("overall_risk", "NONE")
        ov_col  = _SEV_HEX.get(overall, "#888")
        web     = self._data.get("web_enum", {})
        passive = self._data.get("passive_recon", {})

        # ── Risk cards ────────────────────────────────────────────────────────
        risk_cards = ""
        for sev in cfg.SEVERITY_ORDER:
            col = _SEV_HEX.get(sev, "#888")
            n   = counts.get(sev, 0)
            risk_cards += (
                f'<div class="risk-card" style="border-color:{col}">'
                f'<div class="count" style="color:{col}">{n}</div>'
                f'<div class="label">{sev}</div></div>'
            )

        # ── Stat grid ─────────────────────────────────────────────────────────
        stat_grid = ""
        for lbl, val in [
            ("Open Ports",       len(ports)),
            ("Total CVEs",       len(vulns)),
            ("With Exploit",     stats.get("with_exploit", 0)),
            ("Network Exposed",  stats.get("network_exploitable", 0)),
            ("CVSS Max",         f"{stats.get('cvss_max', 0):.1f}"),
            ("EPSS Max",         f"{stats.get('epss_max', 0):.3f}"),
            ("Overall Risk",     f'<span style="color:{ov_col};font-weight:700">{overall}</span>'),
            ("Subdomains",       len(passive.get("subdomains", []))),
            ("Directories",      len(web.get("directories", []))),
        ]:
            stat_grid += (
                f'<div class="stat-box"><div class="val">{val}</div>'
                f'<div class="lbl">{lbl}</div></div>'
            )

        # ── CVE table ─────────────────────────────────────────────────────────
        cve_rows = []
        for v in vulns[:100]:
            sev   = v.get("severity", "NONE")
            exp   = ('<span class="exploit-yes">&#x26A0; YES</span>'
                     if v.get("has_exploit")
                     else '<span class="exploit-no">—</span>')
            ports_str = ", ".join(str(p) for p in v.get("matched_ports", []))
            score = v.get("score", v.get("cvss", {}).get("base_score", 0))
            epss  = v.get("epss_score", 0)
            desc  = v.get("description", "")
            cve_rows.append([
                f'<code>{v.get("cve_id","")}</code>',
                f'<strong>{float(score):.1f}</strong>',
                self._badge(sev),
                exp,
                f'{epss:.3f}',
                v.get("cvss", {}).get("attack_vector", "")[:3],
                ports_str or "—",
                v.get("matched_product", "")[:22],
                f'<span title="{desc}">{desc[:100]}{"…" if len(desc)>100 else ""}</span>',
            ])

        # ── Port table ────────────────────────────────────────────────────────
        port_rows = [
            [f'<strong>{p.get("port","")}</strong>',
             p.get("protocol", ""),
             f'<code>{p.get("service","")}</code>',
             f"{p.get('product','')} {p.get('version','')}".strip() or "—",
             f'<code style="color:#777">{p.get("cpe",[""])[0][:40]}</code>'
             if p.get("cpe") else "—",
             p.get("banner", "")[:50].replace("\n", " ") or "—"]
            for p in ports
        ]

        # ── Remediation table ─────────────────────────────────────────────────
        eff_cols = {"IMMEDIATE": "#FF0000", "SHORT": "#FF6B35",
                    "MEDIUM": "#FFD23F", "LONG": "#06AED5"}
        rem_rows = []
        for task in risk.get("remediation_plan", [])[:30]:
            ec = eff_cols.get(task.get("effort", ""), "#888")
            rem_rows.append([
                f'<strong>{task.get("priority","")}</strong>',
                f'<code>{task.get("cve_id","")}</code>',
                f'<span style="color:{ec};font-weight:700">{task.get("effort","")}</span>',
                str(task.get("effort_days", "")),
                task.get("action", "")[:120],
            ])

        # ── Attack chains ─────────────────────────────────────────────────────
        chains_html = ""
        for path in risk.get("attack_paths", []):
            steps = " &rarr; ".join(
                f'<code>{s.get("cve","?")}</code> '
                f'<span style="color:#888">(port {s.get("port","?")})</span>'
                for s in path.get("steps", [])
            )
            chains_html += (
                f'<div class="chain-item">'
                f'<strong>Chain {path.get("path_id","")}</strong> &nbsp;'
                f'<span class="tag">{path.get("likelihood","")}</span>'
                f'<span style="color:#aaa;margin-left:8px">{path.get("description","")}</span>'
                f'<div style="margin-top:6px;font-size:11px">{steps}</div>'
                f'<div style="margin-top:4px;color:#888;font-size:11px">'
                f'Impact: {path.get("impact","")}</div>'
                f'</div>'
            )

        # ── Security headers table ────────────────────────────────────────────
        hdr_rows = []
        for h in web.get("headers", []):
            status = "&#10003; OK" if h.get("present") else "&#10007; MISSING"
            sev_s  = h.get("severity", "")
            col    = _SEV_HEX.get(sev_s, "#888") if sev_s else "#22c55e"
            hdr_rows.append([
                f'<code>{h.get("header","")}</code>',
                f'<span style="color:{col}">{status}</span>',
                self._badge(sev_s) if sev_s else "",
                h.get("message","") or h.get("value","")[:80],
            ])

        # ── Discovered paths table ────────────────────────────────────────────
        dir_rows = [
            [f'<span style="color:#FFD23F">{d.get("status","")}</span>',
             f'<a href="{d.get("url","")}" target="_blank">{d.get("url","")}</a>',
             str(d.get("size","")) + "B",
             f'<span class="tag" style="color:#FF4444">SENSITIVE</span>'
             if d.get("sensitive") else d.get("note","")]
            for d in web.get("directories", [])[:60]
        ]

        # ── DNS records ───────────────────────────────────────────────────────
        dns_rows = []
        for rtype, records in passive.get("dns_records", {}).items():
            for rec in records:
                dns_rows.append([rtype, str(rec.get("ttl","")), rec.get("value","")])

        # ── Subdomains ────────────────────────────────────────────────────────
        sub_rows = [
            [s.get("fqdn",""), s.get("ip","") or "—", s.get("source",""),
             f'<span style="color:#FF4444">&#9888; {s.get("takeover_service","")}</span>'
             if s.get("takeover_risk") else ""]
            for s in passive.get("subdomains", [])[:80]
        ]

        # ── Subdomain takeover risks ──────────────────────────────────────────
        takeover_rows = [
            [s.get("fqdn",""), s.get("takeover_service",""), s.get("ip","") or "—"]
            for s in passive.get("takeover_risks", [])
        ]

        # ── Threat intel ──────────────────────────────────────────────────────
        threat      = passive.get("threat_intel", {})
        dnsbl_hits  = threat.get("dnsbl_hits", [])
        rep_score   = threat.get("reputation_score", 100)
        rep_color   = "#FF4444" if rep_score < 60 else ("#FFD23F" if rep_score < 85 else "#22c55e")

        # ── Wayback data ──────────────────────────────────────────────────────
        wb           = passive.get("wayback", {})
        wb_endpoints = wb.get("endpoints", [])[:20]

        # ── WHOIS enhanced ────────────────────────────────────────────────────
        whois         = passive.get("whois", {})
        whois_age     = whois.get("domain_age_days", -1)
        whois_expiry  = whois.get("expiry_days", -1)
        whois_privacy = whois.get("privacy_protected", False)

        # ── ASN / GeoIP ───────────────────────────────────────────────────────
        asn = passive.get("asn_geo", {})

        # ── Mail security ─────────────────────────────────────────────────────
        ms = passive.get("mail_security", {})

        # ── Google dorks ──────────────────────────────────────────────────────
        dork_rows = [[str(i+1), d] for i, d in enumerate(passive.get("google_dorks", []))]

        # ── Nikto findings ────────────────────────────────────────────────────
        nikto_html = ""
        for finding in web.get("nikto_findings", []):
            nikto_html += f'<div class="alert alert-warn">&#9888; {finding}</div>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>R3CON-X Report &mdash; {meta.get('target','')}</title>
  <style>{_HTML_CSS}</style>
</head>
<body>

<div class="header">
  <div>
    <h1><span>R3CON&#8209;X</span> Security Assessment Report</h1>
    <div style="color:#666;font-size:11px;margin-top:4px">
      Reconnaissance &amp; Vulnerability Intelligence Framework &mdash; v2.0.0
    </div>
  </div>
  <div class="meta">
    Target:&nbsp;<strong>{meta.get('target','')}</strong><br>
    IP:&nbsp;{meta.get('ip','') or 'N/A'}&nbsp;&nbsp;
    Profile:&nbsp;<strong>{meta.get('profile','')}</strong><br>
    Generated:&nbsp;{meta.get('timestamp','')}
  </div>
</div>

<div class="container">

  <!-- Table of Contents -->
  <div class="toc">
    <h3>Contents</h3>
    <ol>
      <li><a href="#executive">Executive Summary</a></li>
      <li><a href="#ports">Open Ports &amp; Services</a></li>
      <li><a href="#web">Web Enumeration</a></li>
      <li><a href="#passive">Passive Reconnaissance</a></li>
      <li><a href="#cves">CVE Findings ({len(vulns)})</a></li>
      <li><a href="#chains">Attack Chains</a></li>
      <li><a href="#remediation">Remediation Plan</a></li>
    </ol>
  </div>

  <!-- Executive Summary -->
  <div class="section" id="executive">
    <h2>Executive Summary</h2>
    <div class="risk-panel">{risk_cards}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:16px">
      <div>
        <h3>Severity Distribution</h3>
        {self._bar_chart(counts)}
      </div>
      <div>
        <h3>Key Metrics</h3>
        <div class="stat-grid" style="grid-template-columns:repeat(3,1fr)">{stat_grid}</div>
      </div>
    </div>
    {'<div class="alert" style="margin-top:16px">&#128680; <strong>CRITICAL findings require immediate attention.</strong> Network-exploitable vulnerabilities with known public exploits were detected.</div>' if counts.get("CRITICAL",0) > 0 else ''}
    {f'<div class="alert alert-warn" style="margin-top:8px">&#9888; WAF detected: <strong>{web.get("waf","")}</strong> — some findings may be partially mitigated.</div>' if web.get("waf") else ""}
  </div>

  <!-- Open Ports -->
  <div class="section section-blue" id="ports">
    <h2>Open Ports &amp; Services</h2>
    {"<p class='note'>No open TCP ports detected. Host may be firewalled.</p>" if not port_rows else
    f'<div class="tbl-wrap">{self._table(["Port","Proto","Service","Product / Version","CPE","Banner"], port_rows)}</div>'}
  </div>

  <!-- Web Enumeration -->
  <div class="section section-blue" id="web">
    <h2>Web Enumeration</h2>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
      <div>
        {''.join(f'<div class="tag">{k}: <strong>{v}</strong></div>' for k,v in [
          ("Base URL", web.get("base_url","—")),
          ("Status",   web.get("status_code","—")),
          ("Server",   web.get("server","—") or "—"),
          ("WAF",      web.get("waf","") or "none"),
          ("Header Score", f'{web.get("header_score",0)}/100'),
          ("Tech",     ", ".join(t for ts in web.get("technologies",{}).values() for t in ts) or "—"),
        ])}
      </div>
      <div>
        {''.join(f'<div class="tag">TLS: <strong>{web.get("tls",{}).get("tls_version","—")}</strong> &nbsp; Cipher: {web.get("tls",{}).get("cipher","—")[:20]} &nbsp; Expires: {web.get("tls",{}).get("days_remaining","?")} days</div>' if web.get("tls",{}).get("tls_version") else "")}
        {''.join(f'<div class="alert" style="margin-top:6px">CORS CRITICAL: credentials + wildcard reflection</div>' if web.get("cors",{}).get("severity")=="CRITICAL" else "")}
        {('<div class="tag" style="color:#FF4444">&#9888; Dangerous HTTP methods: ' + ", ".join(web.get("dangerous_methods",[])) + '</div>') if web.get("dangerous_methods") else ""}
      </div>
    </div>
    <h3>Security Headers</h3>
    <div class="tbl-wrap">{self._table(["Header","Status","Severity","Detail"], hdr_rows)}</div>
    {'<h3>Discovered Paths (' + str(len(web.get("directories",[]))) + ')</h3><div class="tbl-wrap">' + self._table(["Status","URL","Size","Note"], dir_rows) + '</div>' if dir_rows else ''}
    {('<h3>Nikto Findings</h3>' + nikto_html) if nikto_html else ''}
  </div>

  <!-- Passive Recon -->
  <div class="section section-green" id="passive">
    <h2>Passive Reconnaissance</h2>

    <!-- DNSSEC + Dangling CNAMEs -->
    <div style="margin-bottom:12px">
      {'<span class="tag" style="color:#22c55e">&#10003; DNSSEC Enabled</span>' if passive.get("dnssec_enabled") else '<span class="tag" style="color:#FFD23F">&#9888; DNSSEC Not Detected</span>'}
      {(' &nbsp; <span class="tag" style="color:#FF4444">&#9888; Dangling CNAMEs: ' + ', '.join(passive.get('dangling_cnames',[])) + '</span>') if passive.get('dangling_cnames') else ''}
    </div>

    <!-- Threat Intel -->
    <h3>Threat Intelligence</h3>
    <div style="margin-bottom:12px">
      <span class="tag" style="color:{rep_color}">Reputation Score: {rep_score}/100</span>
      {(' &nbsp; <span class="tag" style="color:#FF4444">DNSBL Listed: ' + ', '.join(dnsbl_hits) + '</span>') if dnsbl_hits else ' &nbsp; <span class="tag" style="color:#22c55e">Not listed on any DNSBL</span>'}
    </div>

    <!-- ASN / GeoIP -->
    <h3>ASN &amp; Geolocation</h3>
    <div class="tbl-wrap">{self._table(["Field","Value"], [r for r in [
      ["ASN",          asn.get("asn","—")],
      ["Network",      (asn.get("network_name","") + " — " + asn.get("asn_cidr","")).strip(" —") or "—"],
      ["Org / ISP",    (asn.get("org","") + " / " + asn.get("isp","")).strip(" /") or "—"],
      ["Location",     ", ".join(filter(None,[asn.get("city"),asn.get("region"),asn.get("country")])) or "—"],
      ["Timezone",     asn.get("timezone","—")],
      ["Abuse Email",  asn.get("abuse_email","—")],
      ["Abuse Phone",  asn.get("abuse_phone","—")],
    ] if r[1] and r[1] != "—"])}</div>

    <!-- WHOIS -->
    {('<h3>WHOIS</h3><div class="tbl-wrap">' + self._table(["Field","Value"], [r for r in [
      ["Registrar",        whois.get("registrar","—")],
      ["Registrant Org",   whois.get("registrant_org","—")],
      ["Country",          whois.get("registrant_country","—")],
      ["Created",          whois.get("creation_date","—")],
      ["Expires",          whois.get("expiry_date","—")],
      ["Domain Age",       (str(whois_age) + " days (" + str(whois_age//365) + " yr)") if whois_age >= 0 else "—"],
      ["Days to Expiry",   ('<span style="color:#FF4444">' + str(whois_expiry) + "</span>") if whois_expiry <= 30 and whois_expiry != -1 else str(whois_expiry) if whois_expiry != -1 else "—"],
      ["Privacy",          "Yes" if whois_privacy else "No"],
      ["Emails Found",     ", ".join(whois.get("emails",[])[:5]) or "—"],
      ["Name Servers",     ", ".join(whois.get("name_servers",[])[:4]) or "—"],
    ] if r[1] and r[1] not in ("—","No")]) + '</div>') if whois else ""}

    <!-- DNS Records -->
    {('<h3>DNS Records</h3><div class="tbl-wrap">' + self._table(["Type","TTL","Value"], dns_rows) + '</div>') if dns_rows else ""}

    <!-- Subdomains -->
    {('<h3>Subdomains (' + str(len(passive.get("subdomains",[]))) + ' found)</h3><div class="tbl-wrap">' + self._table(["FQDN","IP","Source","Takeover Risk"], sub_rows) + '</div>') if sub_rows else ""}

    <!-- Subdomain Takeover Risks -->
    {('<h3 style="color:#FF4444">&#9888; Subdomain Takeover Risks (' + str(len(takeover_rows)) + ')</h3>'
      + '<div class="alert">These subdomains point to unclaimed external services and may be hijackable.</div>'
      + '<div class="tbl-wrap">' + self._table(["Subdomain","Service","IP"], takeover_rows) + '</div>')
     if takeover_rows else ""}

    <!-- Mail Security -->
    <h3>Mail Security</h3>
    <div class="tbl-wrap">{self._table(["Check","Status","Detail"], [
      ["SPF",       "&#10003; OK" if ms.get("spf_valid") else "&#10007; FAIL",    ms.get("spf_record","—")[:80]],
      ["DMARC",     "&#10003; OK" if ms.get("dmarc_policy") not in ("","none") else "&#9888; WARN",  ms.get("dmarc_record","—")[:80]],
      ["DKIM",      "&#10003; OK" if ms.get("dkim_selectors") else "&#9888; WARN", ", ".join(ms.get("dkim_selectors",[])) or "—"],
      ["BIMI",      "&#10003; OK" if ms.get("bimi_record") else "—",              ms.get("bimi_record","not configured")[:60]],
      ["MTA-STS",   "&#10003; OK" if ms.get("mta_sts_policy")=="enforce" else ("&#9888; TESTING" if ms.get("mta_sts_policy")=="testing" else "—"), ms.get("mta_sts_policy","not configured")],
      ["TLS-RPT",   "&#10003; OK" if ms.get("tls_rpt_record") else "—",          ms.get("tls_rpt_record","not configured")[:60]],
    ])}</div>
    {('<h3>Mail Security Issues</h3>' + "".join(f'<div class="alert alert-warn">&#9888; {i}</div>' for i in ms.get("issues",[]))) if ms.get("issues") else ""}

    <!-- Wayback Machine -->
    {('<h3>Wayback Machine History</h3>'
      + f'<div style="margin-bottom:8px"><span class="tag">{wb.get("total_urls",0)} captures</span> &nbsp;'
      + f'<span class="tag">{len(wb.get("endpoints",[]))} unique paths</span> &nbsp;'
      + f'<span class="tag">First: {wb.get("oldest_snapshot","?")[:8]}</span> &nbsp;'
      + f'<span class="tag">Last: {wb.get("newest_snapshot","?")[:8]}</span></div>'
      + ('<div class="tbl-wrap">' + self._table(["#","Historical Path"], [[str(i+1),p] for i,p in enumerate(wb_endpoints)]) + '</div>' if wb_endpoints else ""))
     if wb.get("total_urls",0) > 0 else ""}

    <!-- Google Dorks -->
    {('<h3>Google Dork Queries <span style="color:#888;font-size:11px">(paste into Google manually)</span></h3>'
      + '<div class="tbl-wrap">' + self._table(["#","Query"], dork_rows) + '</div>')
     if dork_rows else ""}

  </div>

  <!-- CVE Findings -->
  <div class="section section-orange" id="cves">
    <h2>CVE Findings &mdash; {len(vulns)} vulnerabilities</h2>
    {"<p class='note'>No vulnerabilities found for detected services.</p>" if not cve_rows else
    f'<div class="tbl-wrap">{self._table(["CVE ID","CVSS","Severity","Exploit","EPSS","AV","Ports","Product","Description"], cve_rows)}</div>'}
  </div>

  <!-- Attack Chains -->
  <div class="section section-orange" id="chains">
    <h2>Attack Chains</h2>
    {chains_html or "<p class='note'>No multi-step attack chains detected.</p>"}
  </div>

  <!-- Remediation -->
  <div class="section" id="remediation">
    <h2>Remediation Plan</h2>
    {"<p class='note'>No remediation tasks generated.</p>" if not rem_rows else
    f'<div class="tbl-wrap">{self._table(["#","CVE","Effort","Days","Recommended Action"], rem_rows)}</div>'}
  </div>

  <div class="footer">
    R3CON&#8209;X v2.0.0 &nbsp;&mdash;&nbsp; <strong>CONFIDENTIAL</strong> &nbsp;&mdash;&nbsp;
    For Authorized Security Assessment Use Only<br>
    Generated: {meta.get('timestamp','')}
  </div>

</div>
</body>
</html>"""

        with open(self._path, "w", encoding="utf-8") as f:
            f.write(html)
        log.success(f"HTML report → {self._path}")


# ══════════════════════════════════════════════════════════════════════════════
# JSON Exporter
# ══════════════════════════════════════════════════════════════════════════════

class JSONExporter:
    def __init__(self, data: dict, path: str):
        self._data = data
        self._path = path

    def export(self) -> None:
        payload = {
            "generator":  "R3CON-X v2.0.0",
            "exported_at": datetime.now().isoformat(),
            **self._data,
        }
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        log.success(f"JSON report → {self._path}")


# ══════════════════════════════════════════════════════════════════════════════
# Markdown Exporter
# ══════════════════════════════════════════════════════════════════════════════

class MarkdownExporter:
    def __init__(self, data: dict, path: str):
        self._data = data
        self._path = path

    def export(self) -> None:
        meta   = self._data.get("meta", {})
        risk   = self._data.get("risk_summary", {})
        counts = risk.get("counts", {})
        vulns  = self._data.get("vulnerabilities", [])
        ports  = self._data.get("active_scan", {}).get("open_ports", [])

        lines = [
            "# R3CON-X Security Assessment Report",
            "",
            f"> **Target:** `{meta.get('target','')}` | "
            f"**IP:** `{meta.get('ip','')}` | "
            f"**Date:** {meta.get('timestamp','')} | "
            f"**Profile:** {meta.get('profile','')}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"| Risk Level | Count |",
            f"|------------|-------|",
        ]
        for sev in cfg.SEVERITY_ORDER:
            lines.append(f"| {sev} | {counts.get(sev, 0)} |")
        lines += [
            "",
            f"**Overall Risk:** `{risk.get('overall_risk','—')}`  "
            f"**Score:** `{risk.get('risk_score',0):.2f}`",
            "",
            "---",
            "",
            "## Open Ports",
            "",
            "| Port | Protocol | Service | Product | Version |",
            "|------|----------|---------|---------|---------|",
        ]
        for p in ports:
            lines.append(
                f"| {p.get('port','')} | {p.get('protocol','')} | "
                f"{p.get('service','')} | {p.get('product','')} | "
                f"{p.get('version','')} |"
            )
        lines += [
            "",
            "---",
            "",
            f"## Vulnerability Findings ({len(vulns)} CVEs)",
            "",
            "| CVE ID | CVSS | Severity | Exploit | AV | Ports | Description |",
            "|--------|------|----------|---------|-----|-------|-------------|",
        ]
        for v in vulns[:30]:
            exp   = "✔" if v.get("has_exploit") else "✗"
            av    = v.get("cvss",{}).get("attack_vector","")[:3]
            ports_str = ",".join(str(p) for p in v.get("matched_ports",[]))
            score = v.get("score", v.get("cvss",{}).get("base_score",0))
            desc  = v.get("description","")[:80].replace("|","∣")
            lines.append(
                f"| {v.get('cve_id','')} | {float(score):.1f} | "
                f"{v.get('severity','')} | {exp} | {av} | {ports_str} | {desc} |"
            )
        lines += [
            "",
            "---",
            "",
            "## Remediation Plan",
            "",
            "| # | CVE | Effort | Days | Action |",
            "|---|-----|--------|------|--------|",
        ]
        for t in risk.get("remediation_plan", [])[:15]:
            action = t.get("action","")[:80].replace("|","∣")
            lines.append(
                f"| {t.get('priority','')} | {t.get('cve_id','')} | "
                f"{t.get('effort','')} | {t.get('effort_days','')} | {action} |"
            )
        lines += [
            "",
            "---",
            "",
            "*Generated by R3CON-X v2.0.0 — CONFIDENTIAL — Authorized Use Only*",
        ]

        with open(self._path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        log.success(f"Markdown report → {self._path}")


# ══════════════════════════════════════════════════════════════════════════════
# CSV Exporter
# ══════════════════════════════════════════════════════════════════════════════

class CSVExporter:
    _FIELDS = [
        "cve_id","score","severity","has_exploit","attack_vector",
        "privileges_required","user_interaction","scope",
        "confidentiality_impact","integrity_impact","availability_impact",
        "matched_port","matched_ports","matched_service","matched_product",
        "matched_version","match_source","epss_score","composite_score",
        "risk_tier","description","published","cwe",
    ]

    def __init__(self, data: dict, path: str):
        self._vulns = data.get("vulnerabilities", [])
        self._path  = path

    def export(self) -> None:
        with open(self._path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self._FIELDS, extrasaction="ignore")
            w.writeheader()
            for v in self._vulns:
                row = dict(v)
                cvss = v.get("cvss", {})
                row["score"]                 = v.get("score", cvss.get("base_score",0))
                row["attack_vector"]         = cvss.get("attack_vector","")
                row["privileges_required"]   = cvss.get("privileges_required","")
                row["user_interaction"]      = cvss.get("user_interaction","")
                row["scope"]                 = cvss.get("scope","")
                row["confidentiality_impact"]= cvss.get("confidentiality_impact","")
                row["integrity_impact"]      = cvss.get("integrity_impact","")
                row["availability_impact"]   = cvss.get("availability_impact","")
                row["matched_ports"]         = ",".join(str(p) for p in v.get("matched_ports",[]))
                row["cwe"]                   = ",".join(v.get("cwe",[]))
                w.writerow(row)
        log.success(f"CSV export → {self._path}")


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
# ══════════════════════════════════════════════════════════════════════════════
# SARIF Exporter  (Static Analysis Results Interchange Format v2.1.0)
# Enables CI/CD integration — GitHub Security tab, VS Code sarif viewer, etc.
# ══════════════════════════════════════════════════════════════════════════════

class SARIFExporter:
    _SARIF_SEV = {
        "CRITICAL": "error", "HIGH": "error",
        "MEDIUM": "warning", "LOW": "note", "NONE": "none",
    }

    def __init__(self, data: dict, path: str):
        self._data = data
        self._path = path

    def export(self) -> None:
        meta  = self._data.get("meta", {})
        vulns = self._data.get("vulnerabilities", [])
        rules = []
        results = []

        for v in vulns:
            cve_id = v.get("cve_id", "")
            sev    = v.get("severity", "NONE")
            score  = float(v.get("score", v.get("cvss", {}).get("base_score", 0)))
            desc   = v.get("description", "")
            refs   = v.get("references", [])

            rules.append({
                "id": cve_id,
                "name": cve_id,
                "shortDescription": {"text": desc[:120]},
                "fullDescription":  {"text": desc},
                "defaultConfiguration": {
                    "level": self._SARIF_SEV.get(sev, "note")
                },
                "helpUri": refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "properties": {
                    "tags": ["security", sev.lower()],
                    "cvss": score,
                    "has_exploit": v.get("has_exploit", False),
                },
            })

            for port in v.get("matched_ports", [v.get("matched_port", 0)]):
                results.append({
                    "ruleId": cve_id,
                    "level": self._SARIF_SEV.get(sev, "note"),
                    "message": {
                        "text": (
                            f"{cve_id} ({sev}, CVSS {score}) on port {port} "
                            f"[{v.get('matched_product','')} {v.get('matched_version','')}]. "
                            f"{desc[:200]}"
                        )
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": meta.get("target", "unknown"),
                                "uriBaseId": "TARGETROOT",
                            },
                            "region": {"startLine": port},
                        }
                    }],
                    "properties": {
                        "security-severity": str(score),
                        "port": port,
                    },
                })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name":           "R3CON-X",
                        "version":        "2.0.0",
                        "informationUri": "https://github.com/r3con-x",
                        "rules":          rules,
                    }
                },
                "results":   results,
                "invocations": [{
                    "executionSuccessful": True,
                    "commandLine": f"r3conx -t {meta.get('target','')}",
                    "startTimeUtc": meta.get("timestamp", ""),
                }],
            }],
        }

        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        log.success(f"SARIF report → {self._path}")


# ══════════════════════════════════════════════════════════════════════════════
# Scan History  (SQLite — tracks every scan for diff/trend analysis)
# ══════════════════════════════════════════════════════════════════════════════

class ScanHistory:
    """Persists scan summaries in a local SQLite database for trend tracking."""

    def __init__(self, db_path: str):
        self._db = db_path
        self._init_db()

    def _init_db(self) -> None:
        con = sqlite3.connect(self._db)
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                target       TEXT,
                ip           TEXT,
                profile      TEXT,
                timestamp    TEXT,
                open_ports   INTEGER,
                total_cves   INTEGER,
                critical     INTEGER,
                high         INTEGER,
                medium       INTEGER,
                low          INTEGER,
                overall_risk TEXT,
                risk_score   REAL,
                with_exploit INTEGER,
                report_json  TEXT
            )
        """)
        con.commit()
        con.close()

    def save(self, data: dict) -> None:
        meta   = data.get("meta", {})
        risk   = data.get("risk_summary", {})
        counts = risk.get("counts", {})
        stats  = risk.get("statistics", {})

        con = sqlite3.connect(self._db)
        con.execute("""
            INSERT INTO scans
              (target,ip,profile,timestamp,open_ports,total_cves,
               critical,high,medium,low,overall_risk,risk_score,with_exploit,report_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            meta.get("target", ""),
            meta.get("ip", ""),
            meta.get("profile", ""),
            meta.get("timestamp", ""),
            data.get("active_scan", {}).get("total_open", 0),
            len(data.get("vulnerabilities", [])),
            counts.get("CRITICAL", 0),
            counts.get("HIGH", 0),
            counts.get("MEDIUM", 0),
            counts.get("LOW", 0),
            risk.get("overall_risk", "NONE"),
            risk.get("risk_score", 0.0),
            stats.get("with_exploit", 0),
            json.dumps({"meta": meta, "counts": counts, "stats": stats}),
        ))
        con.commit()
        con.close()
        log.info(f"  Scan history saved to {self._db}")

    def recent(self, target: str, limit: int = 5) -> list[dict]:
        con = sqlite3.connect(self._db)
        rows = con.execute(
            "SELECT timestamp,total_cves,overall_risk,risk_score FROM scans "
            "WHERE target=? ORDER BY id DESC LIMIT ?",
            (target, limit),
        ).fetchall()
        con.close()
        return [{"timestamp": r[0], "total_cves": r[1],
                 "overall_risk": r[2], "risk_score": r[3]} for r in rows]


@dataclass
class ReportIndex:
    pdf:      str = ""
    html:     str = ""
    json:     str = ""
    markdown: str = ""
    csv:      str = ""
    sarif:    str = ""


class ReportGenerator:
    """
    Orchestrates all report builders.
    Enabled formats are taken from cfg.report.formats (default: pdf, json).
    html / markdown / csv enabled automatically.
    """

    def __init__(self, scan_results: dict, output_dir: str):
        self._data   = scan_results
        self._outdir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        meta   = scan_results.get("meta", {})
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = (meta.get("target","unknown")
                  .replace(".", "_").replace("/","_").replace(":","_"))
        stem   = f"R3CONX_{target}_{ts}"

        self._stem  = stem
        self._index = ReportIndex(
            pdf      = os.path.join(output_dir, f"{stem}.pdf"),
            html     = os.path.join(output_dir, f"{stem}.html"),
            json     = os.path.join(output_dir, f"{stem}.json"),
            markdown = os.path.join(output_dir, f"{stem}.md"),
            csv      = os.path.join(output_dir, f"{stem}_cve.csv"),
            sarif    = os.path.join(output_dir, f"{stem}.sarif"),
        )
        self._history = ScanHistory(os.path.join(output_dir, "scan_history.db"))

    def run(self) -> ReportIndex:
        log.info(f"Generating reports in: {self._outdir}")

        # ── JSON (always) ─────────────────────────────────────────────────────
        JSONExporter(self._data, self._index.json).export()

        # ── CSV ───────────────────────────────────────────────────────────────
        CSVExporter(self._data, self._index.csv).export()

        # ── Markdown ──────────────────────────────────────────────────────────
        MarkdownExporter(self._data, self._index.markdown).export()

        # ── HTML ──────────────────────────────────────────────────────────────
        HTMLBuilder(self._data, self._index.html).build()

        # ── SARIF ─────────────────────────────────────────────────────────────
        SARIFExporter(self._data, self._index.sarif).export()

        # ── PDF ───────────────────────────────────────────────────────────────
        try:
            PDFBuilder(self._data, self._index.pdf).build()
        except ReportError as e:
            log.error(f"PDF generation failed: {e}")
            self._index.pdf = ""

        # ── Scan history ──────────────────────────────────────────────────────
        try:
            self._history.save(self._data)
        except Exception as e:
            log.warn(f"Scan history write failed: {e}")

        # ── Print index table ─────────────────────────────────────────────────
        self._print_index()
        return self._index

    def _print_index(self) -> None:
        t = RichTable(
            title="Generated Reports",
            box=box.ROUNDED, border_style="green",
            header_style="bold green",
        )
        t.add_column("Format",   style="bold white", width=10)
        t.add_column("Path",     overflow="fold")
        t.add_column("Size",     width=10, style="dim")

        for fmt, path in [
            ("PDF",      self._index.pdf),
            ("HTML",     self._index.html),
            ("JSON",     self._index.json),
            ("Markdown", self._index.markdown),
            ("CSV",      self._index.csv),
            ("SARIF",    self._index.sarif),
        ]:
            if path and os.path.exists(path):
                size     = os.path.getsize(path)
                size_str = f"{size//1024}KB" if size > 1024 else f"{size}B"
                t.add_row(fmt, path, size_str)
            elif path:
                t.add_row(fmt, "[red]FAILED[/red]", "—")

        _console.print(t)
