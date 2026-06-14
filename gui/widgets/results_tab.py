import json
import csv
import os
import subprocess
import platform
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTextEdit, QFrame,
    QLineEdit, QComboBox, QGroupBox, QSizePolicy,
    QPushButton, QFileDialog, QMessageBox, QApplication
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from gui.theme import SEV_COLORS
from gui.widgets.gauge_widget import GaugeWidget


def _table(cols: list[str], stretch_col: int = -1) -> QTableWidget:
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setStretchLastSection(True)
    if stretch_col >= 0:
        t.horizontalHeader().setSectionResizeMode(
            stretch_col, QHeaderView.ResizeMode.Stretch)
    return t


def _item(text: str, color: str = "") -> QTableWidgetItem:
    it = QTableWidgetItem(str(text) if text is not None else "—")
    if color:
        it.setForeground(QColor(color))
    return it


class _OverviewTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(18)

        # Summary cards
        cards = QHBoxLayout()
        cards.setSpacing(12)
        self._cards: dict[str, QLabel] = {}

        for key, icon, title, color in [
            ("target", "⌖", "TARGET",          "#00b8d4"),
            ("ip",     "◎", "IP ADDRESS",       "#3b9eff"),
            ("ports",  "⊛", "OPEN PORTS",       "#00ff88"),
            ("vulns",  "⚠", "VULNERABILITIES",  "#ff7b2d"),
            ("risk",   "▲", "RISK LEVEL",       "#ff4757"),
            ("score",  "◈", "RISK SCORE",       "#f59e0b"),
        ]:
            frame = QFrame()
            frame.setObjectName("Card")
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(16, 14, 16, 14)
            fl.setSpacing(4)
            top_row = QHBoxLayout()
            ic = QLabel(icon)
            ic.setStyleSheet(f"color: {color}; font-size: 16px; background: transparent;")
            top_row.addWidget(ic)
            tl = QLabel(title)
            tl.setObjectName("CardTitle")
            top_row.addWidget(tl)
            top_row.addStretch()
            fl.addLayout(top_row)
            vl = QLabel("—")
            vl.setStyleSheet(
                f"color: {color}; font-size: 22px; font-weight: 700;"
                " letter-spacing: -0.5px;")
            fl.addWidget(vl)
            self._cards[key] = vl
            frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            cards.addWidget(frame)
        lay.addLayout(cards)

        # Gauges + severity row
        middle = QHBoxLayout()
        middle.setSpacing(20)

        # Gauges
        gauges_col = QVBoxLayout()
        gauges_row = QHBoxLayout()
        gauges_row.setSpacing(16)
        self._risk_gauge   = GaugeWidget(15,  "Risk Score",   "",     self)
        self._header_gauge = GaugeWidget(100, "Header Score", "/100", self)
        for g in (self._risk_gauge, self._header_gauge):
            g.setFixedSize(145, 145)
            gauges_row.addWidget(g)
        gauges_col.addLayout(gauges_row)
        gauges_col.addStretch()
        middle.addLayout(gauges_col)

        # Severity breakdown
        sev_box = QGroupBox("VULNERABILITY BREAKDOWN")
        sev_lay = QHBoxLayout(sev_box)
        sev_lay.setSpacing(10)
        self._sev_labels: dict[str, QLabel] = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
            col = SEV_COLORS.get(sev, "#4b5e7a")
            vbox = QVBoxLayout()
            vbox.setSpacing(6)
            count_lbl = QLabel("0")
            count_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            count_lbl.setStyleSheet(
                f"color: {col}; font-size: 26px; font-weight: 700;"
                f" background-color: {col}14; border: 1px solid {col}44;"
                f" border-radius: 8px; padding: 10px 18px;"
                f" letter-spacing: -0.5px;")
            vbox.addWidget(count_lbl)
            name_lbl = QLabel(sev)
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_lbl.setStyleSheet(
                f"color: {col}; font-size: 10px; font-weight: 700;"
                f" letter-spacing: 0.8px;")
            vbox.addWidget(name_lbl)
            self._sev_labels[sev] = count_lbl
            sev_lay.addLayout(vbox)
        middle.addWidget(sev_box, stretch=1)
        lay.addLayout(middle)
        lay.addStretch()

    def load(self, data: dict):
        meta    = data.get("meta", {})
        active  = data.get("active_scan", {})
        vulns   = data.get("vulnerabilities", [])
        risk    = data.get("risk_summary", {})
        web     = data.get("web_enum", {})

        self._cards["target"].setText(str(meta.get("target", "—")))
        self._cards["ip"].setText(str(meta.get("ip", "—")))
        self._cards["ports"].setText(str(active.get("total_open", 0)))
        self._cards["vulns"].setText(str(len(vulns)))
        overall = risk.get("overall_risk", "—")
        self._cards["risk"].setText(overall)
        self._cards["risk"].setStyleSheet(
            f"color: {SEV_COLORS.get(overall,'#e0e0e0')};"
            " font-size: 20px; font-weight: bold;")
        score = risk.get("risk_score", 0.0)
        self._cards["score"].setText(f"{score:.2f}")
        self._risk_gauge.setValue(score)
        self._header_gauge.setValue(web.get("header_score", 0))

        counts = risk.get("counts", {})
        for sev, lbl in self._sev_labels.items():
            lbl.setText(str(counts.get(sev, 0)))


class _PassiveTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        lay.addWidget(QLabel("WHOIS / DNS / Subdomains"))

        self._whois = _table(["Field", "Value"])
        self._whois.setMaximumHeight(200)
        lay.addWidget(QLabel("WHOIS"))
        lay.addWidget(self._whois)

        self._dns = _table(["Type", "Name", "Value", "TTL"])
        self._dns.setMaximumHeight(200)
        lay.addWidget(QLabel("DNS Records"))
        lay.addWidget(self._dns)

        self._subs = _table(["Subdomain", "IP", "Takeover Risk"])
        lay.addWidget(QLabel("Subdomains"))
        lay.addWidget(self._subs, stretch=1)

    def load(self, data: dict):
        pr = data.get("passive_recon", {})

        self._whois.setRowCount(0)
        whois = pr.get("whois", {})
        for k, v in (whois if isinstance(whois, dict) else {}).items():
            r = self._whois.rowCount()
            self._whois.insertRow(r)
            self._whois.setItem(r, 0, _item(k, "#00d4ff"))
            self._whois.setItem(r, 1, _item(str(v)))

        self._dns.setRowCount(0)
        for rec in pr.get("dns_records", []):
            if isinstance(rec, dict):
                r = self._dns.rowCount()
                self._dns.insertRow(r)
                self._dns.setItem(r, 0, _item(rec.get("type", "")))
                self._dns.setItem(r, 1, _item(rec.get("name", "")))
                self._dns.setItem(r, 2, _item(rec.get("value", "")))
                self._dns.setItem(r, 3, _item(str(rec.get("ttl", ""))))

        self._subs.setRowCount(0)
        for sub in pr.get("subdomains", []):
            if isinstance(sub, dict):
                r = self._subs.rowCount()
                self._subs.insertRow(r)
                self._subs.setItem(r, 0, _item(sub.get("subdomain", "")))
                self._subs.setItem(r, 1, _item(sub.get("ip", "")))
                risk = sub.get("takeover_risk", False)
                ri = _item("YES" if risk else "no",
                           "#ff4444" if risk else "#00ff88")
                self._subs.setItem(r, 2, ri)


class _ActiveTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        self._ports_tbl = _table(
            ["Port", "Proto", "State", "Service", "Product", "Version", "CPE"])
        lay.addWidget(QLabel("Open Ports"), )
        lay.addWidget(self._ports_tbl, stretch=2)

        self._os_tbl = _table(["OS Guess", "Accuracy"])
        self._os_tbl.setMaximumHeight(120)
        lay.addWidget(QLabel("OS Guesses"))
        lay.addWidget(self._os_tbl)

        self._scripts = QTextEdit()
        self._scripts.setReadOnly(True)
        self._scripts.setMaximumHeight(160)
        self._scripts.setStyleSheet(
            "background-color: #080810; font-family: Consolas, monospace;"
            " font-size: 12px; color: #c0c0d0; border: 1px solid #00ff8818;")
        lay.addWidget(QLabel("Script Output"))
        lay.addWidget(self._scripts)

    def load(self, data: dict):
        ac = data.get("active_scan", {})

        self._ports_tbl.setRowCount(0)
        script_lines = []
        for p in ac.get("open_ports", []):
            r = self._ports_tbl.rowCount()
            self._ports_tbl.insertRow(r)
            col = "#00ff88" if p.get("state") == "OPEN" else "#606070"
            self._ports_tbl.setItem(r, 0, _item(str(p.get("port", "")), "#00d4ff"))
            self._ports_tbl.setItem(r, 1, _item(p.get("protocol", "")))
            self._ports_tbl.setItem(r, 2, _item(p.get("state", ""), col))
            self._ports_tbl.setItem(r, 3, _item(p.get("service", "")))
            self._ports_tbl.setItem(r, 4, _item(p.get("product", "")))
            self._ports_tbl.setItem(r, 5, _item(p.get("version", "")))
            cpes = p.get("cpe", [])
            self._ports_tbl.setItem(r, 6, _item(", ".join(cpes) if cpes else ""))
            for k, v in (p.get("script_out", {}) or {}).items():
                script_lines.append(f"[Port {p.get('port')}] {k}:\n{v}\n")

        self._scripts.setPlainText("\n".join(script_lines) if script_lines else "No script output.")

        self._os_tbl.setRowCount(0)
        for g in ac.get("os_guesses", []):
            r = self._os_tbl.rowCount()
            self._os_tbl.insertRow(r)
            self._os_tbl.setItem(r, 0, _item(g.get("name", "")))
            self._os_tbl.setItem(r, 1, _item(f"{g.get('accuracy', '')}%"))


class _WebTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(10)

        tabs = QTabWidget()
        lay.addWidget(tabs)

        # Headers sub-tab
        hdr_w = QWidget()
        hdr_l = QVBoxLayout(hdr_w)
        self._hdr_tbl = _table(["Header", "Status", "Severity", "Message"])
        hdr_l.addWidget(self._hdr_tbl)
        tabs.addTab(hdr_w, "Security Headers")

        # TLS sub-tab
        tls_w = QWidget()
        tls_l = QVBoxLayout(tls_w)
        self._tls_tbl = _table(["Field", "Value"])
        tls_l.addWidget(self._tls_tbl)
        tabs.addTab(tls_w, "TLS Certificate")

        # Directories sub-tab
        dir_w = QWidget()
        dir_l = QVBoxLayout(dir_w)
        self._dir_tbl = _table(["Status", "Size", "URL", "Note"])
        dir_l.addWidget(self._dir_tbl)
        tabs.addTab(dir_w, "Directories")

        # Cookies sub-tab
        ck_w = QWidget()
        ck_l = QVBoxLayout(ck_w)
        self._ck_tbl = _table(["Name", "Secure", "HttpOnly", "SameSite", "Issues"])
        ck_l.addWidget(self._ck_tbl)
        tabs.addTab(ck_w, "Cookies")

        # Info sub-tab
        info_w = QWidget()
        info_l = QVBoxLayout(info_w)
        self._info_edit = QTextEdit()
        self._info_edit.setReadOnly(True)
        self._info_edit.setStyleSheet(
            "background: #080810; font-family: Consolas, monospace;"
            " font-size: 12px; color: #c0c0d0;")
        info_l.addWidget(self._info_edit)
        tabs.addTab(info_w, "General Info")

    def load(self, data: dict):
        web = data.get("web_enum", {})

        # Headers
        self._hdr_tbl.setRowCount(0)
        for h in web.get("headers", []):
            r = self._hdr_tbl.rowCount()
            self._hdr_tbl.insertRow(r)
            self._hdr_tbl.setItem(r, 0, _item(h.get("header", "")))
            present = h.get("present", False)
            pi = _item("OK" if present else "MISSING",
                       "#00ff88" if present else "#ff4444")
            self._hdr_tbl.setItem(r, 1, pi)
            sev = h.get("severity", "")
            self._hdr_tbl.setItem(r, 2,
                _item(sev, SEV_COLORS.get(sev, "#e0e0e0")))
            self._hdr_tbl.setItem(r, 3, _item(h.get("message", h.get("value", ""))))

        # TLS
        self._tls_tbl.setRowCount(0)
        tls = web.get("tls", {})
        for k, v in tls.items():
            if v in (None, "", [], False):
                continue
            r = self._tls_tbl.rowCount()
            self._tls_tbl.insertRow(r)
            self._tls_tbl.setItem(r, 0, _item(k, "#00d4ff"))
            self._tls_tbl.setItem(r, 1, _item(str(v)))

        # Dirs
        self._dir_tbl.setRowCount(0)
        for d in web.get("directories", []):
            r = self._dir_tbl.rowCount()
            self._dir_tbl.insertRow(r)
            status = d.get("status", 0)
            sc = {"200": "#00ff88", "301": "#00d4ff",
                  "302": "#00d4ff", "403": "#ffcc00",
                  "401": "#ff8800"}.get(str(status), "#e0e0e0")
            self._dir_tbl.setItem(r, 0, _item(str(status), sc))
            self._dir_tbl.setItem(r, 1, _item(str(d.get("size", ""))))
            self._dir_tbl.setItem(r, 2, _item(d.get("url", "")))
            note = d.get("note", "")
            self._dir_tbl.setItem(r, 3,
                _item(note, "#ff4444" if d.get("sensitive") else "#e0e0e0"))

        # Cookies
        self._ck_tbl.setRowCount(0)
        for c in web.get("cookies", []):
            r = self._ck_tbl.rowCount()
            self._ck_tbl.insertRow(r)
            self._ck_tbl.setItem(r, 0, _item(c.get("name", "")))
            sec = c.get("secure", False)
            self._ck_tbl.setItem(r, 1,
                _item("✔" if sec else "✗", "#00ff88" if sec else "#ff4444"))
            ho = c.get("http_only", False)
            self._ck_tbl.setItem(r, 2,
                _item("✔" if ho else "✗", "#00ff88" if ho else "#ffcc00"))
            self._ck_tbl.setItem(r, 3, _item(c.get("same_site", "")))
            issues = c.get("issues", [])
            self._ck_tbl.setItem(r, 4, _item("; ".join(issues) if issues else "OK"))

        # Info text
        methods = web.get("dangerous_methods", [])
        tech    = web.get("technologies", {})
        waf     = web.get("waf", "")
        cors    = web.get("cors", {})
        lines   = [
            f"Base URL:          {web.get('base_url', '—')}",
            f"Server:            {web.get('server', '—')}",
            f"Page Title:        {web.get('page_title', '—')}",
            f"WAF:               {waf or 'Not detected'}",
            f"TLS Version:       {web.get('tls', {}).get('tls_version', '—')}",
            f"Header Score:      {web.get('header_score', 0)}/100",
            f"Dangerous Methods: {', '.join(methods) if methods else 'None'}",
            f"Technologies:      {tech}",
            f"CORS Severity:     {cors.get('severity', '—')}",
            f"CORS Detail:       {cors.get('detail', '—')}",
        ]
        self._info_edit.setPlainText("\n".join(lines))


class _CVETab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_vulns: list[dict] = []

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(8)

        # Filter bar
        fbar = QHBoxLayout()
        fbar.setSpacing(8)
        fbar.addWidget(QLabel("Filter:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Search CVE ID, description, product…")
        self._search.textChanged.connect(self._filter)
        fbar.addWidget(self._search, stretch=1)
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self._sev_filter.currentTextChanged.connect(self._filter)
        fbar.addWidget(self._sev_filter)
        lay.addLayout(fbar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        lay.addWidget(splitter, stretch=1)

        self._tbl = _table(
            ["CVE ID", "Score", "Severity", "Ports", "Product", "AV", "Exploit", "Description"])
        self._tbl.itemSelectionChanged.connect(self._on_select)
        splitter.addWidget(self._tbl)

        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setStyleSheet(
            "background: #080810; font-family: Consolas, monospace;"
            " font-size: 12px; color: #c0c0d0; border: 1px solid #00ff8818;")
        splitter.addWidget(self._detail)
        splitter.setSizes([400, 180])

    def _filter(self):
        query = self._search.text().lower()
        sev   = self._sev_filter.currentText()
        self._tbl.setRowCount(0)
        for v in self._all_vulns:
            if sev != "All" and v.get("severity", "").upper() != sev:
                continue
            haystack = " ".join([
                v.get("cve_id", ""),
                v.get("description", ""),
                v.get("matched_product", ""),
            ]).lower()
            if query and query not in haystack:
                continue
            self._add_row(v)

    def _add_row(self, v: dict):
        r = self._tbl.rowCount()
        self._tbl.insertRow(r)
        sev   = v.get("severity", "")
        score = v.get("score", 0.0)
        col   = SEV_COLORS.get(sev.upper(), "#e0e0e0")
        self._tbl.setItem(r, 0, _item(v.get("cve_id", ""), "#00d4ff"))
        self._tbl.setItem(r, 1, _item(f"{float(score):.1f}", col))
        self._tbl.setItem(r, 2, _item(sev, col))
        ports = v.get("matched_ports", [v.get("matched_port", "")])
        self._tbl.setItem(r, 3, _item(", ".join(str(p) for p in ports if p)))
        self._tbl.setItem(r, 4, _item(v.get("matched_product", "")[:20]))
        av = v.get("cvss", {}).get("attack_vector", "")
        self._tbl.setItem(r, 5, _item(av[:3] if av else "—",
                          "#ff4444" if av == "NETWORK" else "#e0e0e0"))
        has_exp = v.get("has_exploit", False)
        self._tbl.setItem(r, 6, _item("YES" if has_exp else "no",
                          "#ff4444" if has_exp else "#606070"))
        self._tbl.setItem(r, 7, _item(v.get("description", "")[:100]))

    def _on_select(self):
        rows = self._tbl.selectedItems()
        if not rows:
            return
        r = self._tbl.currentRow()
        if r < 0 or r >= len(self._all_vulns):
            return
        v = self._all_vulns[r]
        lines = [
            f"CVE ID:      {v.get('cve_id', '—')}",
            f"Score:       {v.get('score', 0.0):.1f}",
            f"Severity:    {v.get('severity', '—')}",
            f"Published:   {v.get('published', '—')}",
            f"Product:     {v.get('matched_product', '—')}  v{v.get('matched_version', '')}",
            f"Port(s):     {v.get('matched_ports', [])}",
            f"Exploit:     {'YES' if v.get('has_exploit') else 'No'}",
            f"AV:          {v.get('cvss', {}).get('attack_vector', '—')}",
            f"",
            f"Description:",
            f"{v.get('description', '—')}",
            f"",
            f"References:",
        ]
        for ref in v.get("references", [])[:8]:
            lines.append(f"  • {ref}")
        if v.get("exploits"):
            lines.append("\nKnown Exploits:")
            for ex in v.get("exploits", [])[:5]:
                lines.append(f"  [{ex.get('source','')}] {ex.get('url','')}")
        self._detail.setPlainText("\n".join(lines))

    def load(self, data: dict):
        self._all_vulns = data.get("vulnerabilities", [])
        self._filter()


class _RiskTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        self._banner = QLabel("")
        self._banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._banner.setStyleSheet(
            "font-size: 22px; font-weight: bold; padding: 10px;"
            " border-radius: 6px;")
        lay.addWidget(self._banner)

        tabs = QTabWidget()
        lay.addWidget(tabs, stretch=1)

        # Top risks
        risks_w = QWidget()
        risks_l = QVBoxLayout(risks_w)
        self._risks_tbl = _table(
            ["#", "CVE / ID", "CVSS", "Composite", "EPSS", "Tier", "Exploit", "AV"])
        risks_l.addWidget(self._risks_tbl)
        tabs.addTab(risks_w, "Top Risks")

        # Attack surface
        surf_w = QWidget()
        surf_l = QVBoxLayout(surf_w)
        self._surf_tbl = _table(["Category", "Details"])
        surf_l.addWidget(self._surf_tbl)
        tabs.addTab(surf_w, "Attack Surface")

        # Attack chains
        chain_w = QWidget()
        chain_l = QVBoxLayout(chain_w)
        self._chain_tbl = _table(["Chain", "Likelihood", "Impact", "Steps"])
        chain_l.addWidget(self._chain_tbl)
        tabs.addTab(chain_w, "Attack Chains")

        # Remediation
        rem_w = QWidget()
        rem_l = QVBoxLayout(rem_w)
        self._rem_tbl = _table(
            ["#", "CVE / ID", "Effort", "Days", "Ports", "Action"])
        rem_l.addWidget(self._rem_tbl)
        tabs.addTab(rem_w, "Remediation Plan")

    def load(self, data: dict):
        risk = data.get("risk_summary", {})
        overall = risk.get("overall_risk", "NONE")
        score   = risk.get("risk_score", 0.0)
        col     = SEV_COLORS.get(overall, "#e0e0e0")
        self._banner.setText(f"Overall Risk: {overall}  |  Score: {score:.2f}")
        self._banner.setStyleSheet(
            f"font-size: 22px; font-weight: bold; padding: 10px;"
            f" border-radius: 6px; color: {col};"
            f" background-color: {col}18; border: 1px solid {col}44;")

        # Top risks
        self._risks_tbl.setRowCount(0)
        for rs in risk.get("top_risks", [])[:20]:
            r = self._risks_tbl.rowCount()
            self._risks_tbl.insertRow(r)
            tier = rs.get("risk_tier", "")
            col2 = SEV_COLORS.get(tier, "#e0e0e0")
            self._risks_tbl.setItem(r, 0, _item(str(rs.get("priority_rank", ""))))
            self._risks_tbl.setItem(r, 1, _item(rs.get("cve_id", ""), "#00d4ff"))
            self._risks_tbl.setItem(r, 2, _item(f"{rs.get('cvss_score', 0):.1f}", col2))
            self._risks_tbl.setItem(r, 3, _item(f"{rs.get('composite_score', 0):.1f}", col2))
            self._risks_tbl.setItem(r, 4, _item(f"{rs.get('epss_score', 0):.3f}"))
            self._risks_tbl.setItem(r, 5, _item(tier, col2))
            self._risks_tbl.setItem(r, 6,
                _item("YES" if rs.get("exploit_bonus", 0) > 0 else "no"))
            av = rs.get("cvss", {}).get("attack_vector", "") if isinstance(rs.get("cvss"), dict) else ""
            self._risks_tbl.setItem(r, 7, _item(av[:3] if av else "—"))

        # Attack surface
        self._surf_tbl.setRowCount(0)
        surf = risk.get("attack_surface", {})
        for av, cves in (surf.get("by_attack_vector", {}) or {}).items():
            rr = self._surf_tbl.rowCount()
            self._surf_tbl.insertRow(rr)
            self._surf_tbl.setItem(rr, 0, _item(f"AV:{av[:3]}", "#00d4ff"))
            self._surf_tbl.setItem(rr, 1, _item(f"{len(cves)} finding(s)"))
        for cluster, cves in (surf.get("by_service_cluster", {}) or {}).items():
            rr = self._surf_tbl.rowCount()
            self._surf_tbl.insertRow(rr)
            self._surf_tbl.setItem(rr, 0, _item(f"Cluster: {cluster}"))
            self._surf_tbl.setItem(rr, 1, _item(f"{len(cves)} finding(s)"))

        # Chains
        self._chain_tbl.setRowCount(0)
        for ch in risk.get("attack_paths", []):
            rr = self._chain_tbl.rowCount()
            self._chain_tbl.insertRow(rr)
            lh = ch.get("likelihood", "")
            lhc = "#ff4444" if lh == "HIGH" else "#ffcc00"
            self._chain_tbl.setItem(rr, 0, _item(str(ch.get("path_id", ""))))
            self._chain_tbl.setItem(rr, 1, _item(lh, lhc))
            self._chain_tbl.setItem(rr, 2, _item(ch.get("impact", "")))
            steps = ch.get("steps", [])
            step_str = " → ".join(
                f"[{s.get('cve','')}] port {s.get('port','')}" for s in steps)
            self._chain_tbl.setItem(rr, 3, _item(step_str))

        # Remediation
        self._rem_tbl.setRowCount(0)
        eff_col = {"IMMEDIATE": "#ff4444", "SHORT": "#ff8800",
                   "MEDIUM": "#ffcc00", "LONG": "#00ccff"}
        for task in risk.get("remediation_plan", []):
            rr = self._rem_tbl.rowCount()
            self._rem_tbl.insertRow(rr)
            effort = task.get("effort", "")
            self._rem_tbl.setItem(rr, 0, _item(str(task.get("priority", ""))))
            self._rem_tbl.setItem(rr, 1, _item(task.get("cve_id", ""), "#00d4ff"))
            self._rem_tbl.setItem(rr, 2,
                _item(effort, eff_col.get(effort, "#e0e0e0")))
            self._rem_tbl.setItem(rr, 3, _item(str(task.get("effort_days", ""))))
            ports = task.get("affected_ports", [])
            self._rem_tbl.setItem(rr, 4,
                _item(", ".join(str(p) for p in ports)))
            self._rem_tbl.setItem(rr, 5, _item(task.get("action", "")[:120]))


class ResultsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: dict = {}
        self._build_ui()

    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Header bar ─────────────────────────────────────────────────────
        header = QWidget()
        header.setStyleSheet(
            "background-color: #080e1c; border-bottom: 1px solid #1a2e45;")
        header.setFixedHeight(70)
        hb = QHBoxLayout(header)
        hb.setContentsMargins(24, 12, 24, 12)
        hb.setSpacing(12)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        t = QLabel("Scan Results")
        t.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        t.setStyleSheet("color: #cbd5e1; background: transparent;")
        title_col.addWidget(t)
        self._target_lbl = QLabel("No scan loaded")
        self._target_lbl.setStyleSheet(
            "color: #3d5470; font-size: 12px; background: transparent;")
        title_col.addWidget(self._target_lbl)
        hb.addLayout(title_col)
        hb.addStretch()

        # Export buttons
        export_lbl = QLabel("Export:")
        export_lbl.setStyleSheet("color: #3d5470; font-size: 12px; background: transparent;")
        hb.addWidget(export_lbl)

        for fmt, icon, tip in [
            ("JSON", "{ }", "Full scan data as JSON"),
            ("HTML", "</>", "Styled HTML report"),
            ("CSV",  "⊞",  "Vulnerabilities as CSV"),
            ("MD",   "✎",  "Markdown summary"),
        ]:
            btn = QPushButton(f"{icon}  {fmt}")
            btn.setFixedHeight(36)
            btn.setFixedWidth(80)
            btn.setToolTip(tip)
            btn.setStyleSheet(
                "QPushButton { background-color: #0f1929; color: #8fadc8;"
                " border: 1px solid #1a2e45; border-radius: 7px;"
                " font-size: 12px; font-weight: 600; }"
                "QPushButton:hover { background-color: #142035;"
                " color: #cbd5e1; border-color: #2a3f5f; }"
                "QPushButton:pressed { background-color: #0a1525; }")
            btn.clicked.connect(lambda _, f=fmt: self._export(f))
            hb.addWidget(btn)

        open_folder_btn = QPushButton("⊟  Open Folder")
        open_folder_btn.setFixedHeight(36)
        open_folder_btn.setFixedWidth(120)
        open_folder_btn.setStyleSheet(
            "QPushButton { background-color: #0f1929; color: #8fadc8;"
            " border: 1px solid #1a2e45; border-radius: 7px; font-size: 12px; }"
            "QPushButton:hover { background-color: #142035; color: #cbd5e1;"
            " border-color: #2a3f5f; }")
        open_folder_btn.clicked.connect(self._open_output_folder)
        hb.addWidget(open_folder_btn)

        lay.addWidget(header)

        # ── Tabs ───────────────────────────────────────────────────────────
        self._tabs = QTabWidget()
        lay.addWidget(self._tabs, stretch=1)

        self._overview = _OverviewTab()
        self._passive  = _PassiveTab()
        self._active   = _ActiveTab()
        self._web      = _WebTab()
        self._cve      = _CVETab()
        self._risk     = _RiskTab()

        self._tabs.addTab(self._overview, "⊙  Overview")
        self._tabs.addTab(self._passive,  "⌖  Passive Recon")
        self._tabs.addTab(self._active,   "⊛  Active Scan")
        self._tabs.addTab(self._web,      "</>  Web Enum")
        self._tabs.addTab(self._cve,      "⚠  CVE Findings")
        self._tabs.addTab(self._risk,     "▲  Risk Analysis")

    def load(self, data: dict):
        self._data = data
        meta   = data.get("meta", {})
        target = meta.get("target", "Unknown")
        ts     = meta.get("timestamp", "")
        self._target_lbl.setText(
            f"{target}   ·   {ts}" if ts else target)
        self._overview.load(data)
        self._passive.load(data)
        self._active.load(data)
        self._web.load(data)
        self._cve.load(data)
        self._risk.load(data)
        self._tabs.setCurrentIndex(0)

    # ── Export ─────────────────────────────────────────────────────────────
    def _export(self, fmt: str):
        if not self._data:
            QMessageBox.information(self, "No Data", "Run a scan first.")
            return

        meta   = self._data.get("meta", {})
        target = meta.get("target", "scan").replace("/", "-").replace(":", "-")
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        base   = f"r3conx_{target}_{ts}"

        filters = {
            "JSON": ("JSON Report (*.json)", f"{base}.json"),
            "HTML": ("HTML Report (*.html)", f"{base}.html"),
            "CSV":  ("CSV Spreadsheet (*.csv)", f"{base}_vulns.csv"),
            "MD":   ("Markdown Report (*.md)", f"{base}.md"),
        }
        filt, default = filters[fmt]
        path, _ = QFileDialog.getSaveFileName(self, f"Export {fmt}", default, filt)
        if not path:
            return

        try:
            if fmt == "JSON":
                self._write_json(path)
            elif fmt == "HTML":
                self._write_html(path)
            elif fmt == "CSV":
                self._write_csv(path)
            elif fmt == "MD":
                self._write_md(path)

            msg = QMessageBox(self)
            msg.setWindowTitle("Export Complete")
            msg.setText(f"Saved to:\n{path}")
            msg.setStandardButtons(
                QMessageBox.StandardButton.Ok |
                QMessageBox.StandardButton.Open)
            msg.button(QMessageBox.StandardButton.Open).setText("Open File")
            if msg.exec() == QMessageBox.StandardButton.Open:
                _open_file(path)
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    def _write_json(self, path: str):
        with open(path, "w") as f:
            json.dump(self._data, f, indent=2, default=str)

    def _write_csv(self, path: str):
        vulns = self._data.get("vulnerabilities", [])
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["CVE ID", "CVSS Score", "Severity", "Product",
                        "Version", "Port(s)", "Has Exploit",
                        "Attack Vector", "Description"])
            for v in vulns:
                ports = v.get("matched_ports", [v.get("matched_port", "")])
                w.writerow([
                    v.get("cve_id", ""),
                    v.get("score", ""),
                    v.get("severity", ""),
                    v.get("matched_product", ""),
                    v.get("matched_version", ""),
                    ", ".join(str(p) for p in ports if p),
                    "YES" if v.get("has_exploit") else "No",
                    v.get("cvss", {}).get("attack_vector", ""),
                    v.get("description", ""),
                ])

    def _write_md(self, path: str):
        d    = self._data
        meta = d.get("meta", {})
        act  = d.get("active_scan", {})
        risk = d.get("risk_summary", {})
        vulns = d.get("vulnerabilities", [])

        lines = [
            f"# R3CON-X Scan Report",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Target | `{meta.get('target', '—')}` |",
            f"| IP | `{meta.get('ip', '—')}` |",
            f"| Scan Date | {meta.get('timestamp', '—')} |",
            f"| Profile | {meta.get('profile', '—')} |",
            f"| Overall Risk | **{risk.get('overall_risk', '—')}** |",
            f"| Risk Score | {risk.get('risk_score', 0):.2f} |",
            f"| Open Ports | {act.get('total_open', 0)} |",
            f"| Vulnerabilities | {len(vulns)} |",
            f"",
            f"## Open Ports",
            f"",
            f"| Port | Protocol | Service | Product | Version |",
            f"|------|----------|---------|---------|---------|",
        ]
        for p in act.get("open_ports", []):
            lines.append(
                f"| {p.get('port','')} | {p.get('protocol','')} |"
                f" {p.get('service','')} | {p.get('product','')} |"
                f" {p.get('version','')} |")

        lines += ["", "## Vulnerability Findings", "",
                  "| CVE ID | Score | Severity | Product | Exploit | Description |",
                  "|--------|-------|----------|---------|---------|-------------|"]
        for v in sorted(vulns, key=lambda x: float(x.get("score", 0)), reverse=True):
            desc = v.get("description", "")[:120].replace("|", "¦")
            lines.append(
                f"| {v.get('cve_id','')} | {v.get('score','')} |"
                f" {v.get('severity','')} | {v.get('matched_product','')[:20]} |"
                f" {'YES' if v.get('has_exploit') else 'No'} | {desc} |")

        lines += ["", "## Remediation Plan", "",
                  "| Priority | CVE | Effort | Days | Action |",
                  "|----------|-----|--------|------|--------|"]
        for t in risk.get("remediation_plan", []):
            act_txt = t.get("action", "")[:100].replace("|", "¦")
            lines.append(
                f"| {t.get('priority','')} | {t.get('cve_id','')} |"
                f" {t.get('effort','')} | {t.get('effort_days','')} | {act_txt} |")

        lines += ["", f"---", f"*Generated by R3CON-X · {datetime.now():%Y-%m-%d %H:%M}*"]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _write_html(self, path: str):
        d     = self._data
        meta  = d.get("meta", {})
        act   = d.get("active_scan", {})
        risk  = d.get("risk_summary", {})
        vulns = d.get("vulnerabilities", [])
        web   = d.get("web_enum", {})

        overall = risk.get("overall_risk", "NONE")
        risk_color = {
            "CRITICAL": "#ff4757", "HIGH": "#ff7b2d",
            "MEDIUM": "#f59e0b", "LOW": "#3b9eff",
        }.get(overall, "#4b5e7a")

        def sev_badge(sev: str) -> str:
            c = SEV_COLORS.get(sev.upper(), "#4b5e7a")
            return (f'<span style="color:{c};background:{c}18;border:1px solid {c}44;'
                    f'border-radius:4px;padding:2px 8px;font-size:11px;'
                    f'font-weight:700">{sev}</span>')

        ports_rows = "".join(
            f"<tr><td style='color:#3b9eff'>{p.get('port','')}</td>"
            f"<td>{p.get('protocol','')}</td><td style='color:#00ff88'>{p.get('state','')}</td>"
            f"<td>{p.get('service','')}</td><td>{p.get('product','')}</td>"
            f"<td>{p.get('version','')}</td></tr>"
            for p in act.get("open_ports", [])
        )

        vuln_rows_parts = []
        for v in sorted(vulns, key=lambda x: float(x.get("score", 0)), reverse=True):
            sev      = str(v.get("severity", "")).upper()
            sev_col  = SEV_COLORS.get(sev, "#cbd5e1")
            exp_col  = "#ff4757" if v.get("has_exploit") else "#3d5470"
            exp_txt  = "YES" if v.get("has_exploit") else "No"
            desc     = v.get("description", "")[:120]
            prod     = v.get("matched_product", "")[:24]
            vuln_rows_parts.append(
                f"<tr><td style='color:#00b8d4'>{v.get('cve_id','')}</td>"
                f"<td style='color:{sev_col}'>{v.get('score','')}</td>"
                f"<td>{sev_badge(sev)}</td>"
                f"<td>{prod}</td>"
                f"<td style='color:{exp_col}'>{exp_txt}</td>"
                f"<td style='color:#7a95b0;font-size:12px'>{desc}</td></tr>"
            )
        vuln_rows = "".join(vuln_rows_parts)

        _eff_colors = ["#ff4757", "#ff7b2d", "#f59e0b", "#3b9eff"]
        rem_rows_parts = []
        for t in risk.get("remediation_plan", []):
            pri      = t.get("priority", 4)
            eff_col  = _eff_colors[min(int(pri) - 1, 3)] if pri else "#4b5e7a"
            action   = t.get("action", "")[:100]
            rem_rows_parts.append(
                f"<tr><td>{pri}</td>"
                f"<td style='color:#00b8d4'>{t.get('cve_id','')}</td>"
                f"<td style='color:{eff_col}'>{t.get('effort','')}</td>"
                f"<td>{t.get('effort_days','')}</td>"
                f"<td style='font-size:12px'>{action}</td></tr>"
            )
        rem_rows = "".join(rem_rows_parts)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>R3CON-X Report — {meta.get('target','')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0b0f1a;color:#cbd5e1;font-family:'Segoe UI',sans-serif;font-size:14px;padding:32px}}
  h1{{color:#00ff88;font-size:28px;margin-bottom:4px}}
  h2{{color:#00b8d4;font-size:18px;margin:32px 0 12px;padding-bottom:8px;border-bottom:1px solid #1a2e45}}
  .meta-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:20px 0}}
  .card{{background:#0f1929;border:1px solid #1a2e45;border-radius:10px;padding:16px}}
  .card-label{{color:#3d5470;font-size:10px;font-weight:700;letter-spacing:1px;margin-bottom:6px}}
  .card-value{{font-size:22px;font-weight:700}}
  .risk-banner{{background:{risk_color}14;border:1px solid {risk_color}44;border-radius:10px;
    padding:20px;text-align:center;color:{risk_color};font-size:24px;font-weight:700;margin:20px 0}}
  table{{width:100%;border-collapse:collapse;margin-top:8px}}
  th{{background:#08111f;color:#3d5470;font-size:11px;font-weight:700;letter-spacing:0.8px;
    text-align:left;padding:10px 12px;border-bottom:1px solid #1a2e45}}
  td{{padding:9px 12px;border-bottom:1px solid #142035;vertical-align:top}}
  tr:hover td{{background:#0f1929}}
  .footer{{margin-top:40px;color:#243550;font-size:11px;border-top:1px solid #1a2e45;padding-top:16px}}
</style>
</head>
<body>
<h1>R3CON-X Scan Report</h1>
<p style="color:#3d5470;margin-bottom:20px">Generated {datetime.now():%Y-%m-%d %H:%M:%S}</p>

<div class="risk-banner">Overall Risk: {overall} &nbsp;·&nbsp; Score: {risk.get('risk_score',0):.2f}</div>

<div class="meta-grid">
  <div class="card"><div class="card-label">TARGET</div>
    <div class="card-value" style="color:#00b8d4;font-size:16px">{meta.get('target','—')}</div></div>
  <div class="card"><div class="card-label">IP ADDRESS</div>
    <div class="card-value" style="color:#3b9eff">{meta.get('ip','—')}</div></div>
  <div class="card"><div class="card-label">OPEN PORTS</div>
    <div class="card-value" style="color:#00ff88">{act.get('total_open',0)}</div></div>
  <div class="card"><div class="card-label">VULNERABILITIES</div>
    <div class="card-value" style="color:#ff7b2d">{len(vulns)}</div></div>
  <div class="card"><div class="card-label">SCAN PROFILE</div>
    <div class="card-value" style="color:#a78bfa;font-size:16px">{meta.get('profile','—')}</div></div>
  <div class="card"><div class="card-label">HEADER SCORE</div>
    <div class="card-value" style="color:#f59e0b">{web.get('header_score',0)}/100</div></div>
</div>

<h2>Open Ports</h2>
<table>
  <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr>
  {ports_rows if ports_rows else '<tr><td colspan="6" style="color:#3d5470">No open ports found</td></tr>'}
</table>

<h2>Vulnerability Findings ({len(vulns)})</h2>
<table>
  <tr><th>CVE ID</th><th>Score</th><th>Severity</th><th>Product</th><th>Exploit</th><th>Description</th></tr>
  {vuln_rows if vuln_rows else '<tr><td colspan="6" style="color:#3d5470">No vulnerabilities found</td></tr>'}
</table>

<h2>Remediation Plan</h2>
<table>
  <tr><th>#</th><th>CVE</th><th>Effort</th><th>Days</th><th>Action</th></tr>
  {rem_rows if rem_rows else '<tr><td colspan="5" style="color:#3d5470">No remediation items</td></tr>'}
</table>

<div class="footer">R3CON-X · Reconnaissance &amp; Vulnerability Intelligence · {datetime.now():%Y-%m-%d}</div>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _open_output_folder(self):
        path = self._data.get("meta", {}).get("output_dir", "")
        if not path or not os.path.isdir(path):
            # Try to find any output file
            for key in ("json_path", "html_path", "pdf_path"):
                fpath = self._data.get("meta", {}).get(key, "")
                if fpath and os.path.exists(fpath):
                    path = os.path.dirname(fpath)
                    break
        if path and os.path.isdir(path):
            _open_file(path)
        else:
            QMessageBox.information(self, "Folder Not Found",
                                    "Could not locate the output folder for this scan.")


def _open_file(path: str):
    if platform.system() == "Windows":
        os.startfile(path)
    elif platform.system() == "Darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])
