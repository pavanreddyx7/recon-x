from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTextEdit, QFrame,
    QLineEdit, QComboBox, QGroupBox, QScrollArea,
    QGridLayout, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor
from gui.theme import SEV_COLORS
from gui.widgets.severity_badge import SeverityBadge
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
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(16)

        # Summary cards
        cards = QHBoxLayout()
        cards.setSpacing(12)
        self._cards: dict[str, QLabel] = {}

        for key, title, color in [
            ("target",    "TARGET",       "#00d4ff"),
            ("ip",        "IP ADDRESS",   "#00ff88"),
            ("ports",     "OPEN PORTS",   "#00ff88"),
            ("vulns",     "VULNERABILITIES", "#ff8800"),
            ("risk",      "RISK LEVEL",   "#ff4444"),
            ("score",     "RISK SCORE",   "#ffcc00"),
        ]:
            frame = QFrame()
            frame.setObjectName("Card")
            fl = QVBoxLayout(frame)
            fl.setSpacing(4)
            tl = QLabel(title)
            tl.setObjectName("CardTitle")
            fl.addWidget(tl)
            vl = QLabel("—")
            vl.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: bold;")
            fl.addWidget(vl)
            self._cards[key] = vl
            frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            cards.addWidget(frame)
        lay.addLayout(cards)

        # Gauges row
        gauges_row = QHBoxLayout()
        gauges_row.setSpacing(20)

        self._risk_gauge   = GaugeWidget(15, "Risk Score",    "",  self)
        self._header_gauge = GaugeWidget(100, "Header Score", "/100", self)
        for g in (self._risk_gauge, self._header_gauge):
            g.setFixedSize(150, 150)
            gauges_row.addWidget(g)
        gauges_row.addStretch()
        lay.addLayout(gauges_row)

        # Severity breakdown
        sev_box = QGroupBox("Vulnerability Severity Breakdown")
        sev_lay = QHBoxLayout(sev_box)
        self._sev_labels: dict[str, QLabel] = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
            col = SEV_COLORS.get(sev, "#606070")
            vbox = QVBoxLayout()
            count_lbl = QLabel("0")
            count_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            count_lbl.setStyleSheet(
                f"color: {col}; font-size: 22px; font-weight: bold;"
                f" background-color: {col}18; border: 1px solid {col}44;"
                f" border-radius: 6px; padding: 8px 16px;")
            vbox.addWidget(count_lbl)
            name_lbl = QLabel(sev)
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_lbl.setStyleSheet(f"color: {col}; font-size: 10px;")
            vbox.addWidget(name_lbl)
            self._sev_labels[sev] = count_lbl
            sev_lay.addLayout(vbox)
        lay.addWidget(sev_box)
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

        self._tabs = QTabWidget()
        lay.addWidget(self._tabs)

        self._overview = _OverviewTab()
        self._passive  = _PassiveTab()
        self._active   = _ActiveTab()
        self._web      = _WebTab()
        self._cve      = _CVETab()
        self._risk     = _RiskTab()

        self._tabs.addTab(self._overview, "Overview")
        self._tabs.addTab(self._passive,  "Passive Recon")
        self._tabs.addTab(self._active,   "Active Scan")
        self._tabs.addTab(self._web,      "Web Enum")
        self._tabs.addTab(self._cve,      "CVE Findings")
        self._tabs.addTab(self._risk,     "Risk Analysis")

    def load(self, data: dict):
        self._data = data
        self._overview.load(data)
        self._passive.load(data)
        self._active.load(data)
        self._web.load(data)
        self._cve.load(data)
        self._risk.load(data)
        self._tabs.setCurrentIndex(0)
