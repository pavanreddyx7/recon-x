"""
Stage 2 — Passive Reconnaissance  (Advanced Edition)
Collects intelligence without sending a single packet to the target directly.

Sub-engines:
  DNSEngine          — A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/SRV/NAPTR/HINFO + DNSSEC
                       + zone-transfer + dangling CNAME detection
  SubdomainEngine    — 6-source: brute-force (450 words) + crt.sh + HackerTarget
                       + CertSpotter + AlienVault OTX + AnubisDB
  TakeoverEngine     — CNAME-based subdomain takeover (55 service fingerprints)
  WHOISEngine        — Structured WHOIS + domain age + expiry warning + privacy detection
  ASNGeoEngine       — ip-api.com + ipinfo.io fallback + RDAP (abuse contact, network range)
  ThreatIntelEngine  — DNSBL reputation checks across 8 blacklists
  MailSecEngine      — SPF (includes) / DMARC (policy+rua+ruf) / DKIM / BIMI / MTA-STS / TLS-RPT
  WaybackEngine      — Historical URL/endpoint discovery via Wayback Machine CDX API
  TechHintEngine     — CDN/WAF/Cloud/Email detection from DNS values + subdomain name patterns
  GoogleDorksEngine  — Generates ready-to-paste Google dork queries for manual OSINT
"""
from __future__ import annotations

import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
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
from utils.exceptions import WHOISError
from config import cfg

_console = Console(highlight=False)

# ── Shared HTTP session ───────────────────────────────────────────────────────
_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": cfg.web.user_agent,
    "Accept":     "application/json",
})
_SESSION.timeout = cfg.web.timeout

_api_limiter = RateLimiter(calls=3, period=1.0)


# ══════════════════════════════════════════════════════════════════════════════
# Data models
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DNSRecord:
    rtype:  str
    value:  str
    ttl:    int = 0


@dataclass
class Subdomain:
    fqdn:             str
    ip:               str
    source:           str   # bruteforce | ct_log | alienvault | anubis
    takeover_risk:    str  = ""   # "" | "POSSIBLE"
    takeover_service: str  = ""   # e.g. "GitHub Pages"


@dataclass
class WHOISData:
    registrar:           str        = ""
    registrant_org:      str        = ""
    registrant_country:  str        = ""
    creation_date:       str        = ""
    expiry_date:         str        = ""
    updated_date:        str        = ""
    name_servers:        list[str]  = field(default_factory=list)
    status:              list[str]  = field(default_factory=list)
    emails:              list[str]  = field(default_factory=list)
    domain_age_days:     int        = -1
    expiry_days:         int        = -1   # negative = already expired
    privacy_protected:   bool       = False
    raw:                 str        = ""


@dataclass
class ASNInfo:
    ip:           str   = ""
    asn:          str   = ""
    asn_cidr:     str   = ""   # IP range from RDAP
    network_name: str   = ""   # RDAP netName
    org:          str   = ""
    isp:          str   = ""
    country:      str   = ""
    region:       str   = ""
    city:         str   = ""
    lat:          float = 0.0
    lon:          float = 0.0
    timezone:     str   = ""
    reverse_dns:  str   = ""
    abuse_email:  str   = ""   # from RDAP
    abuse_phone:  str   = ""   # from RDAP


@dataclass
class ThreatIntel:
    ip:               str
    dnsbl_hits:       list[str] = field(default_factory=list)
    listed:           bool      = False
    reputation_score: int       = 100   # 100=clean, decrements per DNSBL hit
    notes:            list[str] = field(default_factory=list)


@dataclass
class MailSecurity:
    spf_record:     str        = ""
    spf_valid:      bool       = False
    spf_includes:   list[str]  = field(default_factory=list)
    dmarc_record:   str        = ""
    dmarc_policy:   str        = ""
    dmarc_rua:      list[str]  = field(default_factory=list)
    dmarc_ruf:      list[str]  = field(default_factory=list)
    dkim_selectors: list[str]  = field(default_factory=list)
    bimi_record:    str        = ""
    mta_sts_policy: str        = ""   # "enforce" | "testing" | "none" | ""
    tls_rpt_record: str        = ""
    issues:         list[str]  = field(default_factory=list)


@dataclass
class WaybackData:
    total_urls:      int        = 0
    endpoints:       list[str]  = field(default_factory=list)
    years_active:    list[int]  = field(default_factory=list)
    oldest_snapshot: str        = ""
    newest_snapshot: str        = ""


@dataclass
class TechHint:
    category: str
    name:     str
    evidence: str


@dataclass
class ReconResult:
    target:           str
    ip:               str
    timestamp:        str  = field(default_factory=lambda: datetime.now().isoformat())

    dns_records:      dict[str, list[DNSRecord]] = field(default_factory=dict)
    dnssec_enabled:   bool              = False
    dangling_cnames:  list[str]         = field(default_factory=list)
    zone_transfer:    dict[str, Any]    = field(default_factory=dict)

    subdomains:       list[Subdomain]   = field(default_factory=list)
    takeover_risks:   list[Subdomain]   = field(default_factory=list)

    whois:            WHOISData         = field(default_factory=WHOISData)
    asn_geo:          ASNInfo           = field(default_factory=ASNInfo)
    threat_intel:     ThreatIntel       = field(default_factory=lambda: ThreatIntel(ip=""))
    mail_security:    MailSecurity      = field(default_factory=MailSecurity)
    wayback:          WaybackData       = field(default_factory=WaybackData)
    tech_hints:       list[TechHint]    = field(default_factory=list)
    reverse_dns:      str               = ""
    google_dorks:     list[str]         = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["dns_records"] = {
            rtype: [asdict(r) for r in recs]
            for rtype, recs in self.dns_records.items()
        }
        return d


# ══════════════════════════════════════════════════════════════════════════════
# DNS Engine
# ══════════════════════════════════════════════════════════════════════════════

_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
    "CAA", "SRV", "DNSKEY", "NAPTR", "HINFO",
]

class DNSEngine:
    def __init__(self, target: str, ip: str):
        self.target   = target
        self.ip       = ip
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout     = 5.0
        self.resolver.lifetime    = 8.0
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    def enumerate_records(self) -> dict[str, list[DNSRecord]]:
        results: dict[str, list[DNSRecord]] = {}

        def _query(rtype: str) -> tuple[str, list[DNSRecord]]:
            records: list[DNSRecord] = []
            try:
                answers = self.resolver.resolve(self.target, rtype)
                for rdata in answers:
                    records.append(DNSRecord(rtype=rtype, value=str(rdata), ttl=int(answers.ttl)))
            except (dns.exception.DNSException, Exception):
                pass
            return rtype, records

        with ThreadPoolExecutor(max_workers=len(_RECORD_TYPES)) as pool:
            for rtype, records in pool.map(lambda rt: _query(rt), _RECORD_TYPES):
                if records:
                    results[rtype] = records
                    for r in records:
                        log.info(f"  DNS {rtype:<8} {r.value[:80]}")

        return results

    def reverse_lookup(self) -> str:
        try:
            rev = dns.reversename.from_address(self.ip)
            ptr = str(self.resolver.resolve(rev, "PTR")[0])
            log.info(f"  PTR: {ptr}")
            return ptr
        except Exception:
            return ""

    def check_dnssec(self) -> bool:
        try:
            answers = self.resolver.resolve(self.target, "DNSKEY")
            log.info(f"  DNSSEC: enabled ({len(answers)} key(s))")
            return True
        except Exception:
            log.info("  DNSSEC: not detected")
            return False

    def check_dangling_cnames(self, dns_records: dict[str, list[DNSRecord]]) -> list[str]:
        """Detect CNAME records pointing to unresolvable/unclaimed hostnames."""
        dangling: list[str] = []
        for rec in dns_records.get("CNAME", []):
            target = rec.value.rstrip(".")
            try:
                socket.gethostbyname(target)
            except socket.gaierror:
                dangling.append(rec.value)
                log.warn(f"  Dangling CNAME: {rec.value} → unresolvable (potential takeover)")
        return dangling

    def attempt_zone_transfer(self, ns_records: list[DNSRecord]) -> dict[str, Any]:
        result: dict[str, Any] = {"vulnerable": False, "nameservers_tried": [], "records": []}
        for ns_rec in ns_records:
            ns_host = ns_rec.value.rstrip(".")
            result["nameservers_tried"].append(ns_host)
            try:
                ns_ip = socket.gethostbyname(ns_host)
                z = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, self.target, timeout=5, lifetime=10)
                )
                result["vulnerable"] = True
                for name, node in z.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            result["records"].append(
                                f"{name} {rdataset.ttl} {rdataset.rdtype} {rdata}"
                            )
                log.critical(f"ZONE TRANSFER SUCCEEDED on {ns_host} — CRITICAL MISCONFIGURATION")
                break
            except Exception:
                log.debug(f"  AXFR refused by {ns_host} (expected)")
        if not result["vulnerable"]:
            log.info("  Zone transfer: all nameservers refused (secure)")
        return result


# ══════════════════════════════════════════════════════════════════════════════
# Subdomain Engine  (6 sources)
# ══════════════════════════════════════════════════════════════════════════════

_WORDLIST = [
    # Standard web & mail
    "www","www2","www3","mail","mail2","webmail","smtp","pop","imap","mx","mx1","mx2","mx3",
    "ns1","ns2","ns3","ns4","dns","dns1","dns2","email","owa",
    # API tiers
    "api","api2","api3","api-v1","api-v2","v1","v2","v3","rest","graphql","grpc",
    "ws","webhook","webhooks","rpc","soap","wsdl",
    # App / portal
    "app","app2","apps","web","portal","platform","service","services","gateway",
    "main","core","engine","hub",
    # Environments
    "dev","develop","development","staging","stage","stg","uat","qa","test","testing",
    "sandbox","demo","preview","preprod","pre-prod","prod","production","live","release","rc",
    "alpha","beta","gamma","canary","green","blue","local","int","integration",
    # DevOps / CI-CD
    "jenkins","ci","cd","cicd","travis","teamcity","bamboo","drone","build","builds",
    "gitlab","gitea","gogs","git","code","repo","svn","bitbucket","scm","vcs",
    "sonar","sonarqube","nexus","artifactory","registry","packages","pypi","npm",
    "harbor","docker","containers","k8s","kubernetes","openshift","rancher",
    "helm","argocd","flux","spinnaker","tekton","concourse","octopus",
    # Monitoring / Observability
    "monitor","monitoring","grafana","kibana","elastic","elasticsearch","logstash",
    "splunk","datadog","newrelic","prometheus","alertmanager","status","statuspage",
    "uptime","metrics","logs","logging","apm","jaeger","zipkin","loki","tempo",
    "cloudwatch","dynatrace","pingdom","zabbix","nagios","icinga","prtg",
    # Security
    "vault","consul","secrets","pki","certs","ca","siem","ids","ips",
    "waf","firewall","proxy","bastion","pentest","security","soc","mfa","2fa",
    "scanner","scan","audit","compliance","dlp","edr","xdr",
    # Auth / IAM
    "auth","sso","oauth","oidc","saml","login","signin","iam","ldap",
    "ad","idp","keycloak","okta","ping","cognito","accounts","account",
    "identity","token","jwt","session","passport",
    # VPN / Remote
    "vpn","remote","rdp","ssh","jump","citrix","anyconnect","openvpn","wireguard",
    "access","connect","tunnel","ra","remote-access","globalprotect",
    # Storage / CDN
    "cdn","static","assets","media","img","images","pics","photos","files",
    "download","downloads","upload","uploads","storage","s3","blob","archive",
    "backup","backups","fileserver","resources","content","binary","binaries",
    # Databases & cache
    "db","db2","db3","database","mysql","postgres","redis","mongo","elastic",
    "solr","influx","pgadmin","phpmyadmin","adminer","dba","oracle","cassandra",
    "memcached","couchdb","neo4j","clickhouse","snowflake","redshift",
    # Message queues
    "kafka","rabbit","rabbitmq","queue","mq","activemq","nats","stream","pubsub",
    # Business apps
    "crm","erp","hr","hrm","payroll","finance","jira","confluence","wiki","docs",
    "helpdesk","support","ticket","desk","kb","knowledgebase","faq",
    "reports","reporting","analytics","bi","dashboard","datawarehouse",
    "servicenow","remedy","zendesk","freshdesk","otrs","glpi",
    # E-commerce
    "shop","store","cart","checkout","payment","billing","invoice","orders",
    "catalog","merchant","pos","ecom","ecommerce","magento","woocommerce",
    # Marketing & content
    "blog","news","press","events","newsletter","campaign","promo","landing",
    "marketing","content","cms","wordpress","drupal","liferay",
    # Mobile & edge
    "mobile","m","push","notification","fcm","apns","ios","android",
    # Internal / corporate
    "intranet","internal","corp","private","office","hq","infra",
    "network","ops","devops","netops","secops","noc","itops",
    # Cloud patterns
    "cloud","ec2","rds","lambda","functions","serverless","paas","iaas","saas",
    # Load balancers / HA
    "lb","ha","dr","failover","cluster","edge","ingress","egress","balancer",
    # Email infra
    "relay","outbound","inbound","mailin","mailout","list","lists","bounce","mta",
    # Admin interfaces
    "admin","administrator","manage","management","manager","panel",
    "cpanel","webmin","plesk","directadmin","console","control","whm",
    # Misc
    "health","healthcheck","cron","worker","scheduler","jobs","tasks","async",
    "exchange","autodiscover","sharepoint","teams","skype","lync","meet",
    "chat","slack","video","conference","collab",
    "fw","router","switch","ntp","syslog","radius","tacacs","netflow",
    "test2","probe","debug","trace","diag","diagnostic",
    "old","legacy","v1","v2","new","next","future","archive2",
    "public","private","external","ext","int","internal2",
    "web2","app3","api4","service2",
]

# deduplicate while preserving order
_WORDLIST = list(dict.fromkeys(_WORDLIST))


class SubdomainEngine:
    def __init__(self, target: str, threads: int = 50):
        self.target   = target
        self.threads  = threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout  = 3.0
        self.resolver.lifetime = 5.0
        self._seen: set[str]   = set()
        self._lock = threading.Lock()

    def _is_wildcard(self) -> str | None:
        rand = f"r3conx-nxdomain-{int(time.time())}.{self.target}"
        try:
            ans = self.resolver.resolve(rand, "A")
            wc_ip = str(ans[0])
            log.warn(f"  Wildcard DNS detected ({wc_ip}) — brute-force may produce false positives")
            return wc_ip
        except Exception:
            return None

    def _resolve_sub(self, sub: str) -> Subdomain | None:
        fqdn = f"{sub}.{self.target}"
        try:
            ip = socket.gethostbyname(fqdn)
            with self._lock:
                if fqdn not in self._seen:
                    self._seen.add(fqdn)
                    return Subdomain(fqdn=fqdn, ip=ip, source="bruteforce")
        except socket.gaierror:
            pass
        return None

    def _register(self, name: str, source: str, found: list[Subdomain], seen_names: set[str]) -> None:
        name = name.strip().lstrip("*.")
        if not name or not name.endswith(self.target) or name in seen_names:
            return
        seen_names.add(name)
        with self._lock:
            if name not in self._seen:
                self._seen.add(name)
                try:
                    ip = socket.gethostbyname(name)
                except socket.gaierror:
                    ip = ""
                found.append(Subdomain(fqdn=name, ip=ip, source=source))
                log.info(f"  [{source.upper()[:3]}] {name} → {ip or 'unresolved'}")

    def bruteforce(self, progress: Progress | None = None) -> list[Subdomain]:
        wildcard_ip = self._is_wildcard()
        found: list[Subdomain] = []
        task = None
        if progress:
            task = progress.add_task("  [cyan]Subdomain brute-force[/cyan]", total=len(_WORDLIST))
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._resolve_sub, w): w for w in _WORDLIST}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    if wildcard_ip and result.ip == wildcard_ip:
                        pass
                    else:
                        found.append(result)
                        log.info(f"  [BF] {result.fqdn} → {result.ip}")
                if progress and task is not None:
                    progress.advance(task)
        if progress and task is not None:
            progress.update(task, description=f"  [green]Brute-force done — {len(found)} found[/green]")
        return found

    @_api_limiter
    def cert_transparency(self) -> list[Subdomain]:
        """crt.sh → HackerTarget → CertSpotter cascade."""
        found: list[Subdomain] = []
        seen_names: set[str]   = set()

        # Source 1: crt.sh
        try:
            r = _SESSION.get(f"https://crt.sh/?q=%.{self.target}&output=json", timeout=20)
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("name_value", "").splitlines():
                        self._register(name, "ct_log", found, seen_names)
                log.info(f"  crt.sh: {len(found)} subdomains")
                return found
            log.warn(f"  crt.sh HTTP {r.status_code} — trying fallbacks")
        except Exception as e:
            log.warn(f"  crt.sh failed ({e}) — trying fallbacks")

        # Source 2: HackerTarget
        pre = len(found)
        try:
            r = _SESSION.get(f"https://api.hackertarget.com/hostsearch/?q={self.target}", timeout=12)
            if r.status_code == 200 and "error" not in r.text[:30].lower():
                for line in r.text.splitlines():
                    self._register(line.split(",")[0].strip(), "ct_log", found, seen_names)
                if len(found) > pre:
                    log.info(f"  HackerTarget: {len(found)-pre} subdomains")
                    return found
        except Exception as e:
            log.warn(f"  HackerTarget failed ({e})")

        # Source 3: CertSpotter
        try:
            r = _SESSION.get(
                f"https://api.certspotter.com/v1/issuances"
                f"?domain={self.target}&include_subdomains=true&expand=dns_names",
                timeout=12,
            )
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("dns_names", []):
                        self._register(name, "ct_log", found, seen_names)
        except Exception as e:
            log.warn(f"  CertSpotter failed ({e})")

        return found

    @_api_limiter
    def alienvault_otx(self) -> list[Subdomain]:
        """AlienVault OTX passive DNS — no API key needed for basic."""
        found: list[Subdomain] = []
        seen_names: set[str]   = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
            r = _SESSION.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data.get("passive_dns", []):
                    name = entry.get("hostname", "")
                    self._register(name, "alienvault", found, seen_names)
                log.info(f"  AlienVault OTX: {len(found)} subdomains")
        except Exception as e:
            log.debug(f"  AlienVault OTX failed ({e})")
        return found

    @_api_limiter
    def anubisdb(self) -> list[Subdomain]:
        """AnubisDB subdomain lookup — free, no auth."""
        found: list[Subdomain] = []
        seen_names: set[str]   = set()
        try:
            r = _SESSION.get(f"https://jonlu.ca/anubis/subdomains/{self.target}", timeout=15)
            if r.status_code == 200:
                for name in r.json():
                    self._register(name, "anubis", found, seen_names)
                log.info(f"  AnubisDB: {len(found)} subdomains")
        except Exception as e:
            log.debug(f"  AnubisDB failed ({e})")
        return found


# ══════════════════════════════════════════════════════════════════════════════
# Takeover Engine
# ══════════════════════════════════════════════════════════════════════════════

# (cname_keyword, http_fingerprint, service_name)
_TAKEOVER_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("github.io",               "There isn't a GitHub Pages site here",          "GitHub Pages"),
    ("github.io",               "For root URLs (like http://example.com/)",       "GitHub Pages"),
    ("herokuapp.com",           "No such app",                                    "Heroku"),
    ("herokussl.com",           "No such app",                                    "Heroku"),
    ("netlify.app",             "Not Found - Request ID",                         "Netlify"),
    ("s3.amazonaws.com",        "NoSuchBucket",                                   "AWS S3"),
    ("s3.amazonaws.com",        "The specified bucket does not exist",            "AWS S3"),
    ("s3-website",              "NoSuchBucket",                                   "AWS S3"),
    ("digitaloceanspaces.com",  "NoSuchKey",                                      "DigitalOcean Spaces"),
    ("azurewebsites.net",       "404 Web Site not found",                         "Azure Web Apps"),
    ("cloudapp.net",            "404 Web Site not found",                         "Azure CloudApp"),
    ("cloudapp.azure.com",      "404 Web Site not found",                         "Azure"),
    ("azurefd.net",             "The resource you are looking for has been",      "Azure Front Door"),
    ("trafficmanager.net",      "404 Not Found",                                  "Azure Traffic Manager"),
    ("fastly.net",              "Fastly error: unknown domain",                   "Fastly"),
    ("fastly.net",              "Please check that this domain has been added",   "Fastly"),
    ("shopifypreview.com",      "Sorry, this shop is currently unavailable",      "Shopify"),
    ("myshopify.com",           "Sorry, this shop is currently unavailable",      "Shopify"),
    ("zendesk.com",             "Help Center Closed",                             "Zendesk"),
    ("freshdesk.com",           "There is no helpdesk here",                      "Freshdesk"),
    ("freshservice.com",        "This ServiceDesk does not exist",                "Freshservice"),
    ("ghost.io",                "The thing you were looking for is no longer",    "Ghost"),
    ("surge.sh",                "project not found",                              "Surge.sh"),
    ("bitbucket.io",            "Repository not found",                           "Bitbucket"),
    ("wpengine.com",            "The site you were looking for couldn't be found","WP Engine"),
    ("tumblr.com",              "There's nothing here",                           "Tumblr"),
    ("readme.io",               "Project doesnt exist",                           "ReadMe.io"),
    ("readme.com",              "Project doesnt exist",                           "ReadMe.io"),
    ("fly.dev",                 "404 Not Found",                                  "Fly.io"),
    ("fly.io",                  "Not Found",                                      "Fly.io"),
    ("vercel.app",              "The deployment could not be found",              "Vercel"),
    ("render.com",              "Service not found",                              "Render"),
    ("pantheonsite.io",         "The gods are wise, but do not know of the site", "Pantheon"),
    ("squarespace.com",         "You need to assign a valid domain",              "Squarespace"),
    ("webflow.io",              "The page you are looking for doesn't exist",     "Webflow"),
    ("unbouncepages.com",       "Sorry, this page is no longer here",            "Unbounce"),
    ("helpscoutdocs.com",       "No settings were found for this company",        "HelpScout Docs"),
    ("intercom.help",           "This page is reserved",                          "Intercom"),
    ("strikingly.com",          "But if you're looking to build your own website","Strikingly"),
    ("launchrock.com",          "It looks like you may have taken a wrong turn",  "LaunchRock"),
    ("bigcartel.com",           "Oops! We couldn't find that address",            "Big Cartel"),
    ("cargocollective.com",     "404 Not Found",                                  "Cargo Collective"),
    ("hubspot.com",             "does not exist",                                 "HubSpot"),
    ("typeform.com",            "Typeform is not accessible",                     "Typeform"),
    ("surveygizmo.com",         "data-html5-type",                                "SurveyGizmo"),
    ("pingdom.com",             "This public report page has not been activated", "Pingdom"),
    ("activecampaign.com",      "alt=\"LIGHTTPD\"",                               "ActiveCampaign"),
    ("campaignmonitor.com",     "Double-check the URL",                           "Campaign Monitor"),
    ("mailchimp.com",           "Oops! That page doesn't exist",                 "Mailchimp"),
    ("getresponse.com",         "This account is no longer active",               "GetResponse"),
    ("cargo.site",              "404 Not Found",                                  "Cargo"),
    ("tictail.com",             "Building a brand new",                           "Tictail"),
]

_TAKEOVER_CNAME_KEYWORDS = {fp[0] for fp in _TAKEOVER_FINGERPRINTS}


class TakeoverEngine:
    """Check each subdomain's CNAME chain for unclaimed-service fingerprints."""

    def check(self, subdomains: list[Subdomain], dns_records: dict[str, list[DNSRecord]]) -> list[Subdomain]:
        risks: list[Subdomain] = []
        candidates = self._build_candidates(subdomains, dns_records)

        def _probe(sub: Subdomain) -> Subdomain | None:
            cname_val = sub.fqdn
            # Determine which service to fingerprint based on CNAME value
            matched_fps = [fp for fp in _TAKEOVER_FINGERPRINTS if fp[0] in cname_val]
            if not matched_fps:
                return None
            try:
                r = _SESSION.get(
                    f"http://{sub.fqdn}", timeout=(4, 6), allow_redirects=True,
                    headers={"Host": sub.fqdn},
                )
                body = r.text
                for _, fingerprint, service in matched_fps:
                    if fingerprint.lower() in body.lower():
                        sub.takeover_risk    = "POSSIBLE"
                        sub.takeover_service = service
                        log.warn(
                            f"  [TAKEOVER] {sub.fqdn} → {service} — fingerprint matched"
                        )
                        return sub
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            for result in pool.map(_probe, candidates):
                if result:
                    risks.append(result)

        return risks

    def _build_candidates(
        self,
        subdomains: list[Subdomain],
        dns_records: dict[str, list[DNSRecord]],
    ) -> list[Subdomain]:
        """Return subdomains whose CNAME resolves to a known vulnerable service."""
        candidate_fqdns: set[str] = set()

        # Check CNAMEs in main DNS records
        for rec in dns_records.get("CNAME", []):
            for kw in _TAKEOVER_CNAME_KEYWORDS:
                if kw in rec.value:
                    candidate_fqdns.add(rec.rtype)

        # Check subdomains themselves
        candidates: list[Subdomain] = []
        for sub in subdomains:
            # Check if fqdn or its resolved CNAME touches a known service
            try:
                cname = socket.getfqdn(sub.fqdn)
                for kw in _TAKEOVER_CNAME_KEYWORDS:
                    if kw in cname or kw in sub.fqdn:
                        candidates.append(sub)
                        break
            except Exception:
                pass

        return candidates


# ══════════════════════════════════════════════════════════════════════════════
# WHOIS Engine
# ══════════════════════════════════════════════════════════════════════════════

_WHOIS_FIELDS: list[tuple[str, str]] = [
    ("registrar",          r"Registrar:\s*(.+)"),
    ("registrant_org",     r"Registrant\s*Org(?:anization)?:\s*(.+)"),
    ("registrant_country", r"Registrant\s*Country:\s*(.+)"),
    ("creation_date",      r"Creation\s*Date:\s*(.+)"),
    ("expiry_date",        r"(?:Expiry|Expiration|Registry Expiry)\s*Date:\s*(.+)"),
    ("updated_date",       r"Updated\s*Date:\s*(.+)"),
]

_PRIVACY_KEYWORDS = [
    "privacy", "protect", "whoisguard", "perfect privacy", "withheld",
    "redacted for privacy", "data protected", "registrar lock", "domains by proxy",
]


class WHOISEngine:
    def __init__(self, target: str):
        self.target = target

    @retry(max_attempts=2, delay=3.0, exceptions=(Exception,))
    def lookup(self) -> WHOISData:
        log.info(f"  Running WHOIS for {self.target}...")
        try:
            result = subprocess.run(
                ["whois", self.target],
                capture_output=True, text=True, timeout=20,
            )
            raw = result.stdout or result.stderr
        except FileNotFoundError:
            raise WHOISError("'whois' binary not found — apt install whois")
        except subprocess.TimeoutExpired:
            raise WHOISError("WHOIS timed out after 20s")

        data = WHOISData(raw=raw)

        for attr, pattern in _WHOIS_FIELDS:
            m = re.search(pattern, raw, re.IGNORECASE)
            if m:
                setattr(data, attr, m.group(1).strip())

        data.name_servers = list({
            m.group(1).strip().lower()
            for m in re.finditer(r"Name\s*Server:\s*(.+)", raw, re.I)
        })
        data.status = list({
            m.group(1).strip()
            for m in re.finditer(r"Domain\s*Status:\s*(.+)", raw, re.I)
        })
        data.emails = list({
            e.lower()
            for e in re.findall(r"[\w.+-]+@[\w.-]+\.\w{2,}", raw)
        })

        # Privacy protection detection
        raw_lower = raw.lower()
        data.privacy_protected = any(kw in raw_lower for kw in _PRIVACY_KEYWORDS)
        if data.privacy_protected:
            log.info("  WHOIS privacy protection detected")

        # Domain age & expiry
        for date_str in [data.creation_date, data.expiry_date]:
            if not date_str:
                continue
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y", "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S"):
                try:
                    parsed = datetime.strptime(date_str[:19], fmt[:len(date_str[:19])])
                    delta = (datetime.utcnow() - parsed).days
                    if date_str == data.creation_date:
                        data.domain_age_days = max(0, delta)
                        log.info(f"  Domain age: {delta} days ({delta // 365} years)")
                    else:
                        data.expiry_days = -delta   # positive = days remaining
                        if data.expiry_days <= 30:
                            log.warn(f"  Domain expiry in {data.expiry_days} days — at risk!")
                        elif data.expiry_days < 0:
                            log.warn(f"  Domain EXPIRED {-data.expiry_days} days ago!")
                    break
                except ValueError:
                    continue

        if data.registrar:
            log.info(f"  Registrar     : {data.registrar}")
        if data.creation_date:
            log.info(f"  Created       : {data.creation_date}")
        if data.expiry_date:
            log.info(f"  Expires       : {data.expiry_date}")
        if data.name_servers:
            log.info(f"  Name servers  : {', '.join(data.name_servers)}")
        if data.emails:
            log.info(f"  Emails        : {', '.join(data.emails)}")

        return data


# ══════════════════════════════════════════════════════════════════════════════
# ASN / GeoIP Engine  (ip-api + ipinfo fallback + RDAP)
# ══════════════════════════════════════════════════════════════════════════════

class ASNGeoEngine:
    _IPAPI  = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,reverse,query"
    _IPINFO = "https://ipinfo.io/{ip}/json"

    @_api_limiter
    @retry(max_attempts=2, delay=2.0, exceptions=(requests.RequestException,))
    def lookup(self, ip: str) -> ASNInfo:
        info = ASNInfo(ip=ip)

        # Primary: ip-api
        try:
            r = _SESSION.get(self._IPAPI.format(ip=ip), timeout=10)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    info.asn         = d.get("as", "")
                    info.org         = d.get("org", "")
                    info.isp         = d.get("isp", "")
                    info.country     = d.get("country", "")
                    info.region      = d.get("regionName", "")
                    info.city        = d.get("city", "")
                    info.lat         = d.get("lat", 0.0)
                    info.lon         = d.get("lon", 0.0)
                    info.timezone    = d.get("timezone", "")
                    info.reverse_dns = d.get("reverse", "")
                    log.info(f"  ASN      : {info.asn}")
                    log.info(f"  Org/ISP  : {info.org} / {info.isp}")
                    log.info(f"  Location : {info.city}, {info.region}, {info.country}")
        except Exception as e:
            log.warn(f"  ip-api failed ({e}) — trying ipinfo.io")
            # Fallback: ipinfo.io
            try:
                r2 = _SESSION.get(self._IPINFO.format(ip=ip), timeout=10)
                if r2.status_code == 200:
                    d2 = r2.json()
                    info.org     = d2.get("org", "")
                    info.country = d2.get("country", "")
                    info.city    = d2.get("city", "")
                    info.region  = d2.get("region", "")
                    loc = d2.get("loc", "0,0").split(",")
                    info.lat = float(loc[0]) if len(loc) == 2 else 0.0
                    info.lon = float(loc[1]) if len(loc) == 2 else 0.0
                    log.info(f"  Org/ISP  : {info.org}  ({info.city}, {info.country})")
            except Exception:
                pass

        # RDAP: abuse contact + network range
        try:
            rdap = self._rdap_lookup(ip)
            if rdap:
                info.asn_cidr     = rdap.get("cidr", "")
                info.network_name = rdap.get("name", "")
                info.abuse_email  = rdap.get("abuse_email", "")
                info.abuse_phone  = rdap.get("abuse_phone", "")
                if info.abuse_email:
                    log.info(f"  Abuse     : {info.abuse_email}")
                if info.asn_cidr:
                    log.info(f"  Network   : {info.network_name} — {info.asn_cidr}")
        except Exception:
            pass

        return info

    def _rdap_lookup(self, ip: str) -> dict:
        """Query RDAP for abuse contact and network range."""
        for url in [
            f"https://rdap.arin.net/registry/ip/{ip}",
            f"https://rdap.db.ripe.net/ip/{ip}",
            f"https://rdap.lacnic.net/rdap/ip/{ip}",
        ]:
            try:
                r = _SESSION.get(url, timeout=10, allow_redirects=True)
                if r.status_code == 200:
                    data = r.json()
                    result: dict = {}
                    # Network range from cidr0 or startAddress/endAddress
                    cidrs = data.get("cidr0CIDRs", [])
                    if cidrs:
                        result["cidr"] = cidrs[0].get("v4prefix", "") + "/" + str(cidrs[0].get("length", ""))
                    result["name"] = data.get("name", "")
                    # Abuse contact from entities
                    for entity in data.get("entities", []):
                        roles = entity.get("roles", [])
                        if "abuse" in roles:
                            for vcard in entity.get("vcardArray", [[]])[1:]:
                                for item in vcard:
                                    if isinstance(item, list) and len(item) >= 4:
                                        if item[0] == "email":
                                            result["abuse_email"] = item[3]
                                        elif item[0] == "tel":
                                            result["abuse_phone"] = item[3]
                    return result
            except Exception:
                continue
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# Threat Intelligence Engine  (DNSBL reputation)
# ══════════════════════════════════════════════════════════════════════════════

_DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "combined.abuse.ch",
    "drone.abuse.ch",
    "ips.backscatterer.org",
]

class ThreatIntelEngine:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout  = 3.0
        self.resolver.lifetime = 4.0
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    def check_dnsbl(self, ip: str) -> ThreatIntel:
        intel = ThreatIntel(ip=ip, reputation_score=100)
        try:
            # Reverse IP for DNSBL query format
            reversed_ip = ".".join(reversed(ip.split(".")))
        except Exception:
            return intel

        def _check_zone(zone: str) -> str | None:
            query = f"{reversed_ip}.{zone}"
            try:
                self.resolver.resolve(query, "A")
                return zone
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=len(_DNSBL_ZONES)) as pool:
            for zone in pool.map(_check_zone, _DNSBL_ZONES):
                if zone:
                    intel.dnsbl_hits.append(zone)
                    intel.listed = True
                    intel.reputation_score = max(0, intel.reputation_score - 15)
                    log.warn(f"  [DNSBL] {ip} listed on {zone}")

        if not intel.dnsbl_hits:
            log.info(f"  DNSBL: {ip} not listed on any of {len(_DNSBL_ZONES)} blacklists")
        else:
            intel.notes.append(f"Listed on {len(intel.dnsbl_hits)} DNSBL(s)")
            intel.notes.append("Review required before using as infrastructure")

        return intel


# ══════════════════════════════════════════════════════════════════════════════
# Mail Security Engine  (SPF / DMARC / DKIM / BIMI / MTA-STS / TLS-RPT)
# ══════════════════════════════════════════════════════════════════════════════

_DKIM_SELECTORS = [
    "default", "google", "k1", "k2", "mail", "dkim", "selector1", "selector2",
    "s1", "s2", "smtp", "mta", "key1", "key2", "sendgrid", "mailgun",
    "postmark", "ses", "sparkpost", "mandrill", "mailchimp", "elastic",
    "protonmail", "pm", "zoho", "yandex", "mimecast", "proofpoint",
    "dkim1", "dkim2", "email", "mxvault",
]

class MailSecEngine:
    def __init__(self, target: str):
        self.target   = target
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout  = 4.0
        self.resolver.lifetime = 6.0

    def _txt_records(self, name: str) -> list[str]:
        try:
            return [str(r) for r in self.resolver.resolve(name, "TXT")]
        except Exception:
            return []

    def analyze_spf(self) -> tuple[str, bool, list[str]]:
        txts = self._txt_records(self.target)
        for txt in txts:
            if "v=spf1" in txt.lower():
                record = txt.strip('"')
                valid = "-all" in record or "~all" in record
                includes = re.findall(r"include:([^\s]+)", record)
                log.info(f"  SPF  : {record[:100]}")
                if not valid:
                    log.warn("  SPF  : missing -all / ~all — spoofing risk")
                if includes:
                    log.info(f"  SPF includes: {', '.join(includes)}")
                return record, valid, includes
        log.warn("  SPF  : no record found — domain spoofing possible")
        return "", False, []

    def analyze_dmarc(self) -> tuple[str, str, list[str], list[str]]:
        txts = self._txt_records(f"_dmarc.{self.target}")
        for txt in txts:
            if "v=DMARC1" in txt:
                record = txt.strip('"')
                policy = (re.search(r"p=(\w+)", record) or type("", (), {"group": lambda *a: "none"})()).group(1)
                rua = re.findall(r"rua=([^;]+)", record)
                ruf = re.findall(r"ruf=([^;]+)", record)
                rua = [x.strip() for x in ",".join(rua).split(",") if x.strip()]
                ruf = [x.strip() for x in ",".join(ruf).split(",") if x.strip()]
                log.info(f"  DMARC: {record[:100]}")
                if policy == "none":
                    log.warn("  DMARC: policy=none — monitoring only, not enforcing")
                return record, policy, rua, ruf
        log.warn("  DMARC: no record found")
        return "", "", [], []

    def check_dkim(self) -> list[str]:
        found: list[str] = []
        for sel in _DKIM_SELECTORS:
            if self._txt_records(f"{sel}._domainkey.{self.target}"):
                found.append(sel)
                log.info(f"  DKIM : selector '{sel}' found")
        if not found:
            log.warn("  DKIM : no common selectors found")
        return found

    def check_bimi(self) -> str:
        txts = self._txt_records(f"default._bimi.{self.target}")
        for txt in txts:
            if "v=BIMI1" in txt:
                log.info(f"  BIMI : {txt[:80]}")
                return txt.strip('"')
        return ""

    def check_mta_sts(self) -> str:
        txts = self._txt_records(f"_mta-sts.{self.target}")
        for txt in txts:
            if "v=STSv1" in txt:
                m = re.search(r"mode=(\w+)", txt)
                policy = m.group(1).lower() if m else "unknown"
                log.info(f"  MTA-STS: mode={policy}")
                return policy
        log.info("  MTA-STS: not configured")
        return ""

    def check_tls_rpt(self) -> str:
        txts = self._txt_records(f"_smtp._tls.{self.target}")
        for txt in txts:
            if "v=TLSRPTv1" in txt:
                log.info(f"  TLS-RPT: {txt[:80]}")
                return txt.strip('"')
        return ""

    def run(self) -> MailSecurity:
        ms = MailSecurity()
        ms.spf_record, ms.spf_valid, ms.spf_includes = self.analyze_spf()
        ms.dmarc_record, ms.dmarc_policy, ms.dmarc_rua, ms.dmarc_ruf = self.analyze_dmarc()
        ms.dkim_selectors = self.check_dkim()
        ms.bimi_record    = self.check_bimi()
        ms.mta_sts_policy = self.check_mta_sts()
        ms.tls_rpt_record = self.check_tls_rpt()

        # Issue classification
        if not ms.spf_record:
            ms.issues.append("No SPF record — domain spoofing possible")
        elif not ms.spf_valid:
            ms.issues.append("SPF missing -all / ~all — permissive policy")
        if not ms.dmarc_record:
            ms.issues.append("No DMARC record — phishing protection absent")
        elif ms.dmarc_policy == "none":
            ms.issues.append("DMARC policy=none — monitoring only, not enforcing")
        if not ms.dkim_selectors:
            ms.issues.append("No DKIM selectors found on common names")
        if not ms.mta_sts_policy:
            ms.issues.append("MTA-STS not configured — SMTP downgrade attacks possible")
        elif ms.mta_sts_policy == "testing":
            ms.issues.append("MTA-STS mode=testing — not yet enforcing")
        if not ms.tls_rpt_record:
            ms.issues.append("TLS-RPT not configured — no TLS failure reporting")

        return ms


# ══════════════════════════════════════════════════════════════════════════════
# Wayback Machine Engine
# ══════════════════════════════════════════════════════════════════════════════

class WaybackEngine:
    _CDX = (
        "https://web.archive.org/cdx/search/cdx"
        "?url=*.{domain}&output=json&fl=original,timestamp"
        "&collapse=urlkey&limit=5000&matchType=domain"
    )

    @_api_limiter
    def query(self, target: str) -> WaybackData:
        data = WaybackData()
        try:
            r = _SESSION.get(self._CDX.format(domain=target), timeout=20)
            if r.status_code != 200:
                log.warn(f"  Wayback Machine HTTP {r.status_code}")
                return data

            rows = r.json()
            if len(rows) <= 1:   # first row is header
                log.info("  Wayback Machine: no captures found")
                return data

            rows = rows[1:]   # skip header
            data.total_urls = len(rows)

            paths: set[str] = set()
            years: set[int] = set()
            timestamps: list[str] = []

            for row in rows:
                if len(row) < 2:
                    continue
                url_str, ts = row[0], row[1]
                try:
                    parsed = urlparse(url_str)
                    path = parsed.path
                    if path and path != "/":
                        paths.add(path)
                except Exception:
                    pass
                if len(ts) >= 4:
                    try:
                        years.add(int(ts[:4]))
                    except ValueError:
                        pass
                    timestamps.append(ts)

            data.endpoints    = sorted(paths)[:200]   # cap at 200 unique paths
            data.years_active = sorted(years)
            if timestamps:
                data.oldest_snapshot = min(timestamps)
                data.newest_snapshot = max(timestamps)

            log.info(
                f"  Wayback Machine: {data.total_urls} captures, "
                f"{len(data.endpoints)} unique paths, "
                f"years: {data.years_active[0] if data.years_active else '?'}"
                f"–{data.years_active[-1] if data.years_active else '?'}"
            )
        except Exception as e:
            log.warn(f"  Wayback Machine failed ({e})")

        return data


# ══════════════════════════════════════════════════════════════════════════════
# Technology Hint Engine  (DNS values + subdomain name inference)
# ══════════════════════════════════════════════════════════════════════════════

_TECH_PATTERNS: list[tuple[str, str, str]] = [
    # CDN
    ("CDN",      "Cloudflare",        "cloudflare"),
    ("CDN",      "Fastly",            "fastly"),
    ("CDN",      "Akamai",            "akamai"),
    ("CDN",      "AWS CloudFront",    "cloudfront.net"),
    ("CDN",      "Azure CDN",         "azureedge.net"),
    ("CDN",      "Incapsula",         "incapsula.com"),
    ("CDN",      "Sucuri",            "sucuri.net"),
    ("CDN",      "Bunny CDN",         "b-cdn.net"),
    ("CDN",      "KeyCDN",            "keycdn.com"),
    # Cloud hosting
    ("Cloud",    "AWS",               "amazonaws.com"),
    ("Cloud",    "Google Cloud",      "googleusercontent.com"),
    ("Cloud",    "Azure",             "azure.com"),
    ("Cloud",    "Azure Web Apps",    "azurewebsites.net"),
    ("Cloud",    "Heroku",            "herokussl.com"),
    ("Cloud",    "DigitalOcean",      "digitalocean"),
    ("Cloud",    "Linode / Akamai",   "linode.com"),
    ("Cloud",    "Vercel",            "vercel.app"),
    ("Cloud",    "Netlify",           "netlify.app"),
    ("Cloud",    "Fly.io",            "fly.dev"),
    # Email providers (via MX)
    ("Email",    "Google Workspace",  "google.com"),
    ("Email",    "Microsoft 365",     "protection.outlook.com"),
    ("Email",    "ProofPoint",        "pphosted.com"),
    ("Email",    "Mimecast",          "mimecast.com"),
    ("Email",    "SendGrid",          "sendgrid.net"),
    ("Email",    "Mailgun",           "mailgun"),
    ("Email",    "Amazon SES",        "amazonses.com"),
    ("Email",    "Postmark",          "postmarkapp.com"),
    # DNS providers
    ("DNS",      "NS1",               "nsone.net"),
    ("DNS",      "Route53",           "awsdns"),
    ("DNS",      "DNSimple",          "dnsimple.com"),
    ("DNS",      "Cloudflare DNS",    "ns.cloudflare.com"),
    ("DNS",      "Dyn",               "dynect.net"),
    ("DNS",      "UltraDNS",          "ultradns"),
    # Security / WAF
    ("WAF",      "Imperva / Incapsula","incapsula.com"),
    ("WAF",      "Sucuri WAF",        "sucuri.net"),
    ("WAF",      "Cloudflare WAF",    "cloudflare"),
    ("WAF",      "AWS WAF",           "cloudfront.net"),
    ("WAF",      "Akamai Kona",       "akamaiedge.net"),
]

# Subdomain prefix → tech inference
_SUBDOMAIN_TECH: list[tuple[str, str, str]] = [
    ("jenkins",    "DevOps",    "Jenkins CI/CD"),
    ("gitlab",     "DevOps",    "GitLab"),
    ("gitea",      "DevOps",    "Gitea"),
    ("sonar",      "DevOps",    "SonarQube"),
    ("nexus",      "DevOps",    "Nexus Repository"),
    ("artifactory","DevOps",    "JFrog Artifactory"),
    ("harbor",     "DevOps",    "Harbor Registry"),
    ("grafana",    "Monitoring","Grafana"),
    ("kibana",     "Monitoring","Kibana / ELK"),
    ("prometheus", "Monitoring","Prometheus"),
    ("splunk",     "Monitoring","Splunk"),
    ("vault",      "Security",  "HashiCorp Vault"),
    ("keycloak",   "Auth",      "Keycloak IAM"),
    ("portainer",  "DevOps",    "Portainer"),
    ("rancher",    "DevOps",    "Rancher Kubernetes"),
    ("argocd",     "DevOps",    "Argo CD"),
    ("phpmyadmin", "Database",  "phpMyAdmin"),
    ("adminer",    "Database",  "Adminer"),
    ("pgadmin",    "Database",  "pgAdmin"),
    ("rabbit",     "Messaging", "RabbitMQ"),
    ("kafka",      "Messaging", "Apache Kafka"),
    ("vpn",        "Network",   "VPN Endpoint"),
    ("bastion",    "Network",   "Bastion Host"),
    ("sso",        "Auth",      "SSO / Identity Provider"),
    ("jira",       "Project",   "Atlassian Jira"),
    ("confluence", "Project",   "Atlassian Confluence"),
    ("wiki",       "Project",   "Wiki / Knowledge Base"),
    ("helpdesk",   "Support",   "Help Desk Portal"),
    ("zendesk",    "Support",   "Zendesk"),
]


class TechHintEngine:
    def analyze(
        self,
        dns_records: dict[str, list[DNSRecord]],
        subdomains: list[Subdomain],
    ) -> list[TechHint]:
        hints: list[TechHint] = []
        seen:  set[str]       = set()

        all_values = [
            (rtype, r.value.lower())
            for rtype, recs in dns_records.items()
            for r in recs
        ]

        # Pattern match against DNS values
        for category, name, pattern in _TECH_PATTERNS:
            key = f"{category}:{name}"
            if key in seen:
                continue
            for rtype, val in all_values:
                if pattern.lower() in val:
                    hints.append(TechHint(category=category, name=name, evidence=f"{rtype}: {val[:80]}"))
                    seen.add(key)
                    log.info(f"  [TECH] {category} → {name}")
                    break

        # Infer tech from subdomain names
        for sub in subdomains:
            prefix = sub.fqdn.split(".")[0].lower()
            for kw, category, name in _SUBDOMAIN_TECH:
                key = f"{category}:{name}"
                if key not in seen and kw in prefix:
                    hints.append(TechHint(
                        category=category,
                        name=name,
                        evidence=f"subdomain: {sub.fqdn}",
                    ))
                    seen.add(key)
                    log.info(f"  [TECH] {category} → {name}  (subdomain: {sub.fqdn})")
                    break

        return hints


# ══════════════════════════════════════════════════════════════════════════════
# Google Dorks Engine  (query generation, not execution)
# ══════════════════════════════════════════════════════════════════════════════

class GoogleDorksEngine:
    """Generate ready-to-paste Google dork queries for manual OSINT research."""

    def generate(self, target: str) -> list[str]:
        return [
            f'site:{target}',
            f'site:{target} filetype:pdf OR filetype:doc OR filetype:docx',
            f'site:{target} filetype:xls OR filetype:xlsx OR filetype:csv',
            f'site:{target} filetype:sql OR filetype:bak OR filetype:log',
            f'site:{target} inurl:admin OR inurl:login OR inurl:dashboard',
            f'site:{target} inurl:config OR inurl:setup OR inurl:.env',
            f'site:{target} intext:password OR intext:passwd OR intext:"api key"',
            f'site:{target} "index of /" OR "directory listing"',
            f'site:{target} ext:php inurl:"?id=" OR inurl:"?page="',
            f'site:{target} "Internal Server Error" OR "stack trace" OR "exception"',
            f'site:{target} "confidential" OR "internal use only" OR "do not distribute"',
            f'"{target}" site:pastebin.com OR site:paste.ee OR site:ghostbin.com',
            f'"{target}" site:github.com OR site:gitlab.com',
            f'"{target}" intext:@{target} email',
            f'site:{target} inurl:phpinfo.php OR inurl:info.php OR inurl:test.php',
            f'site:{target} inurl:wp-admin OR inurl:wp-login OR inurl:administrator',
            f'site:{target} inurl:/api/v1 OR inurl:/api/v2 OR inurl:/graphql',
            f'site:{target} "swagger" OR "api-docs" OR "openapi.json"',
        ]


# ══════════════════════════════════════════════════════════════════════════════
# Result print tables
# ══════════════════════════════════════════════════════════════════════════════

def _print_dns_table(records: dict[str, list[DNSRecord]], dnssec: bool, dangling: list[str]) -> None:
    t = Table(title="DNS Records", box=box.ROUNDED, border_style="cyan",
              header_style="bold cyan", show_lines=False)
    t.add_column("Type",  style="bold green",  width=8)
    t.add_column("TTL",   style="dim",          width=7)
    t.add_column("Value", style="white",        overflow="fold")

    for rtype in ["A","AAAA","CNAME","NS","MX","TXT","SOA","CAA","SRV","NAPTR","HINFO","DNSKEY"]:
        for r in records.get(rtype, []):
            t.add_row(r.rtype, str(r.ttl), r.value[:120])
    _console.print(t)

    if dnssec:
        _console.print("[green]  ✓ DNSSEC enabled[/green]")
    else:
        _console.print("[yellow]  ! DNSSEC not detected[/yellow]")

    if dangling:
        _console.print(f"[red]  ! Dangling CNAMEs ({len(dangling)}): {', '.join(dangling[:3])}[/red]")


def _print_subdomain_table(subs: list[Subdomain]) -> None:
    if not subs:
        return
    t = Table(title=f"Subdomains ({len(subs)} found)", box=box.ROUNDED,
              border_style="cyan", header_style="bold cyan")
    t.add_column("FQDN",    style="green",  overflow="fold")
    t.add_column("IP",      style="white",  width=16)
    t.add_column("Source",  style="yellow", width=12)
    t.add_column("Takeover",style="red",    width=14)

    for s in sorted(subs, key=lambda x: x.fqdn):
        takeover = f"[red]{s.takeover_service}[/red]" if s.takeover_risk else ""
        t.add_row(s.fqdn, s.ip or "—", s.source, takeover)
    _console.print(t)


def _print_whois_table(data: WHOISData) -> None:
    t = Table(title="WHOIS", box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
    t.add_column("Field",  style="bold white", width=22)
    t.add_column("Value",  style="white",       overflow="fold")

    t.add_row("Registrar",         data.registrar or "—")
    t.add_row("Registrant Org",    data.registrant_org or "—")
    t.add_row("Country",           data.registrant_country or "—")
    t.add_row("Created",           data.creation_date or "—")
    t.add_row("Expires",           data.expiry_date or "—")
    t.add_row("Privacy Protected", "[yellow]Yes[/yellow]" if data.privacy_protected else "No")
    if data.domain_age_days >= 0:
        t.add_row("Domain Age", f"{data.domain_age_days} days ({data.domain_age_days // 365} years)")
    if data.expiry_days != -1:
        color = "red" if data.expiry_days <= 30 else "green"
        t.add_row("Days Until Expiry", f"[{color}]{data.expiry_days}[/{color}]")
    if data.emails:
        t.add_row("Emails Found", ", ".join(data.emails[:5]))
    if data.name_servers:
        t.add_row("Name Servers", ", ".join(data.name_servers))
    _console.print(t)


def _print_asn_table(info: ASNInfo) -> None:
    t = Table(title="ASN / GeoIP", box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
    t.add_column("Field",  style="bold white", width=16)
    t.add_column("Value",  style="white",       overflow="fold")

    rows = [
        ("IP",            info.ip),
        ("ASN",           info.asn),
        ("Network",       f"{info.network_name} — {info.asn_cidr}" if info.asn_cidr else info.network_name),
        ("Org / ISP",     f"{info.org} / {info.isp}"),
        ("Location",      f"{info.city}, {info.region}, {info.country}"),
        ("Lat / Lon",     f"{info.lat}, {info.lon}"),
        ("Timezone",      info.timezone),
        ("Reverse DNS",   info.reverse_dns),
        ("Abuse Email",   info.abuse_email),
        ("Abuse Phone",   info.abuse_phone),
    ]
    for field, val in rows:
        if val and val.strip(" ,/"):
            t.add_row(field, val)
    _console.print(t)


def _print_threat_table(intel: ThreatIntel) -> None:
    color  = "red" if intel.listed else "green"
    status = f"[{color}]{'LISTED' if intel.listed else 'CLEAN'}[/{color}]"
    t = Table(title=f"Threat Intelligence — {status}", box=box.ROUNDED,
              border_style="cyan", header_style="bold cyan")
    t.add_column("Check",  style="bold white", width=20)
    t.add_column("Result", style="white",       overflow="fold")

    t.add_row("Reputation Score", f"[{color}]{intel.reputation_score}/100[/{color}]")
    if intel.dnsbl_hits:
        t.add_row("DNSBL Listings", "\n".join(intel.dnsbl_hits))
    else:
        t.add_row("DNSBL Listings", "[green]None[/green]")
    for note in intel.notes:
        t.add_row("Note", note)
    _console.print(t)


def _print_mail_table(ms: MailSecurity) -> None:
    t = Table(title="Mail Security", box=box.ROUNDED,
              border_style="cyan", header_style="bold cyan")
    t.add_column("Check",  style="bold white", width=16)
    t.add_column("Status", width=12)
    t.add_column("Detail", overflow="fold")

    t.add_row("SPF",     "[green]OK[/green]" if ms.spf_valid else "[red]FAIL[/red]",
              ms.spf_record[:80] or "—")
    if ms.spf_includes:
        t.add_row("SPF Includes", "", ", ".join(ms.spf_includes))
    t.add_row("DMARC",   "[green]OK[/green]" if ms.dmarc_policy not in ("","none") else "[yellow]WARN[/yellow]",
              ms.dmarc_record[:80] or "—")
    if ms.dmarc_rua:
        t.add_row("DMARC RUA (agg)", "", ", ".join(ms.dmarc_rua))
    if ms.dmarc_ruf:
        t.add_row("DMARC RUF (forensic)", "", ", ".join(ms.dmarc_ruf))
    t.add_row("DKIM",    "[green]OK[/green]" if ms.dkim_selectors else "[yellow]WARN[/yellow]",
              ", ".join(ms.dkim_selectors) or "—")
    t.add_row("BIMI",    "[green]OK[/green]" if ms.bimi_record else "[dim]—[/dim]",
              ms.bimi_record[:60] or "not configured")
    t.add_row("MTA-STS", "[green]OK[/green]" if ms.mta_sts_policy == "enforce" else
              ("[yellow]TESTING[/yellow]" if ms.mta_sts_policy == "testing" else "[dim]—[/dim]"),
              ms.mta_sts_policy or "not configured")
    t.add_row("TLS-RPT", "[green]OK[/green]" if ms.tls_rpt_record else "[dim]—[/dim]",
              ms.tls_rpt_record[:60] or "not configured")
    for issue in ms.issues:
        t.add_row("[red]Issue[/red]", "", issue)
    _console.print(t)


def _print_wayback_table(wb: WaybackData) -> None:
    if not wb.total_urls:
        return
    t = Table(title="Wayback Machine History", box=box.ROUNDED,
              border_style="cyan", header_style="bold cyan")
    t.add_column("Metric",   style="bold white", width=22)
    t.add_column("Value",    style="white",       overflow="fold")

    t.add_row("Total Captures",   str(wb.total_urls))
    t.add_row("Unique Paths",     str(len(wb.endpoints)))
    t.add_row("Oldest Snapshot",  wb.oldest_snapshot or "—")
    t.add_row("Newest Snapshot",  wb.newest_snapshot or "—")
    years_str = " ".join(str(y) for y in wb.years_active)
    t.add_row("Years Active",     years_str or "—")

    if wb.endpoints:
        t.add_section()
        for path in wb.endpoints[:15]:   # show first 15 paths
            t.add_row("Path", path)
        if len(wb.endpoints) > 15:
            t.add_row("…", f"and {len(wb.endpoints)-15} more paths")
    _console.print(t)


def _print_tech_table(hints: list[TechHint]) -> None:
    if not hints:
        return
    t = Table(title="Technology & Infrastructure", box=box.ROUNDED,
              border_style="cyan", header_style="bold cyan")
    t.add_column("Category", style="bold yellow", width=12)
    t.add_column("Tech",     style="green",        width=22)
    t.add_column("Evidence", style="dim",           overflow="fold")
    for h in hints:
        t.add_row(h.category, h.name, h.evidence[:90])
    _console.print(t)


def _print_dorks_table(dorks: list[str]) -> None:
    t = Table(title="Google Dork Queries (paste into Google manually)",
              box=box.ROUNDED, border_style="dim", header_style="bold dim")
    t.add_column("#",      style="dim",  width=4)
    t.add_column("Query",  style="cyan", overflow="fold")
    for i, dork in enumerate(dorks, 1):
        t.add_row(str(i), dork)
    _console.print(t)


def _print_takeover_table(risks: list[Subdomain]) -> None:
    if not risks:
        return
    t = Table(title=f"[red]Subdomain Takeover Risks ({len(risks)} found)[/red]",
              box=box.ROUNDED, border_style="red", header_style="bold red")
    t.add_column("Subdomain",  style="green", overflow="fold")
    t.add_column("Service",    style="red",   width=20)
    t.add_column("IP",         style="white", width=16)
    for s in risks:
        t.add_row(s.fqdn, s.takeover_service, s.ip or "—")
    _console.print(t)


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

class PassiveRecon:
    """
    Orchestrates all passive sub-engines with maximum concurrency.
    Nothing sent directly to the target — all intelligence gathered via
    third-party APIs, public DNS, WHOIS, and OSINT sources.
    """

    def __init__(self, target: str, ip: str):
        self.target = target
        self.ip     = ip

    def run(self) -> dict:
        result = ReconResult(target=self.target, ip=self.ip)

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

            # ── DNS records + DNSSEC + dangling CNAMEs ────────────────────────
            dns_task = progress.add_task("  [cyan]DNS enumeration[/cyan]", total=None)
            dns_eng  = DNSEngine(self.target, self.ip)
            result.dns_records    = dns_eng.enumerate_records()
            result.reverse_dns    = dns_eng.reverse_lookup()
            result.dnssec_enabled = dns_eng.check_dnssec()
            result.dangling_cnames = dns_eng.check_dangling_cnames(result.dns_records)
            progress.update(dns_task, total=1, completed=1,
                            description="  [green]DNS enumeration done[/green]")

            # ── Zone transfer ─────────────────────────────────────────────────
            ns_recs = result.dns_records.get("NS", [])
            if ns_recs:
                zt_task = progress.add_task("  [cyan]Zone transfer attempt[/cyan]", total=None)
                result.zone_transfer = dns_eng.attempt_zone_transfer(ns_recs)
                progress.update(zt_task, total=1, completed=1,
                                description="  [green]Zone transfer done[/green]")

            # ── Launch concurrent background tasks ────────────────────────────
            _threads: dict[str, threading.Thread] = {}
            _results: dict[str, Any] = {}

            def _run(key: str, fn, *args):
                try:
                    _results[key] = fn(*args)
                except Exception as e:
                    log.warn(f"  [{key}] failed: {e}")

            for key, fn, args in [
                ("whois",    WHOISEngine(self.target).lookup,      ()),
                ("asn",      ASNGeoEngine().lookup,                 (self.ip,)),
                ("threat",   ThreatIntelEngine().check_dnsbl,       (self.ip,)),
                ("mail",     MailSecEngine(self.target).run,        ()),
                ("wayback",  WaybackEngine().query,                 (self.target,)),
                ("ct",       SubdomainEngine(self.target).cert_transparency, ()),
                ("otx",      SubdomainEngine(self.target).alienvault_otx,    ()),
                ("anubis",   SubdomainEngine(self.target).anubisdb,          ()),
            ]:
                t = threading.Thread(target=_run, args=(key, fn) + args, daemon=True)
                t.start()
                _threads[key] = t

            # ── Brute-force (main thread — has progress bar) ──────────────────
            sub_eng    = SubdomainEngine(self.target)
            bf_results = sub_eng.bruteforce(progress)

            # ── Wait for all background threads ──────────────────────────────
            for key, t in _threads.items():
                t.join(timeout=45)

            # ── Merge WHOIS / ASN / Threat / Mail / Wayback ───────────────────
            if "whois" in _results:
                result.whois = _results["whois"]
            if "asn" in _results:
                result.asn_geo = _results["asn"]
            if "threat" in _results:
                result.threat_intel = _results["threat"]
            if "mail" in _results:
                result.mail_security = _results["mail"]
            if "wayback" in _results:
                result.wayback = _results["wayback"]

            # ── Merge all subdomain sources ───────────────────────────────────
            seen_fqdns: set[str] = {s.fqdn for s in bf_results}
            all_subs   = list(bf_results)

            for key in ["ct", "otx", "anubis"]:
                for s in _results.get(key, []):
                    if s.fqdn not in seen_fqdns:
                        seen_fqdns.add(s.fqdn)
                        all_subs.append(s)

            result.subdomains = all_subs

            # ── Subdomain takeover detection ──────────────────────────────────
            takeover_task = progress.add_task("  [cyan]Takeover detection[/cyan]", total=None)
            result.takeover_risks = TakeoverEngine().check(all_subs, result.dns_records)
            # Annotate source subdomains with risk info
            risk_map = {s.fqdn: s for s in result.takeover_risks}
            for sub in result.subdomains:
                if sub.fqdn in risk_map:
                    sub.takeover_risk    = risk_map[sub.fqdn].takeover_risk
                    sub.takeover_service = risk_map[sub.fqdn].takeover_service
            progress.update(takeover_task, total=1, completed=1,
                            description="  [green]Takeover detection done[/green]")

            # ── Technology hints ──────────────────────────────────────────────
            tech_task = progress.add_task("  [cyan]Technology fingerprinting[/cyan]", total=None)
            result.tech_hints = TechHintEngine().analyze(result.dns_records, result.subdomains)
            progress.update(tech_task, total=1, completed=1,
                            description="  [green]Tech fingerprinting done[/green]")

            # ── Google dorks ──────────────────────────────────────────────────
            result.google_dorks = GoogleDorksEngine().generate(self.target)

        # ── Print result tables ───────────────────────────────────────────────
        _print_dns_table(result.dns_records, result.dnssec_enabled, result.dangling_cnames)
        _print_subdomain_table(result.subdomains)
        if result.takeover_risks:
            _print_takeover_table(result.takeover_risks)
        _print_whois_table(result.whois)
        _print_asn_table(result.asn_geo)
        _print_threat_table(result.threat_intel)
        _print_mail_table(result.mail_security)
        _print_wayback_table(result.wayback)
        _print_tech_table(result.tech_hints)
        _print_dorks_table(result.google_dorks)

        log.success(
            f"Passive recon complete — "
            f"{sum(len(v) for v in result.dns_records.values())} DNS records, "
            f"{len(result.subdomains)} subdomains "
            f"({len(result.takeover_risks)} takeover risks), "
            f"{len(result.tech_hints)} tech hints, "
            f"{result.wayback.total_urls} Wayback captures, "
            f"reputation score: {result.threat_intel.reputation_score}/100"
        )

        return result.to_dict()
