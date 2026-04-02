#!/usr/bin/env python3
"""
APT Watch — IOC Collector automated
=====================================
Collects, parses and exports IOCs for tracked Russian APT groups.
Supported sources:
  - TrendMicro Research articles (scraping IOC .txt link)
  - TrendMicro IOC .txt files (defanged tabular format)
  - OTX AlienVault pulses (API JSON)
  - Security blogs (regex IOC extraction)
  - GitHub maltrail (sections by group)
  - ESET PDFs (via pypdf)

Safelist: Loads safelist.yaml to filter FPs (IPs, domains, emails).

Modes (via config.ini [general] mode):
  LOCAL  — Generates YAML submissions + exports to repo/community/submissions/
           Contributor commits and pushes (PR). No DB access.
  SERVER — Generates same artifacts + auto-import DB + git commit/push.
           Also validates incoming contributions.
  GITHUB — Like local but API keys via env vars (CI/CD).

Usage:
  python aptwatch_ioc_collector.py                    # all groups
  python aptwatch_ioc_collector.py --group pawn_storm # specific group
  python aptwatch_ioc_collector.py --output ./iocs    # output folder
  python aptwatch_ioc_collector.py --format json      # format json or txt
  python aptwatch_ioc_collector.py --dry-run          # collect without writing
  python aptwatch_ioc_collector.py --mode local       # force local mode

Dependencies:
  pip install pypdf requests pyyaml
"""

import re
import sys
import json
import argparse
import logging
import subprocess
from datetime import date
from pathlib import Path
from typing import Any

from aptwatch_config import config as app_config

# --- Optional dependencies ---
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    HAS_REQUESTS = False

try:
    from pypdf import PdfReader
    import io
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger("aptwatch")

SCRIPT_DIR = Path(__file__).parent
SAFELIST_PATH = SCRIPT_DIR / "safelist.yaml"

# ═══════════════════════════════════════════════════════════════
#  SAFELIST — loaded from safelist.yaml
# ═══════════════════════════════════════════════════════════════

class Safelist:
    """Loads and applies the YAML safelist to filter false positives."""

    def __init__(self, path: Path = SAFELIST_PATH):
        self.ips: set[str] = set()
        self.ip_ranges: list[str] = []
        self.domains: set[str] = set()
        self.domain_patterns: list[str] = []
        self.emails: list[str] = []
        self._load(path)

    def _load(self, path: Path):
        if not path.exists():
            log.warning(f"Safelist not found: {path} — minimal FP filtering")
            self._load_defaults()
            return
        if not HAS_YAML:
            log.warning("pyyaml not installed — safelist ignored, minimal FP filtering")
            self._load_defaults()
            return
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.ips = set(data.get("ips", []))
            self.ip_ranges = data.get("ip_ranges", [])
            self.domains = set(d.lower() for d in data.get("domains", []))
            self.domain_patterns = data.get("domain_patterns", [])
            self.emails = data.get("emails", [])
            log.info(f"Safelist loaded: {len(self.ips)} IPs, "
                     f"{len(self.ip_ranges)} ranges, "
                     f"{len(self.domains)} domains, "
                     f"{len(self.domain_patterns)} patterns, "
                     f"{len(self.emails)} emails")
        except Exception as e:
            log.error(f"Error loading safelist: {e}")
            self._load_defaults()

    def _load_defaults(self):
        """Minimal fallback if safelist.yaml is missing."""
        self.ips = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "0.0.0.0",
                    "9.7.4.4", "23.52.43.176", "34.41.59.0", "255.255.255.255"}
        self.ip_ranges = ["10.", "127.", "169.254.", "192.168.", "0.", "255.", "224.", "240.",
                          "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                          "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                          "172.28.", "172.29.", "172.30.", "172.31."]
        self.domains = {"microsoft.com", "google.com", "github.com", "cloudflare.com",
                        "facebook.com", "twitter.com", "youtube.com", "linkedin.com",
                        "instagram.com", "adobe.com", "mozilla.org", "w3.org", "mitre.org",
                        "trendmicro.com", "eset.com", "wikipedia.org"}
        self.domain_patterns = ["googleapis", "gstatic", "doubleclick", "ampproject",
                                "govdelivery", "qualtrics"]
        self.emails = ["abuse@", "postmaster@", "noreply@", "no-reply@"]

    def is_safe_ip(self, ip: str) -> bool:
        if ip in self.ips:
            return True
        return any(ip.startswith(r) for r in self.ip_ranges)

    def is_safe_domain(self, domain: str) -> bool:
        d = domain.lower()
        # Exact match or subdomain of a safelisted domain
        for safe in self.domains:
            if d == safe or d.endswith("." + safe):
                return True
        # Pattern match
        return any(p in d for p in self.domain_patterns)

    def is_safe_email(self, email: str) -> bool:
        e = email.lower()
        for pattern in self.emails:
            if pattern.startswith("@"):
                # Suffix match
                if e.endswith(pattern):
                    return True
            elif pattern.endswith("@"):
                # Prefix match (e.g.: "abuse@")
                if e.startswith(pattern):
                    return True
            else:
                # Exact match
                if e == pattern:
                    return True
        # Also check domain part against domain safelist
        if "@" in e:
            domain = e.split("@")[1]
            return self.is_safe_domain(domain)
        return False


# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION — Sources by APT group
# ═══════════════════════════════════════════════════════════════

GROUPS: dict[str, dict[str, Any]] = {
    "pawn_storm": {
        "label": "Pawn Storm / APT28 (GRU Unit 26165)",
        "aliases": ["Fancy Bear", "Forest Blizzard", "FROZENLAKE", "Iron Twilight", "Sednit"],
        "trendmicro_articles": [
            "https://www.trendmicro.com/en_us/research/26/c/pawn-storm-targets-govt-infra.html",
        ],
        "ioc_txt_direct": [
            "https://documents.trendmicro.com/assets/txt/Pawn%20Storm%20Deploys%20PRISMA%20IOCs-xQ48S7H.txt",
            "https://documents.trendmicro.com/assets/txt/IOCs_Pawn_Storm_Campaign_Deploys_PRISMEX_Targets_Government_and_Critical_Infrastructure_Entities-nb92d9u.txt",
        ],
        "blogs": [
            "https://hunt.io/blog/operation-roundish-apt28-roundcube-exploitation",
            "https://lab52.io/blog/operation-macromaze-new-apt28-campaign-using-basic-tooling-and-legit-infrastructure/",
            "https://www.zscaler.com/blogs/security-research/apt28-leverages-cve-2026-21509-operation-neusploit",
            "https://www.sentinelone.com/labs/prompts-as-code-embedded-keys-the-hunt-for-llm-enabled-malware/",
            "https://lab52.io/blog/analyzing-notdoor-inside-apt28s-expanding-arsenal/",
            "https://blog.sekoia.io/double-tap-campaign-russia-nexus-apt-possibly-related-to-apt28-conducts-cyber-espionage-on-central-asia-and-kazakhstan-diplomatic-relations/",
        ],
        "otx_pulses": [],
        # --- Tier 1: GitHub sources ---
        "github_maltrail": {
            "url": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/apt_sofacy.txt",
        },
        "github_eset": [
            "https://raw.githubusercontent.com/eset/malware-ioc/master/sednit/samples.sha256",
        ],
    },
    "gamaredon": {
        "label": "Gamaredon / Iron Tilden (FSB Crimea)",
        "aliases": ["Aqua Blizzard", "Shuckworm", "Armageddon", "Primitive Bear", "UAC-0010"],
        "trendmicro_articles": [],
        "ioc_txt_direct": [],
        "blogs": [
            "https://blog.talosintelligence.com/gamaredon-apt-targets-ukrainian-agencies/",
            "https://www.welivesecurity.com/en/eset-research/gamaredon-x-turla-collab/",
            "https://unit42.paloaltonetworks.com/unit-42-title-gamaredon-group-toolset-evolution/",
        ],
        "pdfs": [
            "https://web-assets.esetstatic.com/wls/en/papers/white-papers/gamaredon-in-2024.pdf",
            "https://web-assets.esetstatic.com/wls/en/papers/white-papers/cyberespionage-gamaredon-way.pdf",
        ],
        "otx_pulses": ["632867cb6adb2944df19a4e8"],
        # --- Tier 1: GitHub sources ---
        "github_maltrail": {
            "url": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/apt_gamaredon.txt",
        },
        "github_eset": [
            "https://raw.githubusercontent.com/eset/malware-ioc/master/gamaredon/samples.sha256",
        ],
        "github_unit42": [
            "https://raw.githubusercontent.com/pan-unit42/iocs/master/Gamaredon/Gamaredon_IoCs_DEC2022.txt",
            "https://raw.githubusercontent.com/pan-unit42/iocs/master/Gamaredon/Gamaredon_IoCs_JAN2022.txt",
        ],
    },
    "earth_koshchei": {
        "label": "Earth Koshchei / APT29 / Midnight Blizzard (SVR)",
        "aliases": ["Cozy Bear", "Nobelium", "Iron Hemlock", "UNC2452", "BlueBravo"],
        "trendmicro_articles": [
            "https://www.trendmicro.com/en_us/research/24/l/earth-koshchei.html",
        ],
        "ioc_txt_direct": [
            "https://www.trendmicro.com/content/dam/trendmicro/global/en/research/24/l/earth-koshchei/IOClist-EarthKoshchei.txt",
        ],
        "blogs": [
            "https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/",
            "https://www.mandiant.com/resources/blog/apt29-wineloader-german-political-parties",
        ],
        "otx_pulses": [],
        # --- Tier 1: GitHub sources ---
        "github_maltrail": None,
        "github_eset": [
            "https://raw.githubusercontent.com/eset/malware-ioc/master/dukes/samples.sha256",
        ],
    },
    "sandworm": {
        "label": "Sandworm / Seashell Blizzard (GRU Unit 74455)",
        "aliases": ["APT44", "Iron Viking", "Voodoo Bear", "FROZENBARENTS", "Telebots", "UAC-0002"],
        "trendmicro_articles": [],
        "ioc_txt_direct": [],
        "blogs": [
            "https://blog.eclecticiq.com/sandworm-apt-targets-ukrainian-users-with-trojanized-microsoft-kms-activation-tools-in-cyber-espionage-campaigns",
            "https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q2-2025-q3-2025/",
        ],
        "otx_pulses": [
            "654ce91ef6c5736584839097",
            "602beffabc1975c22c394912",
        ],
        "static_iocs": {
            "ips": ["95.216.13.196", "103.94.157.5"],
            "domains": ["hostapp.be", "esetsmart.com", "esetremover.com"],
            "cves": ["CVE-2019-10149"],
        },
        # --- Tier 1: GitHub sources ---
        "github_maltrail": {
            "url": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/apt_sandworm.txt",
        },
        "github_eset": [
            "https://raw.githubusercontent.com/eset/malware-ioc/master/industroyer/samples.sha256",
            "https://raw.githubusercontent.com/eset/malware-ioc/master/telebots/samples.sha256",
        ],
    },
    "turla": {
        "label": "Turla / Iron Hunter / Secret Blizzard (FSB Center 16)",
        "aliases": ["Venomous Bear", "Snake", "Waterbug", "Krypton", "UAC-0003"],
        "trendmicro_articles": [
            "https://www.trendmicro.com/en_us/research/23/i/examining-the-activities-of-the-turla-group.html",
        ],
        "ioc_txt_direct": [
            "https://www.trendmicro.com/content/dam/trendmicro/global/en/research/23/i/examining-the-activities-of-the-turla-apt-group/ioc-examining-the-activities-of-the-turla-apt-group.txt",
        ],
        "blogs": [
            "https://www.microsoft.com/en-us/security/blog/2024/12/04/frequent-freeloader-part-i-secret-blizzard-compromising-storm-0156-infrastructure-for-espionage/",
            "https://www.microsoft.com/en-us/security/blog/2024/12/11/frequent-freeloader-part-ii-russian-actor-secret-blizzard-using-tools-of-other-groups-to-attack-ukraine/",
            "https://www.microsoft.com/en-us/security/blog/2025/07/31/frozen-in-transit-secret-blizzards-aitm-campaign-against-diplomats/",
        ],
        "otx_pulses": [],
        # --- Tier 1: GitHub sources ---
        "github_maltrail": {
            "url": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/apt_turla.txt",
        },
        "github_eset": [
            "https://raw.githubusercontent.com/eset/malware-ioc/master/turla/samples.sha256",
        ],
    },
    "callisto": {
        "label": "Callisto / Star Blizzard / COLDRIVER (FSB Center 18)",
        "aliases": ["Seaborgium", "ColdRiver", "TA446", "Blue Charlie", "TAG-53", "DANCING SALOME"],
        "trendmicro_articles": [],
        "ioc_txt_direct": [],
        "blogs": [
            "https://cloud.google.com/blog/topics/threat-intelligence/new-malware-russia-coldriver",
            "https://blog.google/threat-analysis-group/google-tag-coldriver-russian-phishing-malware/",
            "https://www.microsoft.com/en-us/security/blog/2025/01/16/new-star-blizzard-spear-phishing-campaign-targets-whatsapp-accounts/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a",
        ],
        "otx_pulses": [
            "65a975c11b1689cdd7554994",
            "678a74025a27014e1b2725ad",
            "65772e10ae5e362a5e0647ee",
        ],
        # --- Tier 1: GitHub sources ---
        "github_maltrail": {
            "url": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/apt_coldriver.txt",
        },
        "github_eset": [],
    },
}


# ═══════════════════════════════════════════════════════════════
#  HTTP CLIENT
# ═══════════════════════════════════════════════════════════════

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def get_session():
    """Returns a requests session with automatic retries."""
    if not HAS_REQUESTS:
        return None
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update(HEADERS)
    return s


SESSION = get_session()


def fetch_text(url: str, timeout: int = 20) -> str:
    """Fetches a URL and returns text. Handles BOM encoding (UTF-8/UTF-16)."""
    try:
        if HAS_REQUESTS:
            r = SESSION.get(url, timeout=timeout)
            r.raise_for_status()
            raw = r.content
        else:
            req = urllib.request.Request(url, headers=HEADERS)
            raw = urllib.request.urlopen(req, timeout=timeout).read()
        # BOM detection
        if raw[:3] == b'\xef\xbb\xbf':
            return raw[3:].decode("utf-8")
        if raw[:2] == b'\xff\xfe':
            return raw[2:].decode("utf-16-le")
        return raw.decode("utf-8", errors="replace")
    except Exception as e:
        log.warning(f"FAIL {url[:70]}: {e}")
        return ""


def fetch_bytes(url: str, timeout: int = 30) -> bytes:
    """Fetches a URL and returns raw bytes."""
    try:
        if HAS_REQUESTS:
            r = SESSION.get(url, timeout=timeout)
            r.raise_for_status()
            return r.content
        else:
            req = urllib.request.Request(url, headers=HEADERS)
            return urllib.request.urlopen(req, timeout=timeout).read()
    except Exception as e:
        log.warning(f"FAIL bytes {url[:70]}: {e}")
        return b""


def fetch_otx_pulse(pulse_id: str) -> dict:
    """Fetches an OTX AlienVault pulse and returns structured indicators."""
    url = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}"
    # OTX API requires authentication header
    otx_key = getattr(app_config, "otx_api_key", "")
    if otx_key:
        extra_headers = {"X-OTX-API-KEY": otx_key}
        try:
            if HAS_REQUESTS:
                r = SESSION.get(url, timeout=20, headers=extra_headers)
                r.raise_for_status()
                text = r.text
            else:
                req = urllib.request.Request(url, headers={**HEADERS, **extra_headers})
                text = urllib.request.urlopen(req, timeout=20).read().decode("utf-8")
        except Exception as e:
            log.warning(f"FAIL OTX {pulse_id}: {e}")
            text = ""
    else:
        log.warning(f"OTX API key not configured — skipping pulse {pulse_id}")
        text = ""
    if not text or '{' not in text:
        return {}
    try:
        data = json.loads(text)
        iocs = data.get("indicators", [])
        return {
            "name": data.get("name", pulse_id),
            "hashes":  [x["indicator"] for x in iocs if x["type"] == "FileHash-SHA256"],
            "ips":     [x["indicator"] for x in iocs if x["type"] == "IPv4"],
            "domains": [x["indicator"] for x in iocs if x["type"] in ("domain", "hostname")],
            "urls":    [x["indicator"] for x in iocs if x["type"] == "URL"],
            "emails":  [x["indicator"] for x in iocs if x["type"] == "email"],
            "cves":    [x["indicator"] for x in iocs if x["type"] == "CVE"],
        }
    except json.JSONDecodeError as e:
        log.warning(f"OTX parse error {pulse_id}: {e}")
        return {}


# ═══════════════════════════════════════════════════════════════
#  IOC PARSERS
# ═══════════════════════════════════════════════════════════════

def defang(text: str) -> str:
    """Reverses the defanging of IOCs."""
    return (text
            .replace("[.]", ".")
            .replace("[dot]", ".")
            .replace("[at]", "@")
            .replace("[@]", "@")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://"))


def is_valid_ip(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def is_valid_domain(d: str) -> bool:
    """Validates that a string looks like a real domain name."""
    d = d.strip().lower()
    if not d or d.startswith("/") or d.startswith(".") or d.startswith("-"):
        return False
    if "%" in d or " " in d or "\t" in d:
        return False
    if d.startswith("http://") or d.startswith("https://"):
        return False
    # Must have at least one dot and a valid TLD
    if "." not in d:
        return False
    parts = d.split(".")
    tld = parts[-1]
    if not re.match(r'^[a-z]{2,20}$', tld):
        return False
    # Each label: alphanumeric + hyphens, 1-63 chars
    for label in parts:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', label) and len(label) > 1:
            return False
    return True


def is_valid_email(e: str) -> bool:
    """Validates that a string looks like a real email address."""
    e = e.strip().lower()
    if " " in e or "\t" in e:
        return False
    if not re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', e):
        return False
    # Filter encoded unicode artifacts (u003e prefix)
    if e.startswith("u003e") or e.startswith("u003c"):
        return False
    return True


def extract_from_text(text: str) -> dict:
    """Extracts all types of IOCs from any text."""
    t = defang(text)

    hashes = sorted(set(h.lower() for h in re.findall(r'\b[a-fA-F0-9]{64}\b', t)))

    raw_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', t)
    ips = sorted(set(ip for ip in raw_ips if is_valid_ip(ip)))

    raw_emails = re.findall(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b', t)
    emails = sorted(set(e.lower() for e in raw_emails if is_valid_email(e)))

    cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', t)))

    # Suspect domains: subdomains of TLDs often abused
    domain_pat = r'\b[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.(?:ru|ua|be|cloud|site|online|xyz|top|info|live|icu|buzz|shop|space|click|link)\b'
    domains = sorted(set(d.lower() for d in re.findall(domain_pat, t) if is_valid_domain(d)))

    return {
        "hashes": hashes,
        "ips": ips,
        "emails": emails,
        "cves": cves,
        "domains": domains,
    }


def parse_trendmicro_ioc_txt(text: str) -> dict:
    """
    Parses a TrendMicro IOC file in defanged tabular format.
    Format: type \t value  (e.g.: file_hash_sha256 \t abc123...)
    """
    result: dict[str, list] = {
        "hashes": [], "ips": [], "domains": [], "urls": [], "emails": [], "cves": []
    }

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("-") or line.startswith("*"):
            continue

        parts = re.split(r'\s{2,}|\t', line, 1)
        if len(parts) < 2:
            if re.match(r'^[a-fA-F0-9]{64}$', line):
                result["hashes"].append(line.lower())
            elif re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', line) and is_valid_ip(line):
                result["ips"].append(line)
            continue

        ioc_type, value = parts[0].lower().strip(), defang(parts[1].strip())

        if "sha256" in ioc_type or "hash" in ioc_type:
            if re.match(r'^[a-fA-F0-9]{64}$', value):
                result["hashes"].append(value.lower())
        elif ioc_type in ("ip", "ip_address", "network_ip"):
            if is_valid_ip(value):
                result["ips"].append(value)
        elif "domain" in ioc_type or "network_domain" in ioc_type:
            if is_valid_domain(value):
                result["domains"].append(value.lower())
        elif "url" in ioc_type or "network_url" in ioc_type:
            if value.startswith("http://") or value.startswith("https://"):
                result["urls"].append(value)
            elif value.startswith("/") and len(value) > 3:
                result["urls"].append(value)  # URI path (C2 endpoint)
        elif "email" in ioc_type:
            if is_valid_email(value):
                result["emails"].append(value.lower())
        elif ioc_type.startswith("cve") or re.match(r'CVE-\d{4}', value):
            m = re.search(r'CVE-\d{4}-\d+', value, re.I)
            if m:
                result["cves"].append(m.group(0))

    return {k: sorted(set(v)) for k, v in result.items()}


def find_trendmicro_ioc_link(article_html: str) -> list[str]:
    """Extracts the IOC .txt link(s) from a TrendMicro research page."""
    patterns = [
        r'(https?://documents\.trendmicro\.com/assets/txt/[^\s"\'<>]+\.txt)',
        r'(https?://www\.trendmicro\.com/content/dam/[^\s"\'<>]*\.txt)',
        r'["\'](/content/dam/trendmicro[^\s"\'<>]+\.txt)["\']',
    ]
    found = []
    for p in patterns:
        for m in re.findall(p, article_html):
            url = m if m.startswith("http") else f"https://www.trendmicro.com{m}"
            found.append(url)
    return sorted(set(found))


def parse_pdf_iocs(pdf_bytes: bytes) -> dict:
    """Extracts IOCs from a PDF via pypdf."""
    if not HAS_PYPDF or not pdf_bytes:
        return {}
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        text = "\n".join(p.extract_text() or "" for p in reader.pages)
        return extract_from_text(text)
    except Exception as e:
        log.warning(f"PDF parse error: {e}")
        return {}


def parse_github_maltrail(url: str, line_start: int = 0, line_end: int = 0) -> dict:
    """Parses a maltrail APT file. Returns dict with ips and domains.
    If line_start/line_end are provided, extracts only that range (legacy mode).
    Otherwise parses the entire file (per-APT file mode)."""
    text = fetch_text(url)
    if not text:
        return {"ips": [], "domains": []}
    lines = text.split("\n")
    if line_start and line_end:
        lines = lines[line_start - 1:line_end]
    ips = []
    domains = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # maltrail format: one IOC per line (domain or IP), sometimes with comments
        value = line.split("#")[0].strip().split()[0] if line else ""
        if not value:
            continue
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value) and is_valid_ip(value):
            ips.append(value)
        elif "." in value and not value.startswith("http") and is_valid_domain(value):
            domains.append(value.lower())
    return {"ips": ips, "domains": domains}


def parse_github_eset(url: str) -> dict:
    """Parses an ESET malware-ioc GitHub raw file.
    Supports: samples.sha256, samples.sha1, domains.txt, ips.txt."""
    text = fetch_text(url)
    if not text:
        return {}
    result: dict[str, list] = {"hashes": [], "ips": [], "domains": []}
    url_lower = url.lower()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "sha256" in url_lower or "sha1" in url_lower:
            # Hash file: one hash per line
            if re.match(r'^[a-fA-F0-9]{64}$', line):
                result["hashes"].append(line.lower())
            elif re.match(r'^[a-fA-F0-9]{40}$', line):
                result["hashes"].append(line.lower())
        elif "domain" in url_lower:
            if "." in line and not line.startswith("http"):
                result["domains"].append(line.lower())
        elif "ip" in url_lower:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line) and is_valid_ip(line):
                result["ips"].append(line)
        else:
            # Generic: try to detect type
            iocs = extract_from_text(line)
            for k in result:
                result[k].extend(iocs.get(k, []))
    return {k: sorted(set(v)) for k, v in result.items() if v}


# ═══════════════════════════════════════════════════════════════
#  MAIN COLLECTOR
# ═══════════════════════════════════════════════════════════════

def collect_group(group_id: str, config: dict, safelist: Safelist) -> dict:
    """Collects all IOCs for an APT group, filtered by safelist."""
    log.info(f"\n{'='*60}")
    log.info(f"Collecting: {config['label']}")
    log.info(f"{'='*60}")

    result: dict[str, set] = {
        "hashes": set(), "ips": set(), "domains": set(),
        "urls": set(), "emails": set(), "cves": set(),
    }

    def merge(d: dict):
        for k in result:
            result[k].update(d.get(k, []))

    # 1. Direct IOC TXT files (TrendMicro)
    for url in config.get("ioc_txt_direct", []):
        log.info(f"  IOC TXT: {url[:70]}")
        text = fetch_text(url)
        if text:
            iocs = parse_trendmicro_ioc_txt(text)
            merge(iocs)
            log.info(f"    -> SHA256:{len(iocs['hashes'])} IPs:{len(iocs['ips'])} "
                     f"domains:{len(iocs['domains'])} emails:{len(iocs['emails'])}")

    # 2. TrendMicro articles (scrape IOC link)
    for url in config.get("trendmicro_articles", []):
        log.info(f"  TM Article: {url[:70]}")
        html = fetch_text(url)
        if not html:
            continue
        ioc_links = find_trendmicro_ioc_link(html)
        if ioc_links:
            for ioc_url in ioc_links:
                log.info(f"    IOC file found: {ioc_url}")
                ioc_text = fetch_text(ioc_url)
                if ioc_text:
                    iocs = parse_trendmicro_ioc_txt(ioc_text)
                    merge(iocs)
        else:
            iocs = extract_from_text(html)
            merge(iocs)

    # 3. Security blogs
    for url in config.get("blogs", []):
        log.info(f"  Blog: {url[:70]}")
        html = fetch_text(url)
        if html:
            iocs = extract_from_text(html)
            merge(iocs)
            log.info(f"    -> SHA256:{len(iocs['hashes'])} IPs:{len(iocs['ips'])}")

    # 4. PDFs
    for url in config.get("pdfs", []):
        if not HAS_PYPDF:
            log.warning("  pypdf not installed — PDFs skipped (pip install pypdf)")
            break
        log.info(f"  PDF: {url[:70]}")
        raw = fetch_bytes(url)
        if raw:
            iocs = parse_pdf_iocs(raw)
            merge(iocs)
            log.info(f"    -> SHA256:{len(iocs['hashes'])} IPs:{len(iocs['ips'])}")

    # 5. OTX Pulses
    for pulse_id in config.get("otx_pulses", []):
        log.info(f"  OTX Pulse: {pulse_id}")
        pulse = fetch_otx_pulse(pulse_id)
        if pulse:
            merge(pulse)
            log.info(f"    [{pulse.get('name','?')[:50]}]")
            log.info(f"    -> SHA256:{len(pulse['hashes'])} domains:{len(pulse['domains'])}")

    # 6. GitHub maltrail (per-APT file)
    if config.get("github_maltrail"):
        cfg = config["github_maltrail"]
        url = cfg["url"] if isinstance(cfg, dict) else cfg
        line_start = cfg.get("line_start", 0) if isinstance(cfg, dict) else 0
        line_end = cfg.get("line_end", 0) if isinstance(cfg, dict) else 0
        log.info(f"  maltrail: {url.split('/')[-1]}")
        parsed = parse_github_maltrail(url, line_start, line_end)
        result["ips"].update(parsed.get("ips", []))
        result["domains"].update(parsed.get("domains", []))
        log.info(f"    -> IPs:{len(parsed.get('ips',[]))} domains:{len(parsed.get('domains',[]))}")

    # 7. GitHub ESET malware-ioc
    for url in config.get("github_eset", []):
        log.info(f"  ESET: {url.split('/')[-1]}")
        iocs = parse_github_eset(url)
        if iocs:
            merge(iocs)
            stats = " ".join(f"{k}:{len(v)}" for k, v in iocs.items())
            log.info(f"    -> {stats}")

    # 8. GitHub Unit42 IOC files
    for url in config.get("github_unit42", []):
        log.info(f"  Unit42 IOC: {url[:70]}")
        text = fetch_text(url)
        if text:
            iocs = extract_from_text(text)
            merge(iocs)

    # 9. Static IOCs (hardcoded)
    if config.get("static_iocs"):
        static = config["static_iocs"]
        result["ips"].update(static.get("ips", []))
        result["domains"].update(static.get("domains", []))
        result["cves"].update(static.get("cves", []))
        log.info(f"  Static IOCs: {len(static.get('ips',[]))} IPs, "
                 f"{len(static.get('domains',[]))} domains")

    # ═══════════════════════════════════════════════════════
    # SAFELIST FILTERING
    # ═══════════════════════════════════════════════════════
    pre_filter = {k: len(v) for k, v in result.items()}

    result["ips"] = {
        ip for ip in result["ips"]
        if is_valid_ip(ip) and not safelist.is_safe_ip(ip)
    }
    result["domains"] = {
        d for d in result["domains"]
        if not safelist.is_safe_domain(d)
    }
    result["emails"] = {
        e for e in result["emails"]
        if not safelist.is_safe_email(e)
    }

    post_filter = {k: len(v) for k, v in result.items()}

    # Log filtered counts
    for k in ("ips", "domains", "emails"):
        diff = pre_filter.get(k, 0) - post_filter.get(k, 0)
        if diff > 0:
            log.info(f"  Safelist: {diff} {k} filtered")

    final = {k: sorted(v) for k, v in result.items()}
    log.info(f"\n  TOTAL {config['label'].split('/')[0].strip()}:")
    for k, v in final.items():
        if v:
            log.info(f"    {k}: {len(v)}")

    return final


# ═══════════════════════════════════════════════════════════════
#  EXPORT — Raw formats (txt/json)
# ═══════════════════════════════════════════════════════════════

def export_txt(group_id: str, config: dict, iocs: dict, output_dir: Path) -> Path:
    """Exports IOCs in structured APT Watch text format."""
    today = date.today().strftime("%Y%m%d")
    filename = f"aptwatch_{group_id}_iocs_{today}.txt"
    filepath = output_dir / filename

    lines = [
        f"## APT Watch — Export IOCs {config['label']}",
        f"## Aliases: {', '.join(config.get('aliases', []))}",
        f"## Generated: {date.today().isoformat()}",
        f"## Mode: {app_config.mode}",
        f"## Safelist: safelist.yaml applied",
        "## " + "=" * 70,
    ]

    sections = [
        ("cves",    "CVEs"),
        ("ips",     "C2 IPs"),
        ("domains", "C2 domains / phishing / credential harvesting"),
        ("emails",  "Operator emails"),
        ("urls",    "C2 URLs / exfiltration"),
        ("hashes",  "SHA256"),
    ]

    for key, label in sections:
        items = iocs.get(key, [])
        if not items:
            continue
        lines += ["", f"## {label} [{len(items)}]"]
        lines += [f"{item}" for item in items]

    lines += ["", "## SOURCES"]
    for url in (config.get("ioc_txt_direct", []) +
                config.get("trendmicro_articles", []) +
                config.get("blogs", []) +
                config.get("pdfs", [])):
        lines.append(f"# {url}")
    for pid in config.get("otx_pulses", []):
        lines.append(f"# OTX: https://otx.alienvault.com/pulse/{pid}")

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath


def export_json(group_id: str, config: dict, iocs: dict, output_dir: Path) -> Path:
    """Exports IOCs in JSON format."""
    today = date.today().strftime("%Y%m%d")
    filename = f"aptwatch_{group_id}_iocs_{today}.json"
    filepath = output_dir / filename

    data = {
        "group_id": group_id,
        "label": config["label"],
        "aliases": config.get("aliases", []),
        "generated": date.today().isoformat(),
        "mode": app_config.mode,
        "safelist_applied": True,
        "iocs": iocs,
        "stats": {k: len(v) for k, v in iocs.items() if v},
    }

    filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return filepath


# ═══════════════════════════════════════════════════════════════
#  ARTIFACT GENERATION — YAML submission + append files
# ═══════════════════════════════════════════════════════════════

MAX_IOCS_PER_TYPE = 500  # Server rejects submissions with >500 per IOC type


def normalize_ipv4(ip: str) -> str:
    """Strips leading zeros from IPv4 octets (e.g. 08.208.178.52 -> 8.208.178.52)."""
    try:
        return ".".join(str(int(o)) for o in ip.split("."))
    except (ValueError, AttributeError):
        return ip


def _build_source_fields(group_config: dict) -> tuple[str, str]:
    """Returns (source_url, source_name) for YAML header."""
    all_urls = (group_config.get("trendmicro_articles", []) +
                group_config.get("blogs", []) +
                group_config.get("ioc_txt_direct", []) +
                group_config.get("pdfs", []))
    for pid in group_config.get("otx_pulses", []):
        all_urls.append(f"https://otx.alienvault.com/pulse/{pid}")
    source_url = all_urls[0] if len(all_urls) == 1 else "Multiple"
    source_name = f"{group_config['label']} — Automated IOC Collection"
    return source_url, source_name


def generate_yaml_submission(group_id: str, group_config: dict, iocs: dict,
                              output_dir: Path, author: str = "collector") -> list[Path]:
    """Generates YAML community submission file(s) for a group.

    Splits into multiple files if any IOC type exceeds MAX_IOCS_PER_TYPE.
    Returns list of generated file paths.
    """
    today = date.today().isoformat()
    source_url, source_name = _build_source_fields(group_config)

    # Normalize IPs: strip leading zeros
    raw_ips = iocs.get("ips", [])
    clean_ips = sorted(set(normalize_ipv4(ip) for ip in raw_ips))

    # Prepare IOC buckets
    all_domains = sorted(set(iocs.get("domains", [])))
    all_emails = sorted(set(iocs.get("emails", [])))
    all_cves = sorted(set(iocs.get("cves", [])))
    all_hashes = sorted(set(iocs.get("hashes", [])))
    all_urls_ioc = sorted(set(iocs.get("urls", [])))

    # Calculate how many parts we need (based on largest IOC type)
    max_count = max(len(all_domains), len(clean_ips), len(all_hashes), 1)
    num_parts = (max_count + MAX_IOCS_PER_TYPE - 1) // MAX_IOCS_PER_TYPE

    aliases = group_config.get("aliases", [])
    apt_groups_list = [group_config["label"].split("/")[0].strip()] + aliases

    generated = []
    for part in range(num_parts):
        start = part * MAX_IOCS_PER_TYPE
        end = start + MAX_IOCS_PER_TYPE

        suffix = f"-part{part + 1}" if num_parts > 1 else ""
        filename = f"{group_id}-auto-{today}{suffix}.yaml"
        filepath = output_dir / filename

        lines = [
            f"# Auto-generated by aptwatch_ioc_collector.py",
            f"# Mode: {app_config.mode} | Date: {today}",
            f"# Safelist applied: safelist.yaml",
        ]
        if num_parts > 1:
            lines.append(f"# Part {part + 1}/{num_parts}")
        lines += [
            "",
            f"author: {author}",
            f"source: {source_url}",
            f'source_name: "{source_name}"',
            "",
            "apt_groups:",
        ]
        for ag in apt_groups_list:
            lines.append(f"  - {ag}")
        lines += [
            "",
            f"description: >",
            f"  Automated IOC collection for {group_config['label']}.",
            f"  Aliases: {', '.join(aliases)}.",
            f"  Sources: TrendMicro, OTX, OSINT blogs, GitHub threat feeds.",
            "",
        ]

        # IPs (first part only, usually <500)
        part_ips = clean_ips[start:end] if part == 0 or len(clean_ips) > MAX_IOCS_PER_TYPE else (clean_ips if part == 0 else [])
        if part == 0 and clean_ips:
            lines.append("ipv4:")
            for ip in clean_ips[:MAX_IOCS_PER_TYPE]:
                lines.append(f"  - {ip}")
            lines.append("")

        # Domains (split across parts)
        part_domains = all_domains[start:end]
        if part_domains:
            lines.append("domains:")
            for d in part_domains:
                lines.append(f"  - {d}")
            lines.append("")

        # Emails (first part only, usually <500)
        if part == 0 and all_emails:
            lines.append("emails:")
            for e in all_emails[:MAX_IOCS_PER_TYPE]:
                lines.append(f"  - {e}")
            lines.append("")

        # CVEs (first part only)
        if part == 0 and all_cves:
            lines.append("cves:")
            for c in all_cves:
                lines.append(f"  - {c}")
            lines.append("")

        # URLs (first part only)
        if part == 0 and all_urls_ioc:
            lines.append("urls:")
            for u in all_urls_ioc[:MAX_IOCS_PER_TYPE]:
                lines.append(f"  - {u}")
            lines.append("")

        # Hashes as comments (server does not accept 'hashes' field)
        part_hashes = all_hashes[start:end]
        if part_hashes:
            lines.append(f"# SHA256 hashes ({len(part_hashes)} in this file)")
            for h in part_hashes:
                lines.append(f"# {h}")
            lines.append("")

        filepath.write_text("\n".join(lines), encoding="utf-8")
        generated.append(filepath)

    return generated


def generate_append_files(all_results: dict, output_dir: Path) -> list[Path]:
    """Generates append files (ipv4, domains, emails, cves) for all groups."""
    today = date.today().isoformat()
    files = []

    # Aggregates all IOCs
    all_ips = set()
    all_domains = set()
    all_emails = set()
    all_cves = set()

    for group_id, iocs in all_results.items():
        label = GROUPS[group_id]["label"].split("/")[0].strip()
        for ip in iocs.get("ips", []):
            all_ips.add(f"{ip}  # {label}")
        for d in iocs.get("domains", []):
            all_domains.add(f"{d}  # {label}")
        for e in iocs.get("emails", []):
            all_emails.add(f"{e}  # {label}")
        for c in iocs.get("cves", []):
            all_cves.add(f"{c}  # {label}")

    header = f"# APT Watch IOC Collector — {today}\n# Mode: {app_config.mode}\n"

    if all_ips:
        p = output_dir / f"append_ipv4_{today}.txt"
        p.write_text(header + "\n".join(sorted(all_ips)) + "\n", encoding="utf-8")
        files.append(p)

    if all_domains:
        p = output_dir / f"append_domains_{today}.txt"
        p.write_text(header + "\n".join(sorted(all_domains)) + "\n", encoding="utf-8")
        files.append(p)

    if all_emails:
        p = output_dir / f"append_emails_{today}.txt"
        p.write_text(header + "\n".join(sorted(all_emails)) + "\n", encoding="utf-8")
        files.append(p)

    if all_cves:
        p = output_dir / f"append_cves_{today}.txt"
        p.write_text(header + "\n".join(sorted(all_cves)) + "\n", encoding="utf-8")
        files.append(p)

    return files


# ═══════════════════════════════════════════════════════════════
#  SERVER MODE — auto-import DB + git commit
# ═══════════════════════════════════════════════════════════════

def server_git_commit(paths: list[Path], message: str):
    """Git add + commit of generated files (server mode only)."""
    if not app_config.auto_git:
        return
    repo_dir = app_config.paths.repo
    try:
        for p in paths:
            subprocess.run(["git", "add", str(p)], cwd=str(repo_dir),
                           capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", message],
            cwd=str(repo_dir), capture_output=True, check=True
        )
        log.info(f"  Git commit: {message[:60]}")
    except subprocess.CalledProcessError as e:
        log.warning(f"  Git commit failed: {e.stderr.decode()[:100]}")


def server_append_iocs(append_files: list[Path]):
    """Appends IOCs to main files (server mode only)."""
    if not app_config.is_server:
        return
    iocs_dir = app_config.paths.iocs_dir
    mapping = {
        "append_ipv4_": "ipv4.txt",
        "append_domains_": "domains.txt",
        "append_emails_": "emails.txt",
        "append_cves_": "cves.txt",
    }
    for af in append_files:
        for prefix, target_name in mapping.items():
            if af.name.startswith(prefix):
                target = iocs_dir / target_name
                if target.exists():
                    # Read without comments
                    new_lines = [
                        l.split("#")[0].strip()
                        for l in af.read_text().splitlines()
                        if l.strip() and not l.startswith("#")
                    ]
                    with open(target, "a", encoding="utf-8") as f:
                        for line in new_lines:
                            f.write(line + "\n")
                    log.info(f"  Appended {len(new_lines)} lines to {target_name}")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="APT Watch IOC Collector — automated collection of Russian APT IOCs"
    )
    parser.add_argument(
        "--group", choices=list(GROUPS.keys()) + ["all"], default="all",
        help="APT group to process (default: all)"
    )
    parser.add_argument(
        "--output", default=None,
        help="Output folder (default: auto by mode)"
    )
    parser.add_argument(
        "--format", choices=["txt", "json", "both"], default="both",
        help="Raw export format (default: both)"
    )
    parser.add_argument(
        "--safelist", default=None,
        help="Path to safelist.yaml (default: safelist.yaml next to script)"
    )
    parser.add_argument(
        "--mode", choices=["local", "server"], default=None,
        help="Force mode (override config.ini)"
    )
    parser.add_argument(
        "--no-artefacts", action="store_true",
        help="Skip artifact generation (YAML, append files)"
    )
    parser.add_argument(
        "--no-git", action="store_true",
        help="Skip git commit even in server mode"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Collect and display without writing files"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Verbose mode"
    )
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Mode override
    if args.mode:
        app_config.mode = args.mode
        app_config.auto_git = (args.mode == "server")
        app_config.paths = type(app_config.paths)(args.mode, app_config.paths.project_root)

    if args.no_git:
        app_config.auto_git = False

    # Log config
    log.info(app_config.summary())

    # Load safelist
    safelist_path = Path(args.safelist) if args.safelist else SAFELIST_PATH
    safelist = Safelist(safelist_path)

    # Output directory
    if args.output:
        output_dir = Path(args.output)
        # Redirect artifacts into the custom output folder too
        app_config.paths.submissions = output_dir / "submissions"
        app_config.paths.iocs_dir = output_dir / "iocs"
    else:
        output_dir = app_config.paths.output
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    groups_to_process = GROUPS if args.group == "all" else {args.group: GROUPS[args.group]}

    # ═══════════════════════════════════════════════════════
    # PHASE 1: COLLECTION
    # ═══════════════════════════════════════════════════════
    all_results = {}
    for group_id, group_config in groups_to_process.items():
        iocs = collect_group(group_id, group_config, safelist)
        all_results[group_id] = iocs

    # ═══════════════════════════════════════════════════════
    # PHASE 2: RAW EXPORT (txt/json)
    # ═══════════════════════════════════════════════════════
    if not args.dry_run:
        for group_id, group_config in groups_to_process.items():
            iocs = all_results[group_id]
            if args.format in ("txt", "both"):
                path = export_txt(group_id, group_config, iocs, output_dir)
                log.info(f"  -> {path}")
            if args.format in ("json", "both"):
                path = export_json(group_id, group_config, iocs, output_dir)
                log.info(f"  -> {path}")

    # ═══════════════════════════════════════════════════════
    # PHASE 3: ARTIFACTS (YAML submissions + append files)
    # ═══════════════════════════════════════════════════════
    generated_files = []

    if not args.dry_run and not args.no_artefacts:
        submissions_dir = app_config.paths.submissions
        submissions_dir.mkdir(parents=True, exist_ok=True)

        for group_id, group_config in groups_to_process.items():
            iocs = all_results[group_id]
            # Skip if no IOCs
            total = sum(len(v) for v in iocs.values())
            if total == 0:
                continue
            yaml_paths = generate_yaml_submission(
                group_id, group_config, iocs, submissions_dir,
                author="collector-auto" if app_config.is_server else "collector-local"
            )
            generated_files.extend(yaml_paths)
            for yp in yaml_paths:
                log.info(f"  YAML: {yp.name}")

        # Append files
        iocs_dir = app_config.paths.iocs_dir
        iocs_dir.mkdir(parents=True, exist_ok=True)
        append_files = generate_append_files(all_results, iocs_dir)
        generated_files.extend(append_files)
        for af in append_files:
            log.info(f"  Append: {af.name}")

    # ═══════════════════════════════════════════════════════
    # PHASE 4: SERVER — auto-append + git commit
    # ═══════════════════════════════════════════════════════
    if app_config.is_server and not args.dry_run and not args.no_artefacts:
        # Auto-append IOCs to main blocklists
        server_append_iocs(append_files)

        # Git commit
        if app_config.auto_git and generated_files:
            today = date.today().isoformat()
            groups_str = ", ".join(
                GROUPS[g]["label"].split("/")[0].strip()
                for g in groups_to_process
            )
            server_git_commit(
                generated_files,
                f"[auto] IOC collector {today}: {groups_str}"
            )

    # ═══════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════
    print(f"\n{'='*60}")
    print(f"APT Watch IOC Collector — Mode: {app_config.mode.upper()}")
    print(f"{'='*60}")
    for gid, iocs in all_results.items():
        label = GROUPS[gid]["label"].split("/")[0].strip()
        stats = " | ".join(f"{k}:{len(v)}" for k, v in iocs.items() if v)
        print(f"  {label:<25} {stats}")

    if not args.dry_run:
        print(f"\nExports: {output_dir.resolve()}")
        if generated_files:
            print(f"Artifacts: {len(generated_files)} files generated")
            if app_config.is_local:
                print(f"\nNext step (contributor):")
                print(f"  1. Check YAMLs in {app_config.paths.submissions}")
                print(f"  2. git add + git commit + git push (or PR)")
            elif app_config.is_server:
                print(f"\nServer: IOCs appended + git commit done.")
    else:
        print(f"\n[DRY RUN] No files written.")


if __name__ == "__main__":
    main()
