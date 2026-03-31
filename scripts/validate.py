#!/usr/bin/env python3
"""
OSINT API Validation for Russian APT IOCs
Validates IPs against multiple sources: Shodan, AbuseIPDB, VirusTotal, AlienVault OTX,
DShield/SANS ISC, abuse.ch ThreatFox, FireHOL blocklists, and Steven Black hosts.
Smart queuing: prioritizes unvalidated IOCs, skips recently checked ones.
All APIs are optional — runs whichever keys are available.

Usage:
    python validate.py queue [N]              # Build queue of N unvalidated IPs
    python validate.py run shodan [N]         # Validate N IPs via Shodan InternetDB
    python validate.py run abuseipdb [N]      # Validate N IPs via AbuseIPDB
    python validate.py run virustotal [N]     # Validate N IPs via VirusTotal
    python validate.py run otx [N]            # Validate N IPs via AlienVault OTX
    python validate.py run censys [N]         # Validate N IPs via Censys
    python validate.py run dshield [N]        # Validate N IPs via DShield/SANS ISC
    python validate.py run threatfox [N]      # Validate N IPs via abuse.ch ThreatFox
    python validate.py run firehol [N]        # Check N IPs against FireHOL blocklists
    python validate.py run stevenblack [N]    # Cross-ref N IPs against Steven Black hosts
    python validate.py run all [N]            # All sources sequentially
    python validate.py check <IP>             # Single IP, all available sources
    python validate.py auto                   # Scheduled run (auto batch sizes per API limits)
    python validate.py status                 # Queue/validation stats
    python validate.py log [N]               # Show last N transaction log entries (default: 30)
    python validate.py purge-log [days]      # Delete transaction log entries older than N days
    python validate.py sync                  # Sync validation_status from enrichment counts
    python validate.py flush                 # Flush completed queue entries to make room

API Keys (env vars, all optional):
    OTX_API_KEY      - AlienVault OTX key (free: ~10,000/day)
    ABUSEIPDB_KEY    - AbuseIPDB API key (free: 1,000/day)
    VIRUSTOTAL_KEY   - VirusTotal API key (free: 500/day, 4/min)
    CENSYS_API_TOKEN - Censys Personal Access Token (free: 100 credits total, use sparingly)
    Shodan InternetDB, DShield, ThreatFox, FireHOL, Steven Black require NO key.

Scheduling (Windows Task Scheduler):
    Use validate_continuous.bat — loops every 15 min with autonomous daily limits.
    See README.md for setup instructions.
"""

import sqlite3
import json
import sys
import os
import time
import glob as globmod
import urllib.request
import urllib.error
import urllib.parse
import configparser
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DB_PATH = Path(__file__).parent.parent / "database" / "apt_intel.db"
LOG_DIR = Path(__file__).parent.parent / "database" / "logs"
LOG_PATH = LOG_DIR / "validate.log"
CONFIG_PATH = PROJECT_ROOT / "config.ini"

# Max log file size (5 MB) and number of rotated files to keep
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_KEEP_COUNT = 5

# Load config
_cfg = configparser.ConfigParser()
if CONFIG_PATH.exists():
    _cfg.read(str(CONFIG_PATH))

def _cfg_int(section, key, default):
    try:
        return _cfg.getint(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
        return default

# Rate limits per source (seconds between requests)
RATE_LIMITS = {
    "shodan": 1.5,       # 1 req/sec official + safety margin
    "abuseipdb": 1.5,    # 1000/day, be safe
    "virustotal": 20.0,  # 4/min = 15s; use 20s for safe margin
    "otx": 0.5,          # Generous limit (~10k/day)
    "censys": 3.0,       # Conservative — 100 credits total on free tier
    "dshield": 1.0,      # No key, be polite
    "threatfox": 1.0,    # No key, POST API
    "firehol": 0.01,     # Local lookup — no network call per IP
    "stevenblack": 0.01, # Local lookup — no network call per IP
    "c2tracker": 0.01,   # Local lookup — cached feed
    "tweetfeed": 0.01,   # Local lookup — cached feed
    "ipsum": 0.01,       # Local lookup — cached feed
    "emerging_threats": 0.01,  # Local lookup — cached feed
}

# Max retries on rate-limit (429) before giving up on a batch
RATE_LIMIT_MAX_RETRIES = 3

# Daily limits for auto-scheduling — from config or defaults
DAILY_LIMITS = {
    "shodan": _cfg_int("validation", "shodan_daily", 2000),
    "abuseipdb": _cfg_int("validation", "abuseipdb_daily", 1000),
    "virustotal": _cfg_int("validation", "virustotal_daily", 500),
    "otx": _cfg_int("validation", "otx_daily", 2000),
    "censys": _cfg_int("validation", "censys_daily", 10),
    "dshield": _cfg_int("validation", "dshield_daily", 5000),
    "threatfox": _cfg_int("validation", "threatfox_daily", 5000),
    "firehol": _cfg_int("validation", "firehol_daily", 99999),
    "stevenblack": _cfg_int("validation", "stevenblack_daily", 99999),
    "c2tracker": _cfg_int("validation", "c2tracker_daily", 99999),
    "tweetfeed": _cfg_int("validation", "tweetfeed_daily", 99999),
    "ipsum": _cfg_int("validation", "ipsum_daily", 99999),
    "emerging_threats": _cfg_int("validation", "emerging_threats_daily", 99999),
}
RUNS_PER_DAY = _cfg_int("validation", "runs_per_day", 4)

# Sources split into API-based and local (offline) categories
API_SOURCES = ["shodan", "otx", "abuseipdb", "virustotal", "censys", "dshield", "threatfox"]
LOCAL_SOURCES = ["firehol", "stevenblack", "c2tracker", "tweetfeed", "ipsum", "emerging_threats"]
ALL_SOURCES = API_SOURCES + LOCAL_SOURCES
VALIDATED_THRESHOLD = _cfg_int("validation", "validated_threshold", 3)

# Cache directory for downloaded blocklists (FireHOL, Steven Black)
CACHE_DIR = PROJECT_ROOT / "database" / "cache"
CACHE_MAX_AGE_HOURS = _cfg_int("validation", "blocklist_cache_hours", 24)


def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    # Transaction log table — audit trail of every DB write
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transaction_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            ip TEXT,
            source TEXT,
            status TEXT,
            detail TEXT,
            run_id TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_txlog_ts ON transaction_log(timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_txlog_run ON transaction_log(run_id)
    """)
    # Daily API usage tracking — autonomous limit enforcement
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_daily_usage (
            source TEXT NOT NULL,
            date TEXT NOT NULL,
            requests INTEGER DEFAULT 0,
            PRIMARY KEY (source, date)
        )
    """)
    return conn


# Current run ID — set once per auto/batch run for grouping
_run_id = datetime.now().strftime("%Y%m%d_%H%M%S")


def get_daily_usage(conn, source):
    """Get the number of API requests made today for a source."""
    today = datetime.now().strftime("%Y-%m-%d")
    row = conn.execute(
        "SELECT requests FROM api_daily_usage WHERE source=? AND date=?",
        (source, today)).fetchone()
    return row["requests"] if row else 0


def increment_daily_usage(conn, source, count=1):
    """Increment the daily API usage counter for a source."""
    today = datetime.now().strftime("%Y-%m-%d")
    conn.execute("""
        INSERT INTO api_daily_usage (source, date, requests)
        VALUES (?, ?, ?)
        ON CONFLICT(source, date) DO UPDATE SET requests = requests + ?
    """, (source, today, count, count))


def get_daily_remaining(conn, source):
    """Get how many API calls are left today for a source."""
    limit = DAILY_LIMITS.get(source, 0)
    if limit == 0:
        return 999999  # No limit configured = unlimited
    used = get_daily_usage(conn, source)
    return max(0, limit - used)


def txlog(conn, action, ip=None, source=None, status="ok", detail=None):
    """Write an entry to the transaction_log table."""
    try:
        conn.execute("""
            INSERT INTO transaction_log (timestamp, action, ip, source, status, detail, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), action, ip, source, status, str(detail)[:1000] if detail else None, _run_id))
    except Exception:
        pass  # Never let logging break the actual work


def _rotate_log():
    """Rotate validate.log if it exceeds LOG_MAX_BYTES."""
    try:
        if not LOG_PATH.exists():
            return
        if LOG_PATH.stat().st_size < LOG_MAX_BYTES:
            return
        # Shift existing rotated files: .4→.5, .3→.4, etc.
        for i in range(LOG_KEEP_COUNT - 1, 0, -1):
            src = LOG_DIR / ("validate.log.%d" % i)
            dst = LOG_DIR / ("validate.log.%d" % (i + 1))
            if src.exists():
                src.rename(dst)
        # Current → .1
        LOG_PATH.rename(LOG_DIR / "validate.log.1")
        # Delete oldest if over limit
        oldest = LOG_DIR / ("validate.log.%d" % (LOG_KEEP_COUNT + 1))
        if oldest.exists():
            oldest.unlink()
    except Exception:
        pass


def log(msg):
    """Log to both stdout and log file (with rotation)."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    print(line)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        _rotate_log()
        with open(str(LOG_PATH), "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def api_get(url, headers=None, timeout=15):
    """GET request with error handling."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "APT-Intel-Validator/1.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "not_found", "code": 404}
        if e.code == 429:
            return {"error": "rate_limited", "code": 429}
        return {"error": str(e), "code": e.code}
    except urllib.error.URLError as e:
        return {"error": str(e.reason)}
    except Exception as e:
        return {"error": str(e)}


def _cfg_str(section, key, default=""):
    """Read string from config, fallback to default."""
    try:
        val = _cfg.get(section, key).strip()
        return val if val else default
    except (configparser.NoSectionError, configparser.NoOptionError):
        return default


def get_mode():
    """Get operating mode: 'local' (config.ini keys) or 'github' (env vars only)."""
    return _cfg_str("general", "mode", "local").lower()


def get_api_keys():
    """Load API keys based on mode.
       local  → config.ini values, env vars override if set
       github → environment variables only
    """
    mode = get_mode()

    if mode == "github":
        # GitHub Actions: keys come exclusively from env vars (secrets)
        return {
            "otx": os.environ.get("OTX_API_KEY", ""),
            "abuseipdb": os.environ.get("ABUSEIPDB_KEY", ""),
            "virustotal": os.environ.get("VIRUSTOTAL_KEY", ""),
            "censys": os.environ.get("CENSYS_API_TOKEN", ""),
        }
    else:
        # Local: config.ini first, env vars override
        return {
            "otx": os.environ.get("OTX_API_KEY", "") or _cfg_str("api_keys", "otx_api_key"),
            "abuseipdb": os.environ.get("ABUSEIPDB_KEY", "") or _cfg_str("api_keys", "abuseipdb_key"),
            "virustotal": os.environ.get("VIRUSTOTAL_KEY", "") or _cfg_str("api_keys", "virustotal_key"),
            "censys": os.environ.get("CENSYS_API_TOKEN", "") or _cfg_str("api_keys", "censys_api_token"),
        }


# =============================================================
# API INTEGRATIONS
# =============================================================

def validate_shodan(ip, **_):
    """Query Shodan InternetDB (free, no key)."""
    url = "https://internetdb.shodan.io/%s" % ip
    data = api_get(url)
    if "error" in data:
        if data.get("code") == 404:
            return {"ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": [], "not_indexed": True}, None
        return None, data.get("error", "unknown")
    return {
        "ports": data.get("ports", []),
        "vulns": data.get("vulns", []),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "cpes": data.get("cpes", []),
    }, None


def validate_abuseipdb(ip, api_key="", **_):
    """Query AbuseIPDB (free: 1000 checks/day)."""
    if not api_key:
        return None, "no_api_key"
    url = "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose" % ip
    headers = {"Key": api_key, "Accept": "application/json"}
    data = api_get(url, headers=headers)
    if "error" in data:
        return None, data.get("error", "unknown")
    d = data.get("data", {})
    return {
        "abuse_confidence": d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
        "is_public": d.get("isPublic", False),
        "is_tor": d.get("isTor", False),
        "country": d.get("countryCode", ""),
        "isp": d.get("isp", ""),
        "domain": d.get("domain", ""),
        "usage_type": d.get("usageType", ""),
        "last_reported": d.get("lastReportedAt", ""),
        "categories": list(set(
            cat for r in d.get("reports", []) for cat in r.get("categories", [])
        )),
    }, None


def validate_virustotal(ip, api_key="", **_):
    """Query VirusTotal (free: 500/day, 4 req/min)."""
    if not api_key:
        return None, "no_api_key"
    url = "https://www.virustotal.com/api/v3/ip_addresses/%s" % ip
    headers = {"x-apikey": api_key}
    data = api_get(url, headers=headers)
    if "error" in data:
        return None, data.get("error", "unknown")
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", ""),
        "as_owner": attrs.get("as_owner", ""),
        "asn": attrs.get("asn", 0),
        "network": attrs.get("network", ""),
        "last_analysis_date": attrs.get("last_analysis_date", ""),
    }, None


def validate_otx(ip, api_key="", **_):
    """Query AlienVault OTX (free: ~10,000/day)."""
    if not api_key:
        return None, "no_api_key"

    headers = {"X-OTX-API-KEY": api_key}

    # General info
    url = "https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general" % ip
    data = api_get(url, headers=headers)
    if "error" in data:
        return None, data.get("error", "unknown")

    result = {
        "pulse_count": data.get("pulse_info", {}).get("count", 0),
        "reputation": data.get("reputation", 0),
        "country": data.get("country_name", ""),
        "country_code": data.get("country_code", ""),
        "city": data.get("city", ""),
        "asn": data.get("asn", ""),
        "indicator": data.get("indicator", ip),
        "tags": [],
        "pulses": [],
        "malware_count": 0,
        "passive_dns_count": 0,
    }

    # Extract pulse names and tags
    pulses = data.get("pulse_info", {}).get("pulses", [])
    for p in pulses[:20]:  # Limit to avoid huge data
        result["pulses"].append(p.get("name", ""))
        result["tags"].extend(p.get("tags", []))
    result["tags"] = list(set(result["tags"]))[:50]

    # Malware data (separate endpoint)
    time.sleep(0.3)
    url2 = "https://otx.alienvault.com/api/v1/indicators/IPv4/%s/malware" % ip
    mal_data = api_get(url2, headers=headers)
    if "error" not in mal_data:
        result["malware_count"] = mal_data.get("count", 0)
        result["malware_samples"] = [
            m.get("hash", "") for m in mal_data.get("data", [])[:10]
        ]

    # Passive DNS (separate endpoint)
    time.sleep(0.3)
    url3 = "https://otx.alienvault.com/api/v1/indicators/IPv4/%s/passive_dns" % ip
    dns_data = api_get(url3, headers=headers)
    if "error" not in dns_data:
        result["passive_dns_count"] = dns_data.get("count", 0)
        result["passive_dns"] = [
            d.get("hostname", "") for d in dns_data.get("passive_dns", [])[:20]
        ]

    return result, None


def validate_censys(ip, api_key="", **_):
    """Query Censys Search API (free: 100 credits total, use sparingly)."""
    mode = get_mode()
    if mode == "github":
        token = os.environ.get("CENSYS_API_TOKEN", "")
    else:
        token = os.environ.get("CENSYS_API_TOKEN", "") or _cfg_str("api_keys", "censys_api_token")
    if not token:
        return None, "no_api_key"

    # Censys Platform API v3 — Bearer token (Personal Access Token)
    url = "https://api.platform.censys.io/v3/global/asset/host/%s" % ip
    headers = {
        "Authorization": "Bearer %s" % token,
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
    }

    data = api_get(url, headers=headers)
    if "error" in data:
        return None, data.get("error", "unknown")

    # v3 response: data → result → resource
    result_data = data.get("result", {}).get("resource", data.get("result", data))
    services = result_data.get("services", [])

    return {
        "ports": [s.get("port", 0) for s in services],
        "services": ["%s/%s" % (s.get("port", ""), s.get("protocol", s.get("service_name", ""))) for s in services],
        "os": result_data.get("operating_system", {}).get("product", ""),
        "os_version": result_data.get("operating_system", {}).get("version", ""),
        "asn": result_data.get("autonomous_system", {}).get("asn", 0),
        "as_name": result_data.get("autonomous_system", {}).get("name", ""),
        "country": result_data.get("location", {}).get("country_code", ""),
        "city": result_data.get("location", {}).get("city", ""),
        "last_updated": result_data.get("last_updated_at", ""),
        "labels": result_data.get("labels", []),
    }, None


# =============================================================
# NEW OSINT SOURCES: DShield, ThreatFox, FireHOL, Steven Black
# =============================================================

def validate_dshield(ip, **_):
    """Query DShield / SANS ISC API (free, no key).
    Returns attack count, threat score, and date range.
    """
    url = "https://isc.sans.edu/api/ip/%s?json" % ip
    headers = {"User-Agent": "APT-Intel-Validator/1.0"}
    data = api_get(url, headers=headers, timeout=20)
    if "error" in data:
        return None, data.get("error", "unknown")
    # DShield wraps response in an "ip" key
    info = data.get("ip", data) if isinstance(data, dict) else data
    if isinstance(info, list) and len(info) > 0:
        info = info[0]
    if not isinstance(info, dict):
        return None, "unexpected_response"
    return {
        "count": int(info.get("count", 0) or 0),
        "attacks": int(info.get("attacks", 0) or 0),
        "maxdate": info.get("maxdate", ""),
        "mindate": info.get("mindate", ""),
        "updated": info.get("updated", ""),
        "comment": info.get("comment", ""),
        "asabusecontact": info.get("asabusecontact", ""),
        "as": int(info.get("as", 0) or 0),
        "asname": info.get("asname", ""),
        "ascountry": info.get("ascountry", ""),
        "assource": info.get("assource", ""),
        "network": info.get("network", ""),
        "threatfeeds": info.get("threatfeeds", {}),
    }, None


_threatfox_cache = {"iocs": {}, "loaded_at": None}
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
THREATFOX_IOC_URL = "https://threatfox.abuse.ch/export/json/recent/"


def _load_threatfox_iocs():
    """Download ThreatFox recent IOCs + Feodo Tracker into an IP lookup dict.
    Uses local cache refreshed every CACHE_MAX_AGE_HOURS.
    """
    global _threatfox_cache
    if not _cache_is_stale(_threatfox_cache["loaded_at"]):
        return _threatfox_cache["iocs"]

    log("Loading abuse.ch threat intelligence...")
    iocs = {}  # ip -> list of match dicts
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # 1) Feodo Tracker (C2 botnet IPs)
    feodo_cache = CACHE_DIR / "feodo_ipblocklist.json"
    if not feodo_cache.exists() or _cache_is_stale(
            datetime.fromtimestamp(feodo_cache.stat().st_mtime) if feodo_cache.exists() else None):
        log("  Downloading Feodo Tracker blocklist...")
        _download_file(FEODO_URL, feodo_cache)

    if feodo_cache.exists():
        try:
            with open(str(feodo_cache), "r") as f:
                feodo_data = json.load(f)
            if isinstance(feodo_data, list):
                for entry in feodo_data:
                    ip = entry.get("ip_address", "")
                    if ip:
                        iocs.setdefault(ip, []).append({
                            "source": "feodo_tracker",
                            "malware": entry.get("malware", ""),
                            "port": entry.get("port", 0),
                            "status": entry.get("status", ""),
                            "first_seen": entry.get("first_seen", ""),
                            "last_online": entry.get("last_online", ""),
                            "as_name": entry.get("as_name", ""),
                            "country": entry.get("country", ""),
                        })
            log("  Feodo Tracker: %d C2 IPs loaded" % len([k for k, v in iocs.items()
                                                            if any(e["source"] == "feodo_tracker" for e in v)]))
        except Exception as e:
            log("  Error loading Feodo data: %s" % e)

    # 2) ThreatFox recent IOCs (try to download, may fail with 401)
    tf_cache = CACHE_DIR / "threatfox_recent.json"
    if not tf_cache.exists() or _cache_is_stale(
            datetime.fromtimestamp(tf_cache.stat().st_mtime) if tf_cache.exists() else None):
        log("  Downloading ThreatFox recent IOCs...")
        _download_file(THREATFOX_IOC_URL, tf_cache)

    if tf_cache.exists():
        try:
            with open(str(tf_cache), "r") as f:
                tf_data = json.load(f)
            # ThreatFox export format: {"data": {"<id>": {...}, ...}} or list
            if isinstance(tf_data, dict):
                entries = tf_data.get("data", tf_data)
                if isinstance(entries, dict):
                    entries = list(entries.values())
            else:
                entries = tf_data if isinstance(tf_data, list) else []

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                ioc_val = entry.get("ioc", "")
                # ThreatFox IOCs can be "ip:port" format
                ip = ioc_val.split(":")[0] if ":" in ioc_val else ioc_val
                # Only include IPv4-looking IOCs
                if ip and ip.count(".") == 3:
                    iocs.setdefault(ip, []).append({
                        "source": "threatfox",
                        "malware": entry.get("malware_printable", ""),
                        "threat_type": entry.get("threat_type", ""),
                        "confidence": entry.get("confidence_level", 0),
                        "tags": entry.get("tags", []),
                        "first_seen": entry.get("first_seen_utc", ""),
                        "reporter": entry.get("reporter", ""),
                    })
            log("  ThreatFox: %d IOC IPs loaded" % len([k for k, v in iocs.items()
                                                         if any(e["source"] == "threatfox" for e in v)]))
        except Exception as e:
            log("  Error loading ThreatFox data: %s" % e)

    _threatfox_cache["iocs"] = iocs
    _threatfox_cache["loaded_at"] = datetime.now()
    log("  abuse.ch total: %d unique IPs in threat database" % len(iocs))
    return iocs


def validate_threatfox(ip, **_):
    """Check IP against abuse.ch ThreatFox + Feodo Tracker (free, no key).
    Downloads blocklists once and caches locally.
    Returns malware associations and IOC details.
    """
    iocs = _load_threatfox_iocs()
    if not iocs:
        return None, "threat_data_unavailable"

    matches = iocs.get(ip, [])
    if not matches:
        return {"matched": False, "ioc_count": 0, "malware": [], "tags": []}, None

    malware_names = list(set(m.get("malware", "") for m in matches if m.get("malware")))
    tags = list(set(t for m in matches for t in (m.get("tags") or []) if isinstance(m.get("tags"), list)))
    threat_types = list(set(m.get("threat_type", "") for m in matches if m.get("threat_type")))
    sources = list(set(m.get("source", "") for m in matches))

    return {
        "matched": True,
        "ioc_count": len(matches),
        "malware": malware_names[:20],
        "tags": tags[:30],
        "threat_types": threat_types,
        "max_confidence": max((m.get("confidence", 0) for m in matches), default=0),
        "first_seen": min((m.get("first_seen", "") for m in matches if m.get("first_seen")), default=""),
        "sources": sources,
    }, None


# ---------- OFFLINE / BLOCKLIST SOURCES ----------

# In-memory caches (loaded once per process, refreshed when stale)
_firehol_cache = {"nets": set(), "loaded_at": None}
_stevenblack_cache = {"domains": set(), "loaded_at": None}

FIREHOL_LISTS = [
    "firehol_level1",  # Most aggressive attacks
    "firehol_level2",  # Known attackers
    "firehol_level3",  # Mass scanners + known threats
    "firehol_abusers_30d",  # Recent abusers
]
STEVENBLACK_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"


def _cache_is_stale(loaded_at):
    """Check if a cached blocklist needs refreshing."""
    if loaded_at is None:
        return True
    age = (datetime.now() - loaded_at).total_seconds() / 3600
    return age > CACHE_MAX_AGE_HOURS


def _download_file(url, dest_path, timeout=60):
    """Download a file to disk. Returns True on success."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "APT-Intel-Validator/1.0")
        resp = urllib.request.urlopen(req, timeout=timeout)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(dest_path), "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
        return True
    except Exception as e:
        log("  Download error (%s): %s" % (url, e))
        return False


def _load_firehol_blocklists():
    """Download and parse FireHOL blocklists into a set of ipaddress networks."""
    global _firehol_cache
    if not _cache_is_stale(_firehol_cache["loaded_at"]):
        return _firehol_cache["nets"]

    log("Loading FireHOL blocklists...")
    nets = set()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    for listname in FIREHOL_LISTS:
        cache_file = CACHE_DIR / ("%s.netset" % listname)
        url = "https://iplists.firehol.org/files/%s.netset" % listname

        # Download if missing or stale
        if not cache_file.exists() or _cache_is_stale(
                datetime.fromtimestamp(cache_file.stat().st_mtime) if cache_file.exists() else None):
            log("  Downloading %s..." % listname)
            if not _download_file(url, cache_file):
                # Try to use existing cache
                if not cache_file.exists():
                    continue

        # Parse the netset file
        try:
            with open(str(cache_file), "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        nets.add(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        continue
            log("  %s: %d entries" % (listname, len(nets)))
        except Exception as e:
            log("  Error parsing %s: %s" % (listname, e))

    _firehol_cache["nets"] = nets
    _firehol_cache["loaded_at"] = datetime.now()
    log("  FireHOL total: %d unique networks loaded" % len(nets))
    return nets


def _load_stevenblack_hosts():
    """Download and parse Steven Black unified hosts file into a set of domains."""
    global _stevenblack_cache
    if not _cache_is_stale(_stevenblack_cache["loaded_at"]):
        return _stevenblack_cache["domains"]

    log("Loading Steven Black hosts file...")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / "stevenblack_hosts.txt"

    # Download if missing or stale
    if not cache_file.exists() or _cache_is_stale(
            datetime.fromtimestamp(cache_file.stat().st_mtime) if cache_file.exists() else None):
        log("  Downloading Steven Black unified hosts...")
        if not _download_file(STEVENBLACK_URL, cache_file):
            if not cache_file.exists():
                return set()

    # Parse the hosts file
    domains = set()
    try:
        with open(str(cache_file), "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    domain = parts[1].lower().strip()
                    if domain and domain not in ("localhost", "localhost.localdomain",
                                                  "local", "broadcasthost", "ip6-localhost",
                                                  "ip6-loopback", "ip6-localnet",
                                                  "ip6-mcastprefix", "ip6-allnodes",
                                                  "ip6-allrouters", "ip6-allhosts"):
                        domains.add(domain)
    except Exception as e:
        log("  Error parsing Steven Black hosts: %s" % e)

    _stevenblack_cache["domains"] = domains
    _stevenblack_cache["loaded_at"] = datetime.now()
    log("  Steven Black: %d blocked domains loaded" % len(domains))
    return domains


def validate_firehol(ip, **_):
    """Check IP against FireHOL blocklists (offline, no API key).
    Downloads lists once and caches locally. Returns matched list names.
    """
    nets = _load_firehol_blocklists()
    if not nets:
        return None, "blocklists_unavailable"

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, "invalid_ip"

    matched_lists = []
    for net in nets:
        if addr in net:
            matched_lists.append(str(net))

    return {
        "listed": len(matched_lists) > 0,
        "matched_networks": matched_lists[:50],
        "match_count": len(matched_lists),
        "lists_checked": len(FIREHOL_LISTS),
        "total_networks": len(nets),
    }, None


def validate_stevenblack(ip, **_):
    """Cross-reference IP's reverse DNS / known hostnames against Steven Black hosts.
    Checks enrichment_results for any hostnames associated with this IP, then
    looks them up in the Steven Black malware/adware domain list.
    """
    domains = _load_stevenblack_hosts()
    if not domains:
        return None, "hosts_list_unavailable"

    # Gather all known hostnames for this IP from enrichment_results
    conn = get_db()
    hostnames = set()

    # From Shodan — hostnames in raw_data
    rows = conn.execute(
        "SELECT raw_data FROM enrichment_results WHERE indicator=? AND source IN ('shodan','otx','censys')",
        (ip,)).fetchall()
    for row in rows:
        try:
            data = json.loads(row["raw_data"] or "{}")
            for key in ("hostnames", "passive_dns"):
                for h in data.get(key, []):
                    if h and isinstance(h, str):
                        hostnames.add(h.lower().strip())
        except (json.JSONDecodeError, TypeError):
            pass
    conn.close()

    # Check each hostname against Steven Black list
    matched = []
    for hostname in hostnames:
        if hostname in domains:
            matched.append(hostname)
        # Also check parent domains (e.g., sub.malware.com → malware.com)
        parts = hostname.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in domains:
                matched.append("%s (via %s)" % (hostname, parent))
                break

    return {
        "hostnames_checked": list(hostnames)[:50],
        "hostnames_count": len(hostnames),
        "matched_domains": matched[:30],
        "match_count": len(matched),
        "blocklist_size": len(domains),
    }, None


# Dispatch table for API calls
from osint_feeds import (
    validate_c2tracker, validate_tweetfeed,
    validate_ipsum, validate_emerging_threats,
)

API_DISPATCH = {
    "shodan": validate_shodan,
    "abuseipdb": validate_abuseipdb,
    "virustotal": validate_virustotal,
    "otx": validate_otx,
    "censys": validate_censys,
    "dshield": validate_dshield,
    "threatfox": validate_threatfox,
    "firehol": validate_firehol,
    "stevenblack": validate_stevenblack,
    "c2tracker": validate_c2tracker,
    "tweetfeed": validate_tweetfeed,
    "ipsum": validate_ipsum,
    "emerging_threats": validate_emerging_threats,
}

# Which sources need API keys (shodan, dshield, threatfox, firehol, stevenblack are free)
NEEDS_KEY = {"abuseipdb", "virustotal", "otx", "censys"}


# =============================================================
# QUEUE MANAGEMENT
# =============================================================

def build_queue(conn, limit=500):
    """Build validation queue prioritizing unvalidated IPs.

    Priority order:
      1. Scan candidates / cert-pattern IPs (newly discovered, need verification)
      2. Tiered APT IPs (TIER_S > TIER_A > TIER_B > TIER_C)
      3. Everything else by pulse count
    """
    log("Building validation queue (limit %d)..." % limit)

    rows = conn.execute("""
        SELECT i.ip,
            CASE
                WHEN i.infra_type LIKE 'scan_candidate%%' THEN 0
                WHEN i.infra_type LIKE 'cert_pattern%%' THEN 0
                WHEN s.tier = 'TIER_S' THEN 1
                WHEN s.tier = 'TIER_A' THEN 2
                WHEN s.tier = 'TIER_B' THEN 3
                WHEN s.tier = 'TIER_C' THEN 4
                ELSE 5
            END as priority
        FROM ipv4_iocs i
        LEFT JOIN subnets s ON s.cidr = (
            SELECT cidr FROM subnets
            WHERE i.ip LIKE substr(cidr, 1, instr(cidr, '/') - 4) || '%'
            LIMIT 1
        )
        WHERE i.validation_status IN ('unvalidated', 'partial')
        ORDER BY priority ASC, i.pulse_count DESC
        LIMIT ?
    """, (limit,)).fetchall()

    if not rows:
        rows = conn.execute("""
            SELECT ip, 5 as priority FROM ipv4_iocs
            WHERE validation_status IN ('unvalidated', 'partial')
            ORDER BY pulse_count DESC
            LIMIT ?
        """, (limit,)).fetchall()

    # Only request sources that are actually available (have API keys or are free)
    keys = get_api_keys()
    available_sources = []
    for source in ALL_SOURCES:
        if source in NEEDS_KEY and not keys.get(source):
            continue
        available_sources.append(source)
    sources_str = ",".join(available_sources)

    now = datetime.now().isoformat()
    added = 0
    for row in rows:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO validation_queue (ip, priority, status, sources_requested, queued_at)
                VALUES (?, ?, 'pending', ?, ?)
            """, (row["ip"], row["priority"], sources_str, now))
            added += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    log("Added %d IPs to queue (%d already queued)" % (added, len(rows) - added))
    return added


def get_queue_ips(conn, source, limit=100):
    """Get pending IPs that haven't been validated by this source."""
    rows = conn.execute("""
        SELECT vq.ip, vq.priority FROM validation_queue vq
        JOIN ipv4_iocs i ON i.ip = vq.ip
        WHERE vq.status IN ('pending', 'error')
          AND vq.attempts < 3
          AND (i.validation_sources NOT LIKE ? OR i.validation_sources IS NULL OR i.validation_sources = '{}')
        ORDER BY vq.priority ASC, vq.queued_at ASC
        LIMIT ?
    """, ("%%\"%s\":%%" % source, limit)).fetchall()

    if len(rows) < limit:
        extra = conn.execute("""
            SELECT vq.ip, vq.priority FROM validation_queue vq
            JOIN ipv4_iocs i ON i.ip = vq.ip
            WHERE vq.status IN ('pending', 'error')
              AND vq.attempts < 3
            ORDER BY vq.priority ASC
            LIMIT ?
        """, (limit,)).fetchall()
        seen = set(r["ip"] for r in rows)
        for r in extra:
            if r["ip"] not in seen:
                rows.append(r)
                seen.add(r["ip"])
            if len(rows) >= limit:
                break

    return rows


def _validate_result(result, source):
    """Sanity-check an API result before storing. Returns True if safe."""
    if not isinstance(result, dict):
        return False
    # Must contain at least one expected field per source
    expected = {
        "shodan": ["ports", "hostnames"],
        "abuseipdb": ["abuse_confidence"],
        "virustotal": ["malicious"],
        "otx": ["pulse_count"],
        "censys": ["ports", "services"],
        "dshield": ["count", "attacks"],
        "threatfox": ["matched", "ioc_count"],
        "firehol": ["listed", "match_count"],
        "stevenblack": ["hostnames_count", "match_count"],
        "c2tracker": ["listed", "match_count"],
        "tweetfeed": ["listed", "tags"],
        "ipsum": ["listed", "blacklist_count"],
        "emerging_threats": ["listed", "match_type"],
    }
    for field in expected.get(source, []):
        if field in result:
            return True
    return False


def store_result(conn, ip, source, result, error=None):
    """Store validation result in enrichment_results and update ipv4_iocs.

    All writes are wrapped in a transaction — either everything commits
    (enrichment_results + ipv4_iocs + validation_queue) or nothing does.
    """
    now = datetime.now().isoformat()

    try:
        conn.execute("BEGIN IMMEDIATE")
    except Exception:
        pass  # Already in a transaction (autocommit off)

    try:
        if result:
            # Reject malformed API responses
            if not _validate_result(result, source):
                log("  SKIP %s/%s: malformed response" % (ip, source))
                txlog(conn, "reject_malformed", ip, source, "error", "failed validation check")
                error = "malformed_response"
                result = None

        if result:
            raw = json.dumps(result, default=str)

            parsed = {"indicator": ip, "indicator_type": "ipv4", "source": source,
                      "raw_data": raw, "queried_at": now}

            if source == "shodan":
                parsed["reverse_dns"] = ",".join(result.get("hostnames", []))[:500]
                parsed["hosting_provider"] = ",".join(result.get("cpes", []))[:500]
                parsed["abuse_contact"] = ",".join(result.get("vulns", []))[:500]
                parsed["city"] = ",".join(result.get("tags", []))[:200]
            elif source == "abuseipdb":
                parsed["abuse_contact"] = str(result.get("abuse_confidence", 0))
                parsed["city"] = str(result.get("total_reports", 0))
                parsed["country"] = result.get("country", "")
                parsed["hosting_provider"] = result.get("isp", "")
            elif source == "virustotal":
                parsed["abuse_contact"] = "%d/%d" % (
                    result.get("malicious", 0),
                    result.get("malicious", 0) + result.get("harmless", 0) + result.get("undetected", 0))
                parsed["hosting_provider"] = result.get("as_owner", "")
                parsed["country"] = result.get("country", "")
                parsed["asn"] = result.get("asn") or None
            elif source == "otx":
                parsed["abuse_contact"] = "pulses:%d mal:%d" % (
                    result.get("pulse_count", 0), result.get("malware_count", 0))
                parsed["reverse_dns"] = ",".join(result.get("passive_dns", [])[:10])[:500]
                parsed["country"] = result.get("country_code", "")
                parsed["city"] = result.get("city", "")
                parsed["hosting_provider"] = ",".join(result.get("tags", [])[:10])[:500]
                asn_raw = result.get("asn", "")
                if asn_raw and str(asn_raw).startswith("AS"):
                    try:
                        parsed["asn"] = int(str(asn_raw).replace("AS", ""))
                    except ValueError:
                        pass
            elif source == "censys":
                parsed["abuse_contact"] = ",".join(result.get("services", []))[:500]
                parsed["hosting_provider"] = result.get("as_name", "")
                parsed["country"] = result.get("country", "")
                parsed["city"] = result.get("city", "")
                parsed["asn"] = result.get("asn") or None
                parsed["reverse_dns"] = "%s %s" % (result.get("os", ""), result.get("os_version", ""))
            elif source == "dshield":
                parsed["abuse_contact"] = "attacks:%d reports:%d" % (
                    result.get("attacks", 0), result.get("count", 0))
                parsed["hosting_provider"] = result.get("asname", "")
                parsed["country"] = result.get("ascountry", "")
                parsed["asn"] = result.get("as") or None
                parsed["reverse_dns"] = result.get("network", "")
            elif source == "threatfox":
                if result.get("matched"):
                    parsed["abuse_contact"] = "iocs:%d conf:%d" % (
                        result.get("ioc_count", 0), result.get("max_confidence", 0))
                    parsed["hosting_provider"] = ",".join(result.get("malware", []))[:500]
                    parsed["reverse_dns"] = ",".join(result.get("tags", []))[:500]
                else:
                    parsed["abuse_contact"] = "not_found"
            elif source == "firehol":
                parsed["abuse_contact"] = "listed:%s matches:%d" % (
                    result.get("listed", False), result.get("match_count", 0))
                parsed["reverse_dns"] = ",".join(result.get("matched_networks", [])[:10])[:500]
            elif source == "stevenblack":
                parsed["abuse_contact"] = "hostnames:%d matches:%d" % (
                    result.get("hostnames_count", 0), result.get("match_count", 0))
                parsed["reverse_dns"] = ",".join(result.get("matched_domains", [])[:10])[:500]

            conn.execute("""
                INSERT OR REPLACE INTO enrichment_results
                (indicator, indicator_type, source, raw_data, asn, asn_org, country, city,
                 registrar, created_date, updated_date, abuse_contact, reverse_dns, hosting_provider, queried_at)
                VALUES (:indicator, :indicator_type, :source, :raw_data,
                        :asn, :asn_org, :country, :city,
                        :registrar, :created_date, :updated_date, :abuse_contact,
                        :reverse_dns, :hosting_provider, :queried_at)
            """, {
                "indicator": parsed["indicator"],
                "indicator_type": parsed["indicator_type"],
                "source": parsed["source"],
                "raw_data": parsed["raw_data"],
                "asn": parsed.get("asn"),
                "asn_org": parsed.get("asn_org"),
                "country": parsed.get("country"),
                "city": parsed.get("city"),
                "registrar": parsed.get("registrar"),
                "created_date": parsed.get("created_date"),
                "updated_date": parsed.get("updated_date"),
                "abuse_contact": parsed.get("abuse_contact"),
                "reverse_dns": parsed.get("reverse_dns"),
                "hosting_provider": parsed.get("hosting_provider"),
                "queried_at": parsed["queried_at"],
            })

            # Update ipv4_iocs validation tracking
            row = conn.execute("SELECT validation_sources, validation_count FROM ipv4_iocs WHERE ip=?",
                               (ip,)).fetchone()
            if row:
                try:
                    sources = json.loads(row["validation_sources"] or "{}")
                except (json.JSONDecodeError, TypeError):
                    sources = {}
                sources[source] = sources.get(source, 0) + 1
                new_count = (row["validation_count"] or 0) + 1
                done_count = len(sources)
                status = "validated" if done_count >= VALIDATED_THRESHOLD else "partial"

                conn.execute("""
                    UPDATE ipv4_iocs SET
                        last_validated=?, validation_count=?, validation_sources=?, validation_status=?
                    WHERE ip=?
                """, (now, new_count, json.dumps(sources), status, ip))

        # Update queue entry
        if error:
            conn.execute("""
                UPDATE validation_queue SET
                    status='error', attempts=attempts+1, last_error=?
                WHERE ip=?
            """, (str(error)[:500], ip))
        else:
            row = conn.execute("SELECT sources_requested, sources_completed FROM validation_queue WHERE ip=?",
                               (ip,)).fetchone()
            if row:
                completed = set(filter(None, (row["sources_completed"] or "").split(",")))
                completed.add(source)
                requested = set(filter(None, (row["sources_requested"] or "").split(",")))
                new_completed = ",".join(sorted(completed))
                new_status = "done" if completed >= requested else "pending"
                conn.execute("""
                    UPDATE validation_queue SET
                        status=?, sources_completed=?, completed_at=?
                    WHERE ip=?
                """, (new_status, new_completed, now if new_status == "done" else None, ip))

        # ── v3: Write to source_validations table + recalculate score ──
        if result and not error:
            try:
                from scoring import get_source_confidence
                confidence = get_source_confidence(source, result)
                ioc_row = conn.execute("SELECT id FROM ipv4_iocs WHERE ip=?", (ip,)).fetchone()
                if ioc_row:
                    conn.execute("""
                        INSERT OR REPLACE INTO source_validations
                        (ioc_id, ioc_type, ioc_value, source, validated_at, confidence_score, raw_response)
                        VALUES (?, 'ipv4', ?, ?, ?, ?, ?)
                    """, (ioc_row["id"], ip, source, now, confidence,
                          json.dumps(result, default=str)[:2000]))
            except Exception as e:
                log("  v3 scoring hook: %s" % e)

        # ── v3: Update composite score after storing result ──
        if result and not error:
            try:
                from scoring import calculate_composite_score, calculate_infrastructure_risk, get_provider_risk_level
                score = calculate_composite_score(ip, conn)
                risk = calculate_infrastructure_risk(ip, conn)
                provider = get_provider_risk_level(ip, conn)
                conn.execute("""
                    UPDATE ipv4_iocs SET composite_score=?, infrastructure_risk_score=?,
                    provider_risk_level=?, score_timestamp=? WHERE ip=?
                """, (score, risk, provider, now, ip))
            except Exception as e:
                log("  v3 score update: %s" % e)

        # ── v3: Reactivate IOC if it was stale/expired ──
        if result and not error:
            try:
                from lifecycle import reactivate_ioc
                ioc_row = conn.execute(
                    "SELECT id, lifecycle_state FROM ipv4_iocs WHERE ip=?", (ip,)).fetchone()
                if ioc_row and ioc_row["lifecycle_state"] in ("stale", "expired"):
                    reactivate_ioc(ioc_row["id"], conn, reason="validation_found")
            except Exception as e:
                log("  v3 lifecycle hook: %s" % e)

        # Log the transaction
        if error:
            txlog(conn, "store_error", ip, source, "error", str(error))
        else:
            txlog(conn, "store_result", ip, source, "ok")

        conn.commit()

    except Exception as e:
        conn.rollback()
        log("  DB ERROR for %s/%s: %s (rolled back)" % (ip, source, e))
        # Log the rollback in a separate micro-transaction
        try:
            txlog(conn, "rollback", ip, source, "error", str(e))
            conn.commit()
        except Exception:
            pass


# =============================================================
# VALIDATION RUNNERS
# =============================================================

def _mark_queue_source_done(conn, ip, source):
    """Mark a source as completed in the validation queue for an IP.
    Called when an IP is skipped (already has results) to prevent queue stall.
    Also updates ipv4_iocs.validation_status if enough sources have results.
    """
    try:
        row = conn.execute(
            "SELECT sources_requested, sources_completed FROM validation_queue WHERE ip=?",
            (ip,)).fetchone()
        if row:
            completed = set(filter(None, (row["sources_completed"] or "").split(",")))
            completed.add(source)
            requested = set(filter(None, (row["sources_requested"] or "").split(",")))
            new_completed = ",".join(sorted(completed))
            new_status = "done" if completed >= requested else "pending"
            conn.execute("""
                UPDATE validation_queue SET
                    status=?, sources_completed=?, completed_at=?
                WHERE ip=?
            """, (new_status, new_completed,
                  datetime.now().isoformat() if new_status == "done" else None, ip))

            # Also ensure ipv4_iocs.validation_status reflects actual enrichment count
            source_count = conn.execute(
                "SELECT COUNT(DISTINCT source) FROM enrichment_results WHERE indicator=?",
                (ip,)).fetchone()[0]
            if source_count >= VALIDATED_THRESHOLD:
                conn.execute(
                    "UPDATE ipv4_iocs SET validation_status='validated' WHERE ip=? AND validation_status != 'validated'",
                    (ip,))
            elif source_count > 0:
                conn.execute(
                    "UPDATE ipv4_iocs SET validation_status='partial' WHERE ip=? AND validation_status='unvalidated'",
                    (ip,))

            conn.commit()
    except Exception:
        pass  # Never let queue bookkeeping break the actual work


def _flush_completed_queue(conn):
    """Flush queue entries that are effectively done.

    An entry is effectively done if:
    1. All its requested sources are completed, OR
    2. The IP already has VALIDATED_THRESHOLD+ distinct sources in enrichment_results, OR
    3. All remaining (uncompleted) sources have exhausted their daily budget.

    This prevents queue buildup from slow/limited sources (censys, VT) blocking new IPs.
    """
    flushed = 0
    rows = conn.execute("""
        SELECT ip, sources_requested, sources_completed
        FROM validation_queue WHERE status = 'pending'
    """).fetchall()

    now = datetime.now().isoformat()
    for row in rows:
        ip = row["ip"]
        requested = set(filter(None, (row["sources_requested"] or "").split(",")))
        completed = set(filter(None, (row["sources_completed"] or "").split(",")))

        # Check 1: all sources completed
        if completed >= requested:
            conn.execute(
                "UPDATE validation_queue SET status='done', completed_at=? WHERE ip=?",
                (now, ip))
            flushed += 1
            continue

        # Check 2: already validated (3+ distinct sources in enrichment_results)
        source_count = conn.execute(
            "SELECT COUNT(DISTINCT source) FROM enrichment_results WHERE indicator=?",
            (ip,)).fetchone()[0]
        if source_count >= VALIDATED_THRESHOLD:
            # Mark all remaining sources as completed too
            new_completed = ",".join(sorted(requested))
            conn.execute("""
                UPDATE validation_queue SET status='done', sources_completed=?, completed_at=?
                WHERE ip=?
            """, (new_completed, now, ip))
            conn.execute(
                "UPDATE ipv4_iocs SET validation_status='validated' WHERE ip=? AND validation_status != 'validated'",
                (ip,))
            flushed += 1
            continue

        # Check 3: all remaining sources are budget-exhausted for today
        remaining_sources = requested - completed
        all_exhausted = True
        for src in remaining_sources:
            if get_daily_remaining(conn, src) > 0:
                all_exhausted = False
                break
        if all_exhausted and remaining_sources:
            # Mark as done — those sources can catch this IP in a future queue cycle
            new_completed = ",".join(sorted(completed))
            conn.execute("""
                UPDATE validation_queue SET status='done', sources_completed=?, completed_at=?
                WHERE ip=?
            """, (new_completed, now, ip))
            flushed += 1
            continue

    if flushed:
        conn.commit()
    return flushed


def run_source(source, limit=100):
    """Run validation for a specific source. Respects daily API limits."""
    conn = get_db()
    keys = get_api_keys()

    if source in NEEDS_KEY and not keys.get(source):
        envvar = {"otx": "OTX_API_KEY", "abuseipdb": "ABUSEIPDB_KEY",
                  "virustotal": "VIRUSTOTAL_KEY", "censys": "CENSYS_API_TOKEN"}
        log("SKIP %s: Set %s environment variable" % (source, envvar.get(source, "?")))
        conn.close()
        return 0

    # Check daily API limit before running
    remaining = get_daily_remaining(conn, source)
    if remaining <= 0:
        used = get_daily_usage(conn, source)
        log("SKIP %s: daily limit reached (%d/%d used today)" % (
            source, used, DAILY_LIMITS.get(source, 0)))
        conn.close()
        return 0

    # Cap batch size to remaining daily budget
    effective_limit = min(limit, remaining)
    if effective_limit < limit:
        log("  %s: capping batch from %d to %d (daily budget remaining)" % (
            source, limit, effective_limit))

    ips = get_queue_ips(conn, source, effective_limit)
    if not ips:
        log("No IPs in queue for %s validation" % source)
        conn.close()
        return 0

    rate = RATE_LIMITS.get(source, 1.0)
    used_today = get_daily_usage(conn, source)
    log("Validating %d IPs via %s (rate: %.1fs, used today: %d/%d)..." % (
        len(ips), source, rate, used_today, DAILY_LIMITS.get(source, 0)))

    validate_fn = API_DISPATCH[source]
    success = 0
    errors = 0

    skipped = 0
    for i, row in enumerate(ips):
        ip = row["ip"]
        sys.stdout.write("\r  [%d/%d] %s..." % (i + 1, len(ips), ip))
        sys.stdout.flush()

        try:
            # Check if already validated by this source
            existing = conn.execute(
                "SELECT id FROM enrichment_results WHERE indicator=? AND source=?",
                (ip, source)).fetchone()
            if existing:
                sys.stdout.write(" (skip)")
                skipped += 1
                # Update queue to mark this source as completed (prevents stale pending)
                _mark_queue_source_done(conn, ip, source)
                continue

            # Call API with smart rate-limit handling
            result, error = validate_fn(ip, api_key=keys.get(source, ""))

            if error == "rate_limited":
                # Single short retry (60s) — if still blocked, skip source for this cycle
                log("\n  Rate limited on %s. Waiting 60s before retry..." % source)
                time.sleep(60)
                result, error = validate_fn(ip, api_key=keys.get(source, ""))
                if error == "rate_limited":
                    log("\n  %s still rate-limited. Marking daily budget exhausted." % source)
                    # Mark budget as exhausted so subsequent cycles don't waste time retrying
                    today = datetime.now().strftime("%Y-%m-%d")
                    limit = DAILY_LIMITS.get(source, 0)
                    conn.execute("""
                        INSERT INTO api_daily_usage (source, date, requests)
                        VALUES (?, ?, ?)
                        ON CONFLICT(source, date) DO UPDATE SET requests = ?
                    """, (source, today, limit, limit))
                    txlog(conn, "rate_limit_exhausted", ip, source, "error",
                          "persistent 429 — marked budget exhausted for today")
                    conn.commit()
                    break

            # Track API call in daily usage (even errors count toward limits)
            increment_daily_usage(conn, source)
            conn.commit()

            store_result(conn, ip, source, result, error)

            if error:
                errors += 1
            else:
                success += 1

            # Stop if we've hit the daily limit mid-batch
            if get_daily_remaining(conn, source) <= 0:
                log("\n  %s daily limit reached mid-batch. Stopping." % source)
                break

        except Exception as e:
            log("\n  UNEXPECTED ERROR on %s/%s: %s (skipping)" % (ip, source, e))
            errors += 1

        time.sleep(rate)

    log("\n  %s complete: %d success, %d errors, %d skipped" % (source, success, errors, skipped))
    conn.close()
    return success


def check_single(ip):
    """Validate a single IP against all available sources."""
    conn = get_db()
    keys = get_api_keys()

    log("Validating %s...\n" % ip)

    for source in ALL_SOURCES:
        print("--- %s ---" % source.upper())

        if source in NEEDS_KEY and not keys.get(source):
            envvars = {"otx": "OTX_API_KEY", "abuseipdb": "ABUSEIPDB_KEY",
                       "virustotal": "VIRUSTOTAL_KEY", "censys": "CENSYS_API_TOKEN"}
            print("  Skipped (set %s)" % envvars.get(source, "?"))
            print()
            continue

        validate_fn = API_DISPATCH[source]
        result, error = validate_fn(ip, api_key=keys.get(source, ""))

        if result:
            store_result(conn, ip, source, result)
            if source == "shodan":
                print("  Ports: %s" % result.get("ports", []))
                print("  Vulns: %s" % result.get("vulns", []))
                print("  Hostnames: %s" % result.get("hostnames", []))
                print("  Tags: %s" % result.get("tags", []))
                print("  CPEs: %s" % result.get("cpes", []))
            elif source == "abuseipdb":
                print("  Abuse Score: %s/100" % result.get("abuse_confidence", 0))
                print("  Reports: %s" % result.get("total_reports", 0))
                print("  Tor: %s" % result.get("is_tor", False))
                print("  ISP: %s" % result.get("isp", ""))
            elif source == "virustotal":
                print("  Malicious: %s" % result.get("malicious", 0))
                print("  Suspicious: %s" % result.get("suspicious", 0))
                print("  Reputation: %s" % result.get("reputation", 0))
                print("  AS Owner: %s" % result.get("as_owner", ""))
            elif source == "otx":
                print("  Pulses: %s" % result.get("pulse_count", 0))
                print("  Malware samples: %s" % result.get("malware_count", 0))
                print("  Passive DNS: %s" % result.get("passive_dns_count", 0))
                print("  Tags: %s" % result.get("tags", [])[:10])
                print("  Country: %s" % result.get("country", ""))
            elif source == "censys":
                print("  Ports: %s" % result.get("ports", []))
                print("  Services: %s" % result.get("services", []))
                print("  OS: %s %s" % (result.get("os", ""), result.get("os_version", "")))
                print("  ASN: %s (%s)" % (result.get("asn", ""), result.get("as_name", "")))
                print("  Location: %s, %s" % (result.get("city", ""), result.get("country", "")))
                print("  Labels: %s" % result.get("labels", []))
            elif source == "dshield":
                print("  Attacks: %s" % result.get("attacks", 0))
                print("  Reports: %s" % result.get("count", 0))
                print("  Date Range: %s → %s" % (result.get("mindate", ""), result.get("maxdate", "")))
                print("  ASN: %s (%s)" % (result.get("as", ""), result.get("asname", "")))
                print("  Network: %s" % result.get("network", ""))
                if result.get("threatfeeds"):
                    print("  Threat Feeds: %s" % list(result["threatfeeds"].keys()))
            elif source == "threatfox":
                if result.get("matched"):
                    print("  IOC Matches: %d" % result.get("ioc_count", 0))
                    print("  Malware: %s" % result.get("malware", []))
                    print("  Threat Types: %s" % result.get("threat_types", []))
                    print("  Max Confidence: %d" % result.get("max_confidence", 0))
                    print("  Tags: %s" % result.get("tags", [])[:10])
                    print("  First Seen: %s" % result.get("first_seen", ""))
                else:
                    print("  Not found in ThreatFox database")
            elif source == "firehol":
                if result.get("listed"):
                    print("  LISTED in FireHOL! Matches: %d" % result.get("match_count", 0))
                    print("  Networks: %s" % result.get("matched_networks", [])[:10])
                else:
                    print("  Not found in FireHOL blocklists")
                print("  Lists checked: %d (%d networks)" % (
                    result.get("lists_checked", 0), result.get("total_networks", 0)))
            elif source == "stevenblack":
                print("  Hostnames checked: %d" % result.get("hostnames_count", 0))
                if result.get("match_count", 0) > 0:
                    print("  MATCHED domains: %s" % result.get("matched_domains", []))
                else:
                    print("  No hostname matches in Steven Black list")
            elif source == "c2tracker":
                if result.get("listed"):
                    print("  LISTED in C2 Tracker!")
                    print("  C2 Frameworks: %s" % result.get("c2_frameworks", []))
                    print("  Matched feeds: %s" % result.get("matched_feeds", []))
                else:
                    print("  Not found in C2 Tracker")
            elif source == "tweetfeed":
                if result.get("listed"):
                    print("  LISTED in TweetFeed!")
                    print("  Tags: %s" % result.get("tags", ""))
                else:
                    print("  Not found in TweetFeed")
            elif source == "ipsum":
                if result.get("listed"):
                    print("  LISTED in IPsum! Blacklist count: %d" % result.get("blacklist_count", 0))
                else:
                    print("  Not found in IPsum")
            elif source == "emerging_threats":
                if result.get("listed"):
                    print("  LISTED in Emerging Threats! Match: %s" % result.get("match_type", ""))
                else:
                    print("  Not found in Emerging Threats")
        else:
            print("  Error: %s" % error)

        print()
        time.sleep(RATE_LIMITS.get(source, 1.0))

    conn.close()


def auto_run():
    """Automated run — autonomous daily API limit enforcement.

    Each source tracks its own daily usage in the api_daily_usage table.
    When a source hits its daily limit, it's automatically skipped until
    the next day. No need to pre-calculate batch sizes; run_source()
    handles everything autonomously.
    """
    log("=" * 60)
    log("AUTO VALIDATION RUN STARTED (mode: %s)" % get_mode())
    log("=" * 60)

    conn = get_db()
    txlog(conn, "auto_run_start", status="ok", detail="mode=%s" % get_mode())
    conn.commit()
    keys = get_api_keys()

    # Check if Shodan is handled separately
    shodan_standalone = _cfg_str("continuous", "shodan_standalone", "false").lower() in ("true", "1", "yes")

    # Show available sources and daily budget status
    available = []
    if shodan_standalone:
        log("  shodan: SKIPPED (shodan_standalone = true)")
    else:
        available.append("shodan")
    for source in ["otx", "abuseipdb", "virustotal", "censys"]:
        if keys.get(source):
            available.append(source)
        else:
            log("  %s: SKIPPED (no API key)" % source)
    # Free API sources (no key needed)
    for source in ["dshield", "threatfox"]:
        available.append(source)
    # Local offline sources (always available)
    for source in LOCAL_SOURCES:
        available.append(source)

    # Show daily usage summary
    for source in available:
        used = get_daily_usage(conn, source)
        limit = DAILY_LIMITS.get(source, 0)
        remaining = get_daily_remaining(conn, source)
        log("  %s: %d/%d used today (%d remaining)" % (source, used, limit, remaining))
    log("Available sources: %s" % ", ".join(available))

    # Flush queue entries that are effectively done (prevents queue stall)
    flushed = _flush_completed_queue(conn)
    if flushed:
        log("Flushed %d effectively-completed queue entries" % flushed)

    # Build/refresh queue if needed
    pending = conn.execute("SELECT COUNT(*) FROM validation_queue WHERE status='pending'").fetchone()[0]
    if pending < 100:
        log("Queue low (%d pending), refilling..." % pending)
        build_queue(conn, 1000)
    else:
        log("Queue has %d pending IPs" % pending)

    conn.close()

    # Run each source — run_source() autonomously enforces daily limits
    # Use a reasonable per-cycle batch (daily_limit / runs_per_day) as a
    # soft target, but run_source() will cap to actual remaining budget.
    total_success = 0
    for source in available:
        batch = max(10, DAILY_LIMITS.get(source, 100) // max(1, RUNS_PER_DAY))
        remaining = get_daily_remaining(get_db(), source)
        if remaining <= 0:
            log("\nSKIP %s: daily limit exhausted" % source)
            continue
        log("\nRunning %s: target batch=%d, remaining today=%d" % (source, batch, remaining))
        success = run_source(source, batch)
        total_success += success

    # Re-export web DB if we got results
    if total_success > 0:
        log("\nRe-exporting web DB...")
        try:
            import subprocess
            export_script = str(Path(__file__).parent / "export.py")
            subprocess.run([sys.executable, export_script],
                           cwd=str(Path(__file__).parent.parent))
            log("Web DB exported successfully")
        except Exception as e:
            log("Export error: %s" % e)

    # Sync validation status (catches vuln_scan and other offline enrichments)
    synced = sync_validation_status()
    if synced:
        log("Synced validation_status for %d IPs" % synced)

    # Final status
    conn2 = get_db()
    txlog(conn2, "auto_run_end", status="ok", detail="validated=%d" % total_success)
    conn2.commit()
    conn2.close()
    log("\n" + "=" * 60)
    log("AUTO RUN COMPLETE — %d IPs validated this run" % total_success)
    show_status()
    log("=" * 60)


def sync_validation_status():
    """Bulk-sync ipv4_iocs.validation_status from enrichment_results counts.

    Catches enrichments added outside the normal pipeline (vuln_scan, manual imports)
    and ensures validation_status accurately reflects the actual source count.
    """
    conn = get_db()
    updated = 0
    rows = conn.execute("""
        SELECT i.ip, i.validation_status,
               COUNT(DISTINCT e.source) as source_count
        FROM ipv4_iocs i
        LEFT JOIN enrichment_results e ON e.indicator = i.ip
        GROUP BY i.ip
        HAVING (source_count >= ? AND i.validation_status != 'validated')
            OR (source_count > 0 AND source_count < ? AND i.validation_status = 'unvalidated')
    """, (VALIDATED_THRESHOLD, VALIDATED_THRESHOLD)).fetchall()

    for row in rows:
        new_status = "validated" if row["source_count"] >= VALIDATED_THRESHOLD else "partial"
        conn.execute(
            "UPDATE ipv4_iocs SET validation_status=?, validation_count=? WHERE ip=?",
            (new_status, row["source_count"], row["ip"]))
        updated += 1

    if updated:
        conn.commit()
    conn.close()
    return updated


def show_status():
    """Show validation statistics."""
    conn = get_db()

    print("\n=== Validation Status ===")
    print("  Mode: %s" % get_mode())
    print()

    total = conn.execute("SELECT COUNT(*) FROM ipv4_iocs").fetchone()[0]
    for status in ["unvalidated", "partial", "validated"]:
        count = conn.execute("SELECT COUNT(*) FROM ipv4_iocs WHERE validation_status=?",
                             (status,)).fetchone()[0]
        pct = count / total * 100 if total else 0
        print("  %s: %d IPs (%.1f%%)" % (status.capitalize(), count, pct))

    print("\nSource Coverage:")
    for source in ALL_SOURCES:
        count = conn.execute("SELECT COUNT(DISTINCT indicator) FROM enrichment_results WHERE source=?",
                             (source,)).fetchone()[0]
        print("  %s: %d IPs (%.1f%%)" % (source, count, count / total * 100 if total else 0))

    # API key status + daily usage
    keys = get_api_keys()
    print("\nAPI Keys & Daily Usage:")
    for source in ALL_SOURCES:
        if source in ("shodan", "dshield", "threatfox"):
            key_status = "OK (no key needed)"
        elif source in LOCAL_SOURCES:
            key_status = "OK (offline)"
        else:
            key_status = "configured" if keys.get(source) else "MISSING"
        used = get_daily_usage(conn, source)
        limit = DAILY_LIMITS.get(source, 0)
        remaining = get_daily_remaining(conn, source)
        if limit >= 99999:
            print("  %s: %s — %d used today (unlimited)" % (source, key_status, used))
        else:
            print("  %s: %s — %d/%d used today (%d remaining)" % (
                source, key_status, used, limit, remaining))

    # Queue status
    print("\nQueue:")
    for status in ["pending", "running", "done", "error"]:
        count = conn.execute("SELECT COUNT(*) FROM validation_queue WHERE status=?",
                             (status,)).fetchone()[0]
        if count:
            print("  %s: %d" % (status.capitalize(), count))

    # Recent validations
    print("\nLast 10 Validations:")
    rows = conn.execute("""
        SELECT indicator, source, queried_at
        FROM enrichment_results
        ORDER BY queried_at DESC LIMIT 10
    """).fetchall()
    for r in rows:
        print("  %s via %s @ %s" % (r["indicator"], r["source"], r["queried_at"]))

    conn.close()


def show_txlog(limit=30):
    """Show recent transaction log entries."""
    conn = get_db()

    print("\n=== Transaction Log (last %d entries) ===" % limit)
    rows = conn.execute("""
        SELECT timestamp, action, ip, source, status, detail, run_id
        FROM transaction_log ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()

    if not rows:
        print("  (empty)")
    else:
        for r in rows:
            ip_str = r["ip"] or ""
            src_str = r["source"] or ""
            detail_str = (" — %s" % r["detail"]) if r["detail"] else ""
            print("  [%s] %-18s %-16s %-10s %s%s" % (
                r["timestamp"][:19], r["action"], ip_str, src_str, r["status"], detail_str))

    # Summary by run
    print("\nRecent Runs:")
    runs = conn.execute("""
        SELECT run_id,
               MIN(timestamp) AS started,
               MAX(timestamp) AS ended,
               SUM(CASE WHEN action='store_result' AND status='ok' THEN 1 ELSE 0 END) AS success,
               SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors,
               SUM(CASE WHEN action='rollback' THEN 1 ELSE 0 END) AS rollbacks
        FROM transaction_log
        GROUP BY run_id
        ORDER BY started DESC
        LIMIT 10
    """).fetchall()
    for r in runs:
        print("  %s  %s → %s  ok:%d  err:%d  rollback:%d" % (
            r["run_id"], r["started"][:19], r["ended"][:19],
            r["success"], r["errors"], r["rollbacks"]))

    conn.close()


def purge_txlog(days=30):
    """Delete transaction log entries older than N days."""
    conn = get_db()
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    deleted = conn.execute("DELETE FROM transaction_log WHERE timestamp < ?", (cutoff,)).rowcount
    conn.commit()
    conn.close()
    log("Purged %d transaction log entries older than %d days" % (deleted, days))


# =============================================================
# CLI
# =============================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1]

    if cmd == "queue":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 500
        conn = get_db()
        build_queue(conn, limit)
        conn.close()

    elif cmd == "run":
        if len(sys.argv) < 3:
            print("Usage: validate.py run <shodan|abuseipdb|virustotal|otx|censys|dshield|threatfox|firehol|stevenblack|all> [N]")
            return
        source = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 100

        if source == "all":
            for s in ALL_SOURCES:
                print("\n" + "=" * 50)
                run_source(s, limit)
        else:
            run_source(source, limit)

    elif cmd == "check":
        if len(sys.argv) < 3:
            print("Usage: validate.py check <IP>")
            return
        check_single(sys.argv[2])

    elif cmd == "auto":
        auto_run()

    elif cmd == "status":
        show_status()

    elif cmd == "log":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        show_txlog(limit)

    elif cmd == "purge-log":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        purge_txlog(days)

    elif cmd == "sync":
        synced = sync_validation_status()
        print("Synced validation_status for %d IPs" % synced)

    elif cmd == "flush":
        conn = get_db()
        flushed = _flush_completed_queue(conn)
        print("Flushed %d effectively-completed queue entries" % flushed)
        conn.close()

    else:
        print("Unknown command: %s" % cmd)
        print(__doc__)


if __name__ == "__main__":
    main()
