#!/usr/bin/env python3
"""
OSINT Feed Integrator for APT Watch v3
Downloads and caches external OSINT feeds (Tier 1 + Tier 2) for cross-validation
against existing IPv4 IOCs. Feeds are stored locally and used by validate.py
as offline blocklist sources (like FireHOL/Steven Black).

Tier 1 — High relevance:
  - ThreatFox (abuse.ch)     — malware URLs with family attribution + confidence
  - C2 Tracker (montysecurity) — C2 framework IPs (Cobalt Strike, Sliver, Brute Ratel…)
  - TweetFeed (0xDanielLopez) — crowdsourced IOCs with APT tags (Kimsuky, etc.)

Tier 2 — Cross-validation:
  - IPsum (stamparm)          — meta-blacklist score (number of lists flagging IP)
  - Emerging Threats (ET)     — curated IP blocklist (Spamhaus, DShield, abuse.ch)

Usage:
    python osint_feeds.py update              # Download/refresh all feeds
    python osint_feeds.py update <feed>       # Download one feed
    python osint_feeds.py status              # Show cache status
    python osint_feeds.py lookup <IP>         # Check IP against all cached feeds
    python osint_feeds.py stats               # Feed statistics

All feeds are cached in database/cache/osint/ and refreshed based on
per-feed intervals (hourly to daily depending on update frequency).
"""

import os
import sys
import json
import time
import csv
import io
import ipaddress
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
CACHE_DIR = PROJECT_ROOT / "database" / "cache" / "osint"
LOG_DIR = PROJECT_ROOT / "database" / "logs"

# ──────────────────────────────────────────────────────────
# Feed definitions
# ──────────────────────────────────────────────────────────

FEEDS = {
    # ── Tier 1 ──────────────────────────────────────────
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/urls/recent/",
        "type": "csv",
        "description": "ThreatFox malware IOCs with family attribution",
        "refresh_hours": 6,
        "tier": 1,
        "ioc_types": ["url", "ip"],
        "has_attribution": True,
    },
    "c2tracker": {
        "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt",
        "type": "ip_list",
        "description": "C2 framework IPs (Cobalt Strike, Sliver, Brute Ratel…)",
        "refresh_hours": 24,  # weekly feed, daily check is fine
        "tier": 1,
        "ioc_types": ["ip"],
        "has_attribution": False,
        "fp_warning": "Known FP risk — use for validation only, not primary ingestion",
    },
    "c2tracker_cobalt": {
        "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Cobalt%20Strike%20C2%20IPs.txt",
        "type": "ip_list",
        "description": "C2 Tracker — Cobalt Strike only (highest APT relevance)",
        "refresh_hours": 24,
        "tier": 1,
        "ioc_types": ["ip"],
        "has_attribution": True,  # implicit: Cobalt Strike
        "attribution_tag": "cobalt_strike",
    },
    "c2tracker_sliver": {
        "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver%20C2%20IPs.txt",
        "type": "ip_list",
        "description": "C2 Tracker — Sliver only",
        "refresh_hours": 24,
        "tier": 1,
        "ioc_types": ["ip"],
        "has_attribution": True,
        "attribution_tag": "sliver",
    },
    "c2tracker_bruteratel": {
        "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Brute%20Ratel%20C4%20IPs.txt",
        "type": "ip_list",
        "description": "C2 Tracker — Brute Ratel C4 only",
        "refresh_hours": 24,
        "tier": 1,
        "ioc_types": ["ip"],
        "has_attribution": True,
        "attribution_tag": "brute_ratel",
    },
    "tweetfeed": {
        "url": "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/today.csv",
        "type": "csv",
        "description": "TweetFeed crowdsourced IOCs with APT tags",
        "refresh_hours": 12,
        "tier": 1,
        "ioc_types": ["ip", "domain", "url", "hash"],
        "has_attribution": True,
    },
    # ── Tier 2 ──────────────────────────────────────────
    "ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "type": "ipsum",
        "description": "IPsum meta-blacklist (IP + number of lists)",
        "refresh_hours": 24,
        "tier": 2,
        "ioc_types": ["ip"],
        "has_attribution": False,
        "fp_warning": "Known FP risk at low scores — use score >= 3 for validation",
    },
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "type": "ip_list",
        "description": "Emerging Threats curated block IPs (Spamhaus, DShield, abuse.ch)",
        "refresh_hours": 12,
        "tier": 2,
        "ioc_types": ["ip"],
        "has_attribution": False,
    },
}

# ──────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[osint_feeds {ts}] {msg}")


# ──────────────────────────────────────────────────────────
# Cache management
# ──────────────────────────────────────────────────────────

def _cache_path(feed_name):
    return CACHE_DIR / f"{feed_name}.raw"

def _meta_path(feed_name):
    return CACHE_DIR / f"{feed_name}.meta.json"

def _ensure_cache_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

def _is_cache_fresh(feed_name):
    """Check if cached feed is still within refresh interval."""
    meta = _meta_path(feed_name)
    if not meta.exists():
        return False
    try:
        info = json.loads(meta.read_text())
        fetched = datetime.fromisoformat(info["fetched_at"])
        max_age = timedelta(hours=FEEDS[feed_name]["refresh_hours"])
        return datetime.now() - fetched < max_age
    except (json.JSONDecodeError, KeyError, ValueError):
        return False

def _save_meta(feed_name, size, entry_count):
    meta = {
        "feed": feed_name,
        "fetched_at": datetime.now().isoformat(),
        "size_bytes": size,
        "entry_count": entry_count,
        "url": FEEDS[feed_name]["url"],
    }
    _meta_path(feed_name).write_text(json.dumps(meta, indent=2))


# ──────────────────────────────────────────────────────────
# Download
# ──────────────────────────────────────────────────────────

def _download(url, timeout=30):
    """Download a URL and return content as string."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "APTWatch-OSINT-Feeds/1.0 (+https://aptwatch.org)"
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        log(f"  ERROR downloading {url}: {e}")
        return None
    except Exception as e:
        log(f"  ERROR downloading {url}: {e}")
        return None


# ──────────────────────────────────────────────────────────
# Parsers — extract IPs from each feed format
# ──────────────────────────────────────────────────────────

def _parse_ip_list(content):
    """Parse a simple one-IP-per-line file, skip comments and CIDRs."""
    ips = set()
    cidrs = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        # Handle CIDR notation
        if "/" in line:
            try:
                net = ipaddress.ip_network(line, strict=False)
                cidrs.add(net)
            except ValueError:
                pass
            continue
        # Plain IP
        try:
            ipaddress.ip_address(line)
            ips.add(line)
        except ValueError:
            pass
    return ips, cidrs


def _parse_ipsum(content):
    """Parse IPsum format: IP<tab>score per line. Returns dict {ip: score}."""
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            ip_str, score_str = parts[0].strip(), parts[1].strip()
            try:
                ipaddress.ip_address(ip_str)
                result[ip_str] = int(score_str)
            except (ValueError, TypeError):
                pass
    return result


def _parse_threatfox_csv(content):
    """Parse ThreatFox CSV. Returns list of dicts with ioc_value, malware, threat_type, confidence."""
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith('"first_seen'):
            continue
        # CSV fields: first_seen, ioc_id, ioc_value, ioc_type, threat_type,
        #             fk_malware, malware_alias, malware_printable, last_seen,
        #             confidence_level, is_compromised, reference, tags, anonymous, reporter
        try:
            reader = csv.reader(io.StringIO(line))
            row = next(reader)
            if len(row) < 10:
                continue
            # Extract IP from URL if present
            ioc_value = row[2].strip().strip('"')
            ioc_type = row[3].strip().strip('"')
            threat_type = row[4].strip().strip('"')
            malware = row[7].strip().strip('"') if len(row) > 7 else ""
            confidence = row[9].strip().strip('"') if len(row) > 9 else "0"
            tags = row[12].strip().strip('"') if len(row) > 12 else ""

            # Try to extract IP from URL
            ip_extracted = None
            if "://" in ioc_value:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(ioc_value)
                    host = parsed.hostname
                    if host:
                        try:
                            ipaddress.ip_address(host)
                            ip_extracted = host
                        except ValueError:
                            pass
                except Exception:
                    pass

            entries.append({
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "threat_type": threat_type,
                "malware": malware,
                "confidence": int(confidence) if confidence.isdigit() else 0,
                "tags": tags,
                "ip": ip_extracted,
            })
        except (csv.Error, StopIteration):
            continue
    return entries


def _parse_tweetfeed_csv(content):
    """Parse TweetFeed CSV. Returns list of dicts with type, value, tags."""
    entries = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            reader = csv.reader(io.StringIO(line))
            row = next(reader)
            if len(row) < 4:
                continue
            # Fields: timestamp, reporter, type, value, tags, source_url
            ioc_type = row[2].strip() if len(row) > 2 else ""
            ioc_value = row[3].strip() if len(row) > 3 else ""
            tags = row[4].strip() if len(row) > 4 else ""

            ip_extracted = None
            if ioc_type == "ip":
                try:
                    ipaddress.ip_address(ioc_value)
                    ip_extracted = ioc_value
                except ValueError:
                    pass

            entries.append({
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "tags": tags,
                "ip": ip_extracted,
            })
        except (csv.Error, StopIteration):
            continue
    return entries


# ──────────────────────────────────────────────────────────
# Feed update
# ──────────────────────────────────────────────────────────

def update_feed(feed_name, force=False):
    """Download and cache a single feed. Returns (success, entry_count)."""
    if feed_name not in FEEDS:
        log(f"Unknown feed: {feed_name}")
        return False, 0

    _ensure_cache_dir()
    feed = FEEDS[feed_name]

    if not force and _is_cache_fresh(feed_name):
        log(f"  {feed_name}: cache fresh (< {feed['refresh_hours']}h), skipping")
        return True, 0

    log(f"  Downloading {feed_name} from {feed['url']}...")
    content = _download(feed['url'])
    if content is None:
        return False, 0

    # Save raw content
    cache_file = _cache_path(feed_name)
    cache_file.write_text(content)

    # Count entries based on type
    count = 0
    feed_type = feed["type"]
    if feed_type == "ip_list":
        ips, cidrs = _parse_ip_list(content)
        count = len(ips) + len(cidrs)
    elif feed_type == "ipsum":
        scores = _parse_ipsum(content)
        count = len(scores)
    elif feed_type == "csv" and feed_name == "threatfox":
        entries = _parse_threatfox_csv(content)
        count = len(entries)
    elif feed_type == "csv" and feed_name == "tweetfeed":
        entries = _parse_tweetfeed_csv(content)
        count = len(entries)
    else:
        count = len([l for l in content.splitlines() if l.strip() and not l.startswith("#")])

    _save_meta(feed_name, len(content), count)
    log(f"  {feed_name}: {count} entries cached ({len(content)} bytes)")
    return True, count


def update_all(force=False):
    """Download all feeds."""
    log("Updating all OSINT feeds...")
    total = 0
    for name in FEEDS:
        ok, count = update_feed(name, force=force)
        if ok:
            total += count
    log(f"Done. Total entries across all feeds: {total}")
    return total


# ──────────────────────────────────────────────────────────
# Lookup — check an IP against all cached feeds
# ──────────────────────────────────────────────────────────

def _load_cached_ips(feed_name):
    """Load IPs from a cached feed. Returns set of IP strings."""
    cache = _cache_path(feed_name)
    if not cache.exists():
        return set()
    content = cache.read_text()
    feed = FEEDS[feed_name]

    if feed["type"] == "ip_list":
        ips, cidrs = _parse_ip_list(content)
        return ips, cidrs
    elif feed["type"] == "ipsum":
        scores = _parse_ipsum(content)
        return scores
    elif feed["type"] == "csv" and feed_name == "threatfox":
        entries = _parse_threatfox_csv(content)
        return {e["ip"] for e in entries if e.get("ip")}, entries
    elif feed["type"] == "csv" and feed_name == "tweetfeed":
        entries = _parse_tweetfeed_csv(content)
        return {e["ip"] for e in entries if e.get("ip")}, entries
    return set()


def lookup_ip(ip_str):
    """
    Check an IP against all cached OSINT feeds.
    Returns dict: {feed_name: {matched: bool, details: ...}}
    """
    results = {}
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"error": f"Invalid IP: {ip_str}"}

    for name, feed in FEEDS.items():
        cache = _cache_path(name)
        if not cache.exists():
            results[name] = {"matched": False, "reason": "not_cached"}
            continue

        content = cache.read_text()
        matched = False
        details = {}

        if feed["type"] == "ip_list":
            ips, cidrs = _parse_ip_list(content)
            if ip_str in ips:
                matched = True
                details["match_type"] = "exact"
            else:
                for net in cidrs:
                    if addr in net:
                        matched = True
                        details["match_type"] = "cidr"
                        details["matched_network"] = str(net)
                        break

        elif feed["type"] == "ipsum":
            scores = _parse_ipsum(content)
            if ip_str in scores:
                matched = True
                details["score"] = scores[ip_str]
                details["match_type"] = "meta_score"

        elif feed["type"] == "csv" and name == "threatfox":
            entries = _parse_threatfox_csv(content)
            for e in entries:
                if e.get("ip") == ip_str:
                    matched = True
                    details["malware"] = e["malware"]
                    details["threat_type"] = e["threat_type"]
                    details["confidence"] = e["confidence"]
                    details["tags"] = e["tags"]
                    break

        elif feed["type"] == "csv" and name == "tweetfeed":
            entries = _parse_tweetfeed_csv(content)
            for e in entries:
                if e.get("ip") == ip_str:
                    matched = True
                    details["tags"] = e["tags"]
                    details["ioc_type"] = e["ioc_type"]
                    break

        if feed.get("attribution_tag") and matched:
            details["c2_framework"] = feed["attribution_tag"]

        results[name] = {"matched": matched, "details": details}

    return results


# ──────────────────────────────────────────────────────────
# validate.py integration functions
# ──────────────────────────────────────────────────────────

def validate_c2tracker(ip, **_):
    """Validate IP against C2 Tracker feeds. Used by validate.py."""
    results = {}
    c2_feeds = ["c2tracker", "c2tracker_cobalt", "c2tracker_sliver", "c2tracker_bruteratel"]

    for fname in c2_feeds:
        cache = _cache_path(fname)
        if not cache.exists():
            continue
        ips, cidrs = _parse_ip_list(cache.read_text())
        if ip in ips:
            tag = FEEDS[fname].get("attribution_tag", "unknown")
            results[fname] = tag

    if not results:
        # Check general list too
        cache = _cache_path("c2tracker")
        if cache.exists():
            ips, cidrs = _parse_ip_list(cache.read_text())
            try:
                addr = ipaddress.ip_address(ip)
                for net in cidrs:
                    if addr in net:
                        results["c2tracker"] = "unknown_framework"
                        break
            except ValueError:
                pass

    if results:
        return {
            "listed": True,
            "c2_frameworks": list(results.values()),
            "matched_feeds": list(results.keys()),
            "match_count": len(results),
        }, None
    return {
        "listed": False,
        "c2_frameworks": [],
        "matched_feeds": [],
        "match_count": 0,
    }, None


def validate_tweetfeed(ip, **_):
    """Validate IP against TweetFeed. Used by validate.py."""
    cache = _cache_path("tweetfeed")
    if not cache.exists():
        return None, "not_cached"
    entries = _parse_tweetfeed_csv(cache.read_text())
    for e in entries:
        if e.get("ip") == ip:
            return {
                "listed": True,
                "tags": e["tags"],
                "ioc_type": e["ioc_type"],
            }, None
    return {"listed": False, "tags": "", "ioc_type": ""}, None


def validate_ipsum(ip, **_):
    """Validate IP against IPsum meta-blacklist. Used by validate.py."""
    cache = _cache_path("ipsum")
    if not cache.exists():
        return None, "not_cached"
    scores = _parse_ipsum(cache.read_text())
    if ip in scores:
        return {
            "listed": True,
            "blacklist_count": scores[ip],
        }, None
    return {"listed": False, "blacklist_count": 0}, None


def validate_emerging_threats(ip, **_):
    """Validate IP against Emerging Threats. Used by validate.py."""
    cache = _cache_path("emerging_threats")
    if not cache.exists():
        return None, "not_cached"
    content = cache.read_text()
    ips, cidrs = _parse_ip_list(content)

    if ip in ips:
        return {"listed": True, "match_type": "exact"}, None

    try:
        addr = ipaddress.ip_address(ip)
        for net in cidrs:
            if addr in net:
                return {"listed": True, "match_type": "cidr", "network": str(net)}, None
    except ValueError:
        pass

    return {"listed": False, "match_type": None}, None


# ──────────────────────────────────────────────────────────
# Status & stats
# ──────────────────────────────────────────────────────────

def show_status():
    """Show cache status for all feeds."""
    _ensure_cache_dir()
    print(f"\n{'Feed':<22} {'Tier':>4}  {'Entries':>8}  {'Size':>8}  {'Age':>12}  {'Status':<10}")
    print("-" * 80)
    for name, feed in sorted(FEEDS.items(), key=lambda x: (x[1]["tier"], x[0])):
        meta = _meta_path(name)
        if meta.exists():
            try:
                info = json.loads(meta.read_text())
                fetched = datetime.fromisoformat(info["fetched_at"])
                age = datetime.now() - fetched
                age_str = f"{age.seconds // 3600}h{(age.seconds % 3600) // 60}m" if age.days == 0 else f"{age.days}d"
                fresh = age < timedelta(hours=feed["refresh_hours"])
                size_kb = info.get("size_bytes", 0) / 1024
                print(f"  {name:<20} T{feed['tier']:>2}  {info.get('entry_count', '?'):>8}  {size_kb:>6.0f}KB  {age_str:>12}  {'OK' if fresh else 'STALE'}")
            except (json.JSONDecodeError, KeyError):
                print(f"  {name:<20} T{feed['tier']:>2}  {'?':>8}  {'?':>8}  {'?':>12}  CORRUPT")
        else:
            print(f"  {name:<20} T{feed['tier']:>2}  {'-':>8}  {'-':>8}  {'-':>12}  NOT CACHED")
    print()


def show_stats():
    """Show detailed statistics for cached feeds."""
    _ensure_cache_dir()
    total_ips = set()
    for name, feed in FEEDS.items():
        cache = _cache_path(name)
        if not cache.exists():
            continue
        content = cache.read_text()
        if feed["type"] == "ip_list":
            ips, _ = _parse_ip_list(content)
            total_ips.update(ips)
            print(f"  {name}: {len(ips)} unique IPs")
        elif feed["type"] == "ipsum":
            scores = _parse_ipsum(content)
            high = sum(1 for s in scores.values() if s >= 5)
            med = sum(1 for s in scores.values() if 3 <= s < 5)
            low = sum(1 for s in scores.values() if s < 3)
            total_ips.update(scores.keys())
            print(f"  {name}: {len(scores)} IPs (high>=5: {high}, med 3-4: {med}, low<3: {low})")
        elif feed["type"] == "csv" and name == "threatfox":
            entries = _parse_threatfox_csv(content)
            ip_entries = [e for e in entries if e.get("ip")]
            malware_families = set(e["malware"] for e in entries if e.get("malware"))
            total_ips.update(e["ip"] for e in ip_entries)
            print(f"  {name}: {len(entries)} IOCs ({len(ip_entries)} with IPs), {len(malware_families)} malware families")
        elif feed["type"] == "csv" and name == "tweetfeed":
            entries = _parse_tweetfeed_csv(content)
            ip_entries = [e for e in entries if e.get("ip")]
            total_ips.update(e["ip"] for e in ip_entries)
            print(f"  {name}: {len(entries)} IOCs ({len(ip_entries)} IPs)")

    print(f"\n  Total unique IPs across all feeds: {len(total_ips)}")


# ──────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1].lower()

    if cmd == "update":
        if len(sys.argv) >= 3:
            feed_name = sys.argv[2].lower()
            update_feed(feed_name, force="--force" in sys.argv)
        else:
            update_all(force="--force" in sys.argv)

    elif cmd == "status":
        show_status()

    elif cmd == "stats":
        show_stats()

    elif cmd == "lookup":
        if len(sys.argv) < 3:
            print("Usage: osint_feeds.py lookup <IP>")
            return
        ip = sys.argv[2]
        results = lookup_ip(ip)
        print(f"\nOSINT feed lookup for {ip}:")
        print("-" * 50)
        for feed, result in sorted(results.items()):
            if result.get("matched"):
                details = result.get("details", {})
                detail_str = ", ".join(f"{k}={v}" for k, v in details.items() if v)
                print(f"  [HIT]  {feed}: {detail_str}")
            elif result.get("reason") == "not_cached":
                print(f"  [---]  {feed}: not cached")
            else:
                print(f"  [   ]  {feed}: not found")
        print()

    else:
        print(f"Unknown command: {cmd}")
        print("Usage: osint_feeds.py [update|status|stats|lookup]")


if __name__ == "__main__":
    main()
