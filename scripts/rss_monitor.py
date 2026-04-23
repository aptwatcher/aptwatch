#!/usr/bin/env python3
"""
RSS Threat Intelligence Monitor for APT Intel Project

Monitors security blog RSS feeds for articles matching tracked keywords,
extracts IOCs (IPs, domains, hashes), cross-references them against the
aptwatch API, and generates YAML submission files for new findings.

Usage:
    python rss_monitor.py                   # Run all feeds
    python rss_monitor.py --dry-run         # Preview without writing files
    python rss_monitor.py --feed microsoft  # Run specific feed only
    python rss_monitor.py --list-feeds      # Show configured feeds

Designed to run via systemd timer (every 6 hours).
State is persisted in rss_monitor_state.json to avoid re-processing articles.
"""

import json
import re
import sys
import hashlib
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timedelta
from aptwatch_ioc_collector import Safelist, is_valid_domain
from aptwatch_config import config as app_config

# =============================================================
# CONFIGURATION (paths from aptwatch_config.py / config.ini)
# =============================================================

STATE_FILE = app_config.paths.project_root / "server" / "database" / "rss_monitor_state.json"
SUBMISSIONS_DIR = app_config.paths.submissions
LOG_DIR = app_config.paths.project_root / "server" / "database" / "logs"

API_BASE = "https://api.aptwatch.org"
AUTHOR = "rss-monitor"

# Max age of articles to process (skip anything older)
MAX_AGE_DAYS = 30

# IOC extraction patterns
# Matches IPs with any mix of . and [.] separators
IP_MIXED_PATTERN = re.compile(
    r'\b(\d{1,3}(?:\[?\.\]?)\d{1,3}(?:\[?\.\]?)\d{1,3}(?:\[?\.\]?)\d{1,3})\b'
)
DOMAIN_PATTERN = re.compile(
    r'\b([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\[\.\]|\.)(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\[\.\]|\.))*[a-z]{2,})\b',
    re.IGNORECASE
)
HASH_SHA256_PATTERN = re.compile(r'\b([a-fA-F0-9]{64})\b')
HASH_MD5_PATTERN = re.compile(r'\b([a-fA-F0-9]{32})\b')

# Safelist — loaded from safelist.yaml (single source of truth for FP filtering)
SAFELIST = Safelist()

# =============================================================
# KEYWORD CONFIGURATION
# =============================================================

KEYWORDS_FILE = Path(__file__).parent / "rss_keywords.yaml"

def load_keywords():
    """Load keywords from rss_keywords.yaml config file."""
    defaults = {
        "microsoft_search": ["threat intelligence IOC", "nation-state attack"],
        "article_keywords": ["APT28", "APT29", "Sandworm", "Turla", "Gamaredon"],
        "tracked_asns": [],
        "tracked_providers": [],
    }
    if not KEYWORDS_FILE.exists():
        print("  WARN: %s not found, using defaults" % KEYWORDS_FILE)
        return defaults
    try:
        import yaml
        with open(str(KEYWORDS_FILE)) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return defaults
        return {
            "microsoft_search": data.get("microsoft_search", defaults["microsoft_search"]),
            "article_keywords": data.get("article_keywords", defaults["article_keywords"]),
            "tracked_asns": [str(a) for a in data.get("tracked_asns", [])],
            "tracked_providers": data.get("tracked_providers", []),
        }
    except ImportError:
        # Fallback: basic YAML parsing without pyyaml
        data = {"microsoft_search": [], "article_keywords": [], "tracked_asns": [], "tracked_providers": []}
        current_key = None
        with open(str(KEYWORDS_FILE)) as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.endswith(":") and not stripped.startswith("-"):
                    current_key = stripped[:-1].strip()
                    if current_key not in data:
                        current_key = None
                elif stripped.startswith("- ") and current_key:
                    val = stripped[2:].strip()
                    # Strip inline comments
                    if "#" in val:
                        val = val[:val.index("#")].strip()
                    if val:
                        data[current_key].append(val)
        return {k: v if v else defaults.get(k, []) for k, v in data.items()}


def score_article_relevance(text, keywords_config):
    """Score how relevant an article is to the project. Returns (score, matched_keywords)."""
    text_lower = text.lower()
    matched = []
    score = 0

    # Check article keywords (each match = +10)
    for kw in keywords_config.get("article_keywords", []):
        if kw.lower() in text_lower:
            matched.append(kw)
            score += 10

    # Check tracked ASN numbers in text (each = +20, high signal)
    for asn in keywords_config.get("tracked_asns", []):
        patterns = ["AS" + asn, "ASN" + asn, "AS " + asn, "ASN " + asn]
        for p in patterns:
            if p.lower() in text_lower:
                matched.append("ASN:" + asn)
                score += 20
                break

    # Check tracked provider names (each = +15)
    for provider in keywords_config.get("tracked_providers", []):
        if provider.lower() in text_lower:
            matched.append("Provider:" + provider)
            score += 15

    return score, matched


# =============================================================
# RSS FEEDS — Microsoft uses keyword search, others are direct
# =============================================================

FEEDS = {
    "microsoft": {
        "description": "Microsoft Security Blog (keyword-based)",
        "type": "microsoft_keyword",
        "base_url": "https://www.microsoft.com/en-us/security/blog/search/{keyword}/feed/rss2/",
    },
    "microsoft_threat": {
        "description": "Microsoft Threat Intelligence blog",
        "type": "rss",
        "url": "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
    },
    "lab52": {
        "description": "Lab52 (S2 Grupo) threat research",
        "type": "rss",
        "url": "https://lab52.io/blog/feed/",
    },
    "certua": {
        "description": "CERT-UA advisories",
        "type": "rss",
        "url": "https://cert.gov.ua/api/articles/rss",
    },
    "google_ti": {
        "description": "Google Threat Intelligence (Mandiant)",
        "type": "rss",
        "url": "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
    },
    "eset": {
        "description": "ESET WeLiveSecurity research blog",
        "type": "rss",
        "url": "https://feeds.feedburner.com/eset/blog?format=xml",
    },
    # "trendmicro": {
    #     "description": "Trend Micro threat research",
    #     "type": "rss",
    #     "url": "https://www.trendmicro.com/en_us/research.rss.html",
    # },
    # DISABLED 2026-03-30: RSS feed returns malformed XML (invalid token line 18)
}

# Step 2.C — per-feed confidence score for attribution tagging on ingest.
# These scores flow into the auto-YAML via `confidence_score:` and the loader
# (scripts/ingest_yaml_submission.py) propagates them to
# ipv4_iocs.actor_attribution_score et al.
#
# Semantics (matches Step 2.A migration):
#   0.70-0.99 — vetted per-group feeds (Mandiant, MSTIC, CISA).
#   0.50-0.69 — aggregated feeds (OTX, AlienVault).
#   0.30-0.49 — noisy / community sources.
FEED_CONFIDENCE = {
    "microsoft":        0.80,  # MSTIC keyword-search
    "microsoft_threat": 0.85,  # MSTIC threat blog — higher signal
    "lab52":            0.70,  # S2 Grupo research
    "certua":           0.75,  # CERT-UA advisories — official
    "google_ti":        0.85,  # Mandiant / Google TI
    "eset":             0.75,  # ESET WeLiveSecurity research
}
DEFAULT_FEED_CONFIDENCE = 0.50

# RSS feeds don't resolve APT group per-article (no NLP yet). The loader
# writes IOCs under this sentinel campaign bucket until phase-2 actor
# resolution ships.
RSS_UNATTRIBUTED_GROUP = "Unattributed"


# =============================================================
# STATE MANAGEMENT
# =============================================================

def load_state():
    """Load processed article state."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"processed": {}, "last_run": None, "stats": {"runs": 0, "articles": 0, "submissions": 0}}


def save_state(state):
    """Save processed article state."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state["last_run"] = datetime.utcnow().isoformat()
    STATE_FILE.write_text(json.dumps(state, indent=2))


def article_id(url):
    """Generate a stable ID for an article URL."""
    return hashlib.sha256(url.encode()).hexdigest()[:16]


# =============================================================
# RSS PARSING
# =============================================================

def fetch_rss(url, timeout=30):
    """Fetch and parse an RSS feed. Returns list of articles."""
    articles = []
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "APTWatch-RSS-Monitor/1.0 (+https://aptwatch.org)"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        root = ET.fromstring(data)
    except (urllib.error.URLError, ET.ParseError, OSError) as e:
        print("    WARN: failed to fetch %s: %s" % (url, e))
        return articles

    ns = {"content": "http://purl.org/rss/1.0/modules/content/"}

    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        description = (item.findtext("description") or "").strip()
        content = (item.findtext("content:encoded", namespaces=ns) or "").strip()
        categories = [c.text for c in item.findall("category") if c.text]

        if not link:
            continue

        articles.append({
            "title": title,
            "link": link,
            "pub_date": pub_date,
            "description": description,
            "content": content,
            "categories": categories,
        })

    return articles


def parse_date(date_str):
    """Parse RSS date string to datetime."""
    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt).replace(tzinfo=None)
        except (ValueError, AttributeError):
            continue
    return None


# =============================================================
# ARTICLE FETCHING
# =============================================================

def fetch_article_text(url, timeout=30):
    """Fetch full article page and extract text content."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "APTWatch-RSS-Monitor/1.0 (+https://aptwatch.org)"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        # Strip HTML tags
        text = re.sub(r'<[^>]+>', ' ', html)
        # Collapse whitespace
        text = re.sub(r'\s+', ' ', text)
        return text
    except Exception as e:
        log("    WARN: failed to fetch article %s: %s" % (url, e))
        return ""


# =============================================================
# IOC EXTRACTION
# =============================================================

def extract_iocs(text):
    """Extract IOCs from article text, filtered by safelist. Returns dict of IOC lists."""
    iocs = {"ipv4": set(), "domains": set(), "sha256": set()}

    # Strip HTML tags for cleaner extraction
    clean = re.sub(r'<[^>]+>', ' ', text)

    # IPs (handles plain, fully defanged, and partially defanged)
    for match in IP_MIXED_PATTERN.finditer(clean):
        raw = match.group(1)
        ip = raw.replace("[.]", ".").replace("[]", ".")
        if SAFELIST.is_safe_ip(ip):
            continue
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    iocs["ipv4"].add(ip)
            except ValueError:
                continue

    # Domains
    for match in DOMAIN_PATTERN.finditer(clean):
        domain = match.group(1).lower().replace("[.]", ".")
        if SAFELIST.is_safe_domain(domain):
            continue
        # Skip version-like strings (e.g. "v2.0", "3.11") and invalid domains
        if re.match(r'^[vV]?\d+\.\d+', domain):
            continue
        if not is_valid_domain(domain):
            continue
        iocs["domains"].add(domain)

    # SHA256 hashes
    for match in HASH_SHA256_PATTERN.finditer(clean):
        iocs["sha256"].add(match.group(1).lower())

    return {k: sorted(v) for k, v in iocs.items() if v}


# =============================================================
# API CROSS-REFERENCE
# =============================================================

def check_ip_against_api(ip):
    """Check a single IP against the aptwatch API."""
    try:
        url = "%s/api/ioc/%s" % (API_BASE, ip)
        req = urllib.request.Request(url, headers={"User-Agent": "APTWatch-RSS-Monitor/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return data
    except Exception:
        return None


def check_ip_range_against_api(ip):
    """Search for IPs in the same /16 range."""
    prefix = ".".join(ip.split(".")[:2])
    try:
        url = "%s/api/search?q=%s" % (API_BASE, prefix)
        req = urllib.request.Request(url, headers={"User-Agent": "APTWatch-RSS-Monitor/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return data
    except Exception:
        return None


def enrich_iocs(iocs):
    """Cross-reference extracted IOCs against the aptwatch API."""
    results = {
        "known_ips": [],       # Already in our DB
        "related_ips": [],     # Same /16 range as known IOCs
        "new_ips": [],         # Not in our DB at all
        "new_domains": iocs.get("domains", []),
        "sha256": iocs.get("sha256", []),
    }

    for ip in iocs.get("ipv4", []):
        # Direct lookup
        data = check_ip_against_api(ip)
        if data and data.get("found"):
            results["known_ips"].append({
                "ip": ip,
                "validation_count": data.get("ioc", {}).get("validation_count", 0),
            })
            continue

        # Range lookup
        range_data = check_ip_range_against_api(ip)
        if range_data and range_data.get("total", 0) > 0:
            results["related_ips"].append({
                "ip": ip,
                "nearby_count": range_data["total"],
            })
        else:
            results["new_ips"].append(ip)

    return results


# =============================================================
# SUBMISSION GENERATION
# =============================================================

def generate_submission(article, iocs, enrichment, feed_name, relevance_score=0, matched_keywords=None):
    """Generate a YAML submission file for an article with IOCs."""
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    slug = re.sub(r'[^a-z0-9]+', '-', article["title"].lower())[:40].strip('-')
    filename = "%s-%s-%s.yaml" % (AUTHOR, date_str, slug)
    filepath = SUBMISSIONS_DIR / filename

    # Build description
    desc_parts = [article["title"] + "."]
    if matched_keywords:
        desc_parts.append(
            "RELEVANCE: score=%d, matched keywords: %s." % (
                relevance_score, ", ".join(matched_keywords[:10]))
        )
    if enrichment["known_ips"]:
        desc_parts.append(
            "OVERLAP: %d IP(s) already in aptwatch database." % len(enrichment["known_ips"])
        )
    if enrichment["related_ips"]:
        desc_parts.append(
            "RELATED: %d IP(s) in same /16 range as existing IOCs." % len(enrichment["related_ips"])
        )
    desc_parts.append("Auto-extracted from RSS feed: %s." % feed_name)

    # Build YAML content
    lines = [
        "# Auto-generated by rss_monitor.py on %s" % date_str,
        "",
        "author: %s" % AUTHOR,
        "",
        "confidence_score: %.2f" % FEED_CONFIDENCE.get(feed_name, DEFAULT_FEED_CONFIDENCE),
        "",
        "source: %s" % article["link"],
        'source_name: "%s"' % article["title"].replace('"', '\\"'),
        "",
        "apt_groups:",
        "  - %s" % RSS_UNATTRIBUTED_GROUP,
        "",
        "description: >",
    ]
    for part in desc_parts:
        lines.append("  %s" % part)

    # IOC sections
    all_ips = (
        [e["ip"] for e in enrichment["known_ips"]] +
        [e["ip"] for e in enrichment["related_ips"]] +
        enrichment["new_ips"]
    )
    if all_ips:
        lines.append("")
        lines.append("ipv4:")
        for ip in sorted(set(all_ips)):
            comment = ""
            for k in enrichment["known_ips"]:
                if k["ip"] == ip:
                    comment = "  # ALREADY TRACKED (validation_count: %d)" % k["validation_count"]
            for r in enrichment["related_ips"]:
                if r["ip"] == ip:
                    comment = "  # RELATED (%d nearby IOCs in DB)" % r["nearby_count"]
            lines.append("  - %s%s" % (ip, comment))

    if enrichment["new_domains"]:
        lines.append("")
        lines.append("domains:")
        for d in sorted(enrichment["new_domains"]):
            # Defang for safety
            defanged = d.replace(".", "[.]")
            lines.append("  - %s" % defanged)

    if enrichment["sha256"]:
        lines.append("")
        lines.append("# NOTE: SHA256 hashes (not importable yet, kept for reference)")
        for h in sorted(enrichment["sha256"]):
            lines.append("#   %s" % h)

    lines.append("")
    return filepath, "\n".join(lines)


# =============================================================
# LOGGING
# =============================================================

def log(msg):
    """Print and log a message."""
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    print(line)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = LOG_DIR / "rss_monitor.log"
        with open(str(log_file), "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# =============================================================
# MAIN PROCESSING
# =============================================================

def process_feed(feed_name, feed_config, state, keywords_config, dry_run=False):
    """Process a single feed configuration. Returns count of new submissions."""
    log("Processing feed: %s (%s)" % (feed_name, feed_config["description"]))
    submissions = 0
    cutoff = datetime.utcnow() - timedelta(days=MAX_AGE_DAYS)

    # Collect all articles from this feed
    articles = []
    if feed_config["type"] == "microsoft_keyword":
        ms_keywords = keywords_config.get("microsoft_search", [])
        for keyword in ms_keywords:
            url = feed_config["base_url"].format(keyword=keyword.replace(" ", "+"))
            fetched = fetch_rss(url)
            for a in fetched:
                a["_keyword"] = keyword
            articles.extend(fetched)
            log("  [%s] %d articles" % (keyword, len(fetched)))
    else:
        articles = fetch_rss(feed_config["url"])
        log("  %d articles fetched" % len(articles))

    # Deduplicate by URL
    seen_urls = set()
    unique_articles = []
    for a in articles:
        if a["link"] not in seen_urls:
            seen_urls.add(a["link"])
            unique_articles.append(a)
    articles = unique_articles

    for article in articles:
        aid = article_id(article["link"])

        # Skip already processed
        if aid in state.get("processed", {}):
            continue

        # Skip old articles
        pub_date = parse_date(article.get("pub_date", ""))
        if pub_date and pub_date < cutoff:
            state["processed"][aid] = {
                "title": article["title"][:80],
                "url": article["link"],
                "skipped": "too old",
                "date": article.get("pub_date", ""),
            }
            continue

        # Extract IOCs from RSS content first (title + description + content)
        rss_text = " ".join([
            article.get("title", ""),
            article.get("description", ""),
            article.get("content", ""),
        ])
        iocs = extract_iocs(rss_text)

        # If no IOCs in RSS content, fetch the full article page
        if not iocs.get("ipv4") and not iocs.get("domains"):
            log("    No IOCs in RSS excerpt, fetching full article: %s" % article["link"][:60])
            full_text = fetch_article_text(article["link"])
            if full_text:
                iocs = extract_iocs(full_text)

        # Skip articles with no IOCs
        if not iocs.get("ipv4") and not iocs.get("domains"):
            state["processed"][aid] = {
                "title": article["title"][:80],
                "url": article["link"],
                "skipped": "no IOCs found",
                "date": article.get("pub_date", ""),
            }
            continue

        log("  FOUND IOCs in: %s" % article["title"][:70])
        log("    IPs: %d, Domains: %d, Hashes: %d" % (
            len(iocs.get("ipv4", [])),
            len(iocs.get("domains", [])),
            len(iocs.get("sha256", [])),
        ))

        # Score article relevance against project keywords
        full_text_for_scoring = " ".join([
            article.get("title", ""),
            article.get("description", ""),
            article.get("content", ""),
        ])
        relevance_score, matched_keywords = score_article_relevance(
            full_text_for_scoring, keywords_config
        )
        if matched_keywords:
            log("    RELEVANCE: score=%d, matched: %s" % (
                relevance_score, ", ".join(matched_keywords[:10])))
        else:
            log("    RELEVANCE: score=0 (no project keywords matched)")

        # Cross-reference against aptwatch API
        enrichment = enrich_iocs(iocs)

        if enrichment["known_ips"]:
            log("    OVERLAP: %d IP(s) already in database" % len(enrichment["known_ips"]))
        if enrichment["related_ips"]:
            log("    RELATED: %d IP(s) in nearby ranges" % len(enrichment["related_ips"]))
        if enrichment["new_ips"]:
            log("    NEW: %d IP(s) not yet tracked" % len(enrichment["new_ips"]))

        # Generate submission if relevant to our project
        has_new = enrichment["new_ips"] or enrichment["related_ips"] or enrichment["new_domains"]
        has_overlap = enrichment["known_ips"] or enrichment["related_ips"]
        is_relevant = relevance_score >= 10  # At least one keyword match

        if not is_relevant and not has_overlap:
            log("    SKIP: no project keyword match and no DB overlap")
            state["processed"][aid] = {
                "title": article["title"][:80],
                "url": article["link"],
                "skipped": "not relevant (score=%d, no overlap)" % relevance_score,
                "date": article.get("pub_date", ""),
            }
            continue

        if (has_new or has_overlap) and is_relevant:
            filepath, content = generate_submission(
                article, iocs, enrichment, feed_name,
                relevance_score, matched_keywords
            )

            if dry_run:
                log("    DRY-RUN: would create %s" % filepath.name)
                log("    Preview:\n%s" % content[:500])
            else:
                SUBMISSIONS_DIR.mkdir(parents=True, exist_ok=True)
                filepath.write_text(content)
                log("    CREATED: %s" % filepath.name)
                submissions += 1

        # Mark as processed
        state["processed"][aid] = {
            "title": article["title"][:80],
            "url": article["link"],
            "date": article.get("pub_date", ""),
            "iocs_found": {k: len(v) for k, v in iocs.items()},
            "relevance_score": relevance_score,
            "matched_keywords": matched_keywords[:10] if matched_keywords else [],
            "overlap": len(enrichment.get("known_ips", [])),
            "related": len(enrichment.get("related_ips", [])),
            "new": len(enrichment.get("new_ips", [])),
            "submission": filepath.name if (has_new or has_overlap) and is_relevant and not dry_run else None,
        }

    return submissions


def main():
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]

    if "--list-feeds" in args:
        print("Configured RSS feeds:\n")
        for name, config in FEEDS.items():
            print("  %-20s %s" % (name, config["description"]))
            if config["type"] == "microsoft_keyword":
                print("  %-20s %d keywords configured" % ("", len(config["keywords"])))
            else:
                print("  %-20s %s" % ("", config.get("url", "")))
        return

    # Filter to specific feed if requested
    feed_filter = None
    if "--feed" in args:
        idx = args.index("--feed")
        if idx + 1 < len(args):
            feed_filter = args[idx + 1]
            if feed_filter not in FEEDS:
                print("Unknown feed: %s" % feed_filter)
                print("Available: %s" % ", ".join(FEEDS.keys()))
                return

    state = load_state()
    state["stats"]["runs"] = state["stats"].get("runs", 0) + 1

    # Load project-specific keywords
    keywords_config = load_keywords()

    log("=" * 60)
    log("RSS Threat Intelligence Monitor — starting")
    if dry_run:
        log("DRY-RUN mode — no files will be written")
    log("Keywords loaded: %d search terms, %d article keywords, %d tracked ASNs, %d providers" % (
        len(keywords_config.get("microsoft_search", [])),
        len(keywords_config.get("article_keywords", [])),
        len(keywords_config.get("tracked_asns", [])),
        len(keywords_config.get("tracked_providers", [])),
    ))
    log("=" * 60)

    total_submissions = 0

    for name, config in FEEDS.items():
        if feed_filter and name != feed_filter:
            continue
        try:
            subs = process_feed(name, config, state, keywords_config, dry_run)
            total_submissions += subs
        except Exception as e:
            log("ERROR processing feed %s: %s" % (name, e))

    state["stats"]["articles"] = len(state.get("processed", {}))
    state["stats"]["submissions"] = state["stats"].get("submissions", 0) + total_submissions

    save_state(state)

    log("")
    log("=" * 60)
    log("Run complete: %d new submission(s) generated" % total_submissions)
    log("Total articles tracked: %d" % state["stats"]["articles"])
    if total_submissions > 0 and not dry_run:
        log("")
        log("Next step: run import_approved.py to import the submissions")
        log("  Or wait for the next sync cycle to pick them up automatically")
    log("=" * 60)


if __name__ == "__main__":
    main()
