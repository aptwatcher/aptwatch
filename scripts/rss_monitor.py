#!/usr/bin/env python3
"""
RSS Threat Intelligence Monitor for APT Watch

Monitors security blog RSS feeds for articles matching tracked keywords,
extracts IOCs (IPs, domains, hashes), cross-references them against the
aptwatch API, and generates YAML submission files for new findings.

Usage:
    python rss_monitor.py                   # Run all feeds
    python rss_monitor.py --dry-run         # Preview without writing files
    python rss_monitor.py --feed microsoft  # Run specific feed only
    python rss_monitor.py --list-feeds      # Show configured feeds

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
# CONFIGURATION
# =============================================================

STATE_FILE = app_config.paths.project_root / "rss_monitor_state.json"
SUBMISSIONS_DIR = app_config.paths.submissions
LOG_DIR = app_config.paths.project_root / "logs"

AUTHOR = "rss-monitor"

# Max age of articles to process (skip anything older)
MAX_AGE_DAYS = 30

# IOC extraction patterns
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

    for kw in keywords_config.get("article_keywords", []):
        if kw.lower() in text_lower:
            matched.append(kw)
            score += 10

    for asn in keywords_config.get("tracked_asns", []):
        patterns = ["AS" + asn, "ASN" + asn, "AS " + asn, "ASN " + asn]
        for p in patterns:
            if p.lower() in text_lower:
                matched.append("ASN:" + asn)
                score += 20
                break

    for provider in keywords_config.get("tracked_providers", []):
        if provider.lower() in text_lower:
            matched.append("Provider:" + provider)
            score += 15

    return score, matched


# =============================================================
# RSS FEEDS
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
}


# =============================================================
# STATE MANAGEMENT
# =============================================================

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"processed": {}, "last_run": None, "stats": {"runs": 0, "articles": 0, "submissions": 0}}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state["last_run"] = datetime.utcnow().isoformat()
    STATE_FILE.write_text(json.dumps(state, indent=2))


def article_id(url):
    return hashlib.sha256(url.encode()).hexdigest()[:16]


# =============================================================
# RSS PARSING
# =============================================================

def fetch_rss(url, timeout=30):
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
            "title": title, "link": link, "pub_date": pub_date,
            "description": description, "content": content, "categories": categories,
        })
    return articles


def parse_date(date_str):
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
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "APTWatch-RSS-Monitor/1.0 (+https://aptwatch.org)"
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
        text = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', text)
        return text
    except Exception as e:
        log("    WARN: failed to fetch article %s: %s" % (url, e))
        return ""


# =============================================================
# IOC EXTRACTION
# =============================================================

def extract_iocs(text):
    iocs = {"ipv4": set(), "domains": set(), "sha256": set()}
    clean = re.sub(r'<[^>]+>', ' ', text)

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

    for match in DOMAIN_PATTERN.finditer(clean):
        domain = match.group(1).lower().replace("[.]", ".")
        if SAFELIST.is_safe_domain(domain):
            continue
        if re.match(r'^[vV]?\d+\.\d+', domain):
            continue
        if not is_valid_domain(domain):
            continue
        iocs["domains"].add(domain)

    for match in HASH_SHA256_PATTERN.finditer(clean):
        iocs["sha256"].add(match.group(1).lower())

    return {k: sorted(v) for k, v in iocs.items() if v}


# =============================================================
# SUBMISSION GENERATION
# =============================================================

def generate_submission(article, iocs, enrichment, feed_name, relevance_score=0, matched_keywords=None):
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    slug = re.sub(r'[^a-z0-9]+', '-', article["title"].lower())[:40].strip('-')
    filename = "%s-%s-%s.yaml" % (AUTHOR, date_str, slug)
    filepath = SUBMISSIONS_DIR / filename

    desc_parts = [article["title"] + "."]
    if matched_keywords:
        desc_parts.append(
            "RELEVANCE: score=%d, matched keywords: %s." % (
                relevance_score, ", ".join(matched_keywords[:10])))
    desc_parts.append("Auto-extracted from RSS feed: %s." % feed_name)

    lines = [
        "# Auto-generated by rss_monitor.py on %s" % date_str,
        "",
        "author: %s" % AUTHOR,
        "",
        "source: %s" % article["link"],
        'source_name: "%s"' % article["title"].replace('"', '\\"'),
        "",
        "description: >",
    ]
    for part in desc_parts:
        lines.append("  %s" % part)

    all_ips = iocs.get("ipv4", [])
    if all_ips:
        lines.append("")
        lines.append("ipv4:")
        for ip in sorted(set(all_ips)):
            lines.append("  - %s" % ip)

    domains = iocs.get("domains", [])
    if domains:
        lines.append("")
        lines.append("domains:")
        for d in sorted(domains):
            defanged = d.replace(".", "[.]")
            lines.append("  - %s" % defanged)

    hashes = iocs.get("sha256", [])
    if hashes:
        lines.append("")
        lines.append("# SHA256 hashes (reference only)")
        for h in sorted(hashes):
            lines.append("#   %s" % h)

    lines.append("")
    return filepath, "\n".join(lines)


# =============================================================
# LOGGING
# =============================================================

def log(msg):
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
    log("Processing feed: %s (%s)" % (feed_name, feed_config["description"]))
    submissions = 0
    cutoff = datetime.utcnow() - timedelta(days=MAX_AGE_DAYS)

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

    seen_urls = set()
    unique_articles = []
    for a in articles:
        if a["link"] not in seen_urls:
            seen_urls.add(a["link"])
            unique_articles.append(a)
    articles = unique_articles

    for article in articles:
        aid = article_id(article["link"])

        if aid in state.get("processed", {}):
            continue

        pub_date = parse_date(article.get("pub_date", ""))
        if pub_date and pub_date < cutoff:
            state["processed"][aid] = {
                "title": article["title"][:80], "url": article["link"],
                "skipped": "too old", "date": article.get("pub_date", ""),
            }
            continue

        rss_text = " ".join([
            article.get("title", ""),
            article.get("description", ""),
            article.get("content", ""),
        ])
        iocs = extract_iocs(rss_text)

        if not iocs.get("ipv4") and not iocs.get("domains"):
            log("    No IOCs in RSS excerpt, fetching full article: %s" % article["link"][:60])
            full_text = fetch_article_text(article["link"])
            if full_text:
                iocs = extract_iocs(full_text)

        if not iocs.get("ipv4") and not iocs.get("domains"):
            state["processed"][aid] = {
                "title": article["title"][:80], "url": article["link"],
                "skipped": "no IOCs found", "date": article.get("pub_date", ""),
            }
            continue

        log("  FOUND IOCs in: %s" % article["title"][:70])
        log("    IPs: %d, Domains: %d, Hashes: %d" % (
            len(iocs.get("ipv4", [])),
            len(iocs.get("domains", [])),
            len(iocs.get("sha256", [])),
        ))

        full_text_for_scoring = " ".join([
            article.get("title", ""),
            article.get("description", ""),
            article.get("content", ""),
        ])
        relevance_score, matched_keywords = score_article_relevance(
            full_text_for_scoring, keywords_config
        )

        has_new = iocs.get("ipv4") or iocs.get("domains")
        is_relevant = relevance_score >= 10

        if not is_relevant:
            log("    SKIP: no project keyword match (score=%d)" % relevance_score)
            state["processed"][aid] = {
                "title": article["title"][:80], "url": article["link"],
                "skipped": "not relevant (score=%d)" % relevance_score,
                "date": article.get("pub_date", ""),
            }
            continue

        if has_new and is_relevant:
            filepath, content = generate_submission(
                article, iocs, {}, feed_name,
                relevance_score, matched_keywords
            )

            if dry_run:
                log("    DRY-RUN: would create %s" % filepath.name)
            else:
                SUBMISSIONS_DIR.mkdir(parents=True, exist_ok=True)
                filepath.write_text(content)
                log("    CREATED: %s" % filepath.name)
                submissions += 1

        state["processed"][aid] = {
            "title": article["title"][:80], "url": article["link"],
            "date": article.get("pub_date", ""),
            "iocs_found": {k: len(v) for k, v in iocs.items()},
            "relevance_score": relevance_score,
            "matched_keywords": matched_keywords[:10] if matched_keywords else [],
            "submission": filepath.name if has_new and is_relevant and not dry_run else None,
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
        return

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
    keywords_config = load_keywords()

    log("=" * 60)
    log("RSS Threat Intelligence Monitor — starting")
    if dry_run:
        log("DRY-RUN mode — no files will be written")
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
    log("Run complete: %d new submission(s) generated" % total_submissions)
    log("Total articles tracked: %d" % state["stats"]["articles"])
    log("=" * 60)


if __name__ == "__main__":
    main()
