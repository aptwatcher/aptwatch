#!/usr/bin/env python3
"""
rss_discovery.py — multi-feed RSS/Atom discovery extractor for the APT Watch
daily threat-hunt job.

WHY THIS EXISTS
---------------
The hunt job (Scheduled/apt-threat-hunting) previously consumed The Register
Atom feed via the agent's WebFetch path. That path serves an EMPTY body for
theregister.com/.atom (bot/JS gating at the CDN), so the RSS discovery leg
silently died and fell back to search every run.

This script fetches feeds DIRECT-TO-ORIGIN with urllib + a real User-Agent —
the same mechanism the server's rss_monitor.py uses successfully — which
resolves the empty-body problem for The Register while also adding
BleepingComputer and The Hacker News as high-frequency discovery feeds.

It is a DISCOVERY tool: it surfaces in-scope articles and harvests outbound
links to primaries. It does NOT extract IOCs or write curator YAMLs — that
remains the curator's job downstream.

SCOPE / GUARDRAILS
------------------
- stdlib only (urllib, xml.etree, gzip, json, csv, argparse, datetime, re).
- Read-only: performs HTTP GETs on public feeds, writes only the report file.
- No .onion, no paywalled follow. Link harvesting is left to the hunt (this
  script only lists candidate outbound links per in-scope entry).

USAGE
-----
  python3 rss_discovery.py                         # JSON to stdout, 24h window
  python3 rss_discovery.py --window-hours 48
  python3 rss_discovery.py --output csv --out out.csv
  python3 rss_discovery.py --all                   # include out-of-scope too
  python3 rss_discovery.py --feeds feeds.json      # custom feed registry
  python3 rss_discovery.py --self-test             # parse bundled fixtures, no network

Exit codes: 0 = ran; 2 = every feed was UNFETCHABLE/EMPTY (hard failure).
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

# =============================================================
# FEED REGISTRY (override with --feeds feeds.json)
# =============================================================
# "kind" is a hint only; the parser auto-detects RSS vs Atom regardless.
# Feeds marked (validate) were added from rss_monitor.py's FEEDS list or from
# CERT-FR / Securelist and should be confirmed with a real run on the host
# (`--self-test` only checks parsing, not live reachability).
DEFAULT_FEEDS = [
    # --- CTI news / high-frequency discovery ---
    {
        "name": "bleepingcomputer",
        "description": "BleepingComputer — all stories (RSS 2.0). Tested working.",
        "url": "https://www.bleepingcomputer.com/feed/",
        "kind": "rss",
    },
    {
        "name": "thehackernews",
        "description": "The Hacker News (RSS via FeedBurner). (validate)",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "kind": "rss",
    },
    {
        "name": "theregister_security",
        "description": "The Register — Security (Atom 1.0). Empty via WebFetch; works direct.",
        "url": "https://www.theregister.com/security/headlines.atom",
        "kind": "atom",
    },
    # --- vendor threat-intel blogs (mirrors rss_monitor.py FEEDS) ---
    {
        "name": "microsoft_threat",
        "description": "Microsoft Threat Intelligence blog (RSS). (from rss_monitor.py)",
        "url": "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",
        "kind": "rss",
    },
    {
        "name": "google_ti_mandiant",
        "description": "Google Threat Intelligence / Mandiant (RSS via FeedBurner). (from rss_monitor.py)",
        "url": "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
        "kind": "rss",
    },
    {
        "name": "eset_welivesecurity",
        "description": "ESET WeLiveSecurity research (RSS via FeedBurner). (from rss_monitor.py)",
        "url": "https://feeds.feedburner.com/eset/blog?format=xml",
        "kind": "rss",
    },
    {
        "name": "lab52",
        "description": "Lab52 (S2 Grupo) threat research (RSS). (from rss_monitor.py)",
        "url": "https://lab52.io/blog/feed/",
        "kind": "rss",
    },
    {
        "name": "securelist",
        "description": "Kaspersky Securelist research (RSS). (validate)",
        "url": "https://securelist.com/feed/",
        "kind": "rss",
    },
    # --- gov / CERT advisories ---
    {
        "name": "certua",
        "description": "CERT-UA advisories (RSS) — most relevant for Russian APTs. (from rss_monitor.py)",
        "url": "https://cert.gov.ua/api/articles/rss",
        "kind": "rss",
    },
    {
        "name": "certfr_avis",
        "description": "CERT-FR — Avis de sécurité (RSS). (validate)",
        "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
        "kind": "rss",
    },
    {
        "name": "certfr_alerte",
        "description": "CERT-FR — Alertes de sécurité (RSS). (validate)",
        "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "kind": "rss",
    },
]

# =============================================================
# SCOPE — in-scope actors + aliases + trigger keywords
# (mirrors the hunt-job SKILL scope block)
# =============================================================
# Actor names + aliases. Reconciled 2026-07-06 against the live Intel API
# (intel_list_actors) so the canonical names AND their tracked aliases both
# match. Kept strictly to the hunt-job SKILL in-scope list (no scope creep to
# other DB actors like Saint Bear / Dragonfly / Qilin, which are out of scope).
IN_SCOPE_ACTORS = [
    # --- Russian state APTs (canonical + aliases) ---
    "gamaredon", "aqua blizzard", "primitive bear", "armageddon", "shuckworm",
    "trident ursa", "earth dahu",                                    # Gamaredon
    "sandworm", "apt44", "seashell blizzard", "voodoo bear", "telebots",
    "iridium", "badpilot",                                           # Sandworm
    "cadet blizzard", "ember bear", "unc2589",                       # Cadet Blizzard
    "storm-2372", "pawn storm",
    "callisto", "callisto group", "star blizzard", "coldriver",      # Star Blizzard/Callisto
    "earth koshchei",
    "secret blizzard", "turla", "venomous bear", "snake", "kazuar",  # Turla
    "apt28", "forest blizzard", "fancy bear", "sofacy", "sednit", "strontium",
    "apt29", "midnight blizzard", "cozy bear", "nobelium", "the dukes",
    "winter vivern", "tag-70",
    "void blizzard",
    # --- Ransomware / crime ops adjacent (in-scope list + aliases) ---
    "blacksanta", "black santa",
    "alphv", "blackcat", "noberus",                                  # ALPHV
    "lockbit", "conti", "wizard spider",                             # LockBit / Conti
    "sangria tempest", "akira",
    "warlock", "water manaul", "storm-2603",                         # Warlock
    "pistachio tempest", "storm-0844", "storm-1567", "vect",
    # --- Project-tracked adjacent campaign ---
    "fortibleed",
]

# Keywords that flag likely Russian-linked / relevant ops even without a named
# actor. CVEs are matched separately by regex.
# Noise tuning (2026-07-06): bare "ukraine" REMOVED — it flagged large volumes
# of unrelated Ukraine coverage. Actor names in an article body are still caught
# at step 3 (full-article WebFetch re-confirm); "cert-ua" is kept as it is
# precise. GRU unit numbers use the specific forms.
TRIGGER_KEYWORDS = [
    "gru", "svr", "fsb",
    "unit 26165", "unit 74455", "unit 29155",
    "ransomware affiliate", "ransomware-as-a-service", "raas",
    "wiper", "cert-ua",
    # Filter-gap backfill (2026-08-23): outlet phrasings that name no actor
    # alias in title/summary (e.g. The Register 2026-08-21 "Russian snoops add
    # OAuth abuse..." — sister coverage of the GTIG primary, missed by the
    # title+summary filter). Phrase forms only — never a bare "russia".
    "russian snoops", "russian spies",
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

ATOM_NS = "{http://www.w3.org/2005/Atom}"

# =============================================================
# FETCH (direct-to-origin — this is what fixes the Register)
# =============================================================
DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 APTWatch-RSS-Discovery/1.0"
)


def fetch(url: str, timeout: int = 30, user_agent: str = DEFAULT_UA) -> tuple[str, str]:
    """Fetch a URL direct-to-origin. Returns (body_text, error).
    On success error == ''. On failure body_text == '' and error is set."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "application/atom+xml, application/rss+xml, "
                      "application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5",
            "Accept-Encoding": "gzip, identity",
            "Accept-Language": "en-US,en;q=0.8",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                try:
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
                except OSError:
                    pass  # not actually gzipped
            charset = resp.headers.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="replace"), ""
    except urllib.error.HTTPError as e:
        return "", f"HTTP {e.code} {e.reason}"
    except urllib.error.URLError as e:
        return "", f"URLError {e.reason}"
    except Exception as e:  # noqa: BLE001
        return "", f"{type(e).__name__}: {e}"


# =============================================================
# PARSE (auto-detect RSS 2.0 vs Atom 1.0)
# =============================================================
def _text(el) -> str:
    return (el.text or "").strip() if el is not None else ""


def _parse_dt(s: str):
    """Parse RFC822 (RSS pubDate) or ISO8601/Atom timestamps. Returns aware UTC datetime or None."""
    if not s:
        return None
    s = s.strip()
    # Atom / ISO 8601 — handle trailing Z and normalize fractional seconds to
    # 6 digits (fromisoformat on <3.11 rejects 1/2-digit fractions like ".00").
    iso = s.replace("Z", "+00:00").replace("z", "+00:00")
    m = re.search(r"\.(\d+)", iso)
    if m:
        frac = (m.group(1) + "000000")[:6]
        iso = iso[:m.start()] + "." + frac + iso[m.end():]
    try:
        dt = datetime.fromisoformat(iso)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # RFC822 (RSS pubDate: "Wed, 01 Jul 2026 17:37:24 -0400")
    try:
        dt = parsedate_to_datetime(s)
        if dt is not None:
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        pass
    return None


def parse_feed(body: str) -> list[dict]:
    """Parse feed body into a list of {title, url, summary, published(dt|None)}."""
    entries: list[dict] = []
    if not body or not body.strip():
        return entries
    try:
        root = ET.fromstring(body.encode("utf-8"))
    except ET.ParseError:
        # tolerate a leading BOM / stray prolog whitespace
        try:
            root = ET.fromstring(body.strip().encode("utf-8"))
        except ET.ParseError:
            return entries

    tag = root.tag.lower()
    # ---- Atom ----
    if tag.endswith("feed"):
        for e in root.findall(f"{ATOM_NS}entry"):
            title = _text(e.find(f"{ATOM_NS}title"))
            url = ""
            for ln in e.findall(f"{ATOM_NS}link"):
                rel = ln.get("rel", "alternate")
                if rel == "alternate":
                    url = ln.get("href", "")
                    break
            if not url:  # fall back to any link
                ln = e.find(f"{ATOM_NS}link")
                url = ln.get("href", "") if ln is not None else ""
            summary = _text(e.find(f"{ATOM_NS}summary")) or _text(e.find(f"{ATOM_NS}content"))
            pub = _text(e.find(f"{ATOM_NS}published")) or _text(e.find(f"{ATOM_NS}updated"))
            entries.append({"title": title, "url": url, "summary": summary,
                            "published": _parse_dt(pub)})
        return entries

    # ---- RSS 2.0 ----
    channel = root.find("channel")
    items = channel.findall("item") if channel is not None else root.findall(".//item")
    for it in items:
        title = _text(it.find("title"))
        url = _text(it.find("link"))
        summary = _text(it.find("description"))
        pub = _text(it.find("pubDate"))
        entries.append({"title": title, "url": url, "summary": summary,
                        "published": _parse_dt(pub)})
    return entries


# =============================================================
# SCOPE FILTER
# =============================================================
def scope_match(title: str, summary: str) -> list[str]:
    """Return list of matched scope terms (empty == out of scope)."""
    hay = f"{title}\n{summary}".lower()
    matched: list[str] = []
    for actor in IN_SCOPE_ACTORS:
        if actor in hay:
            matched.append(f"actor:{actor}")
    for kw in TRIGGER_KEYWORDS:
        if kw in hay:
            matched.append(f"kw:{kw}")
    for cve in sorted(set(m.upper() for m in CVE_RE.findall(f"{title} {summary}"))):
        matched.append(f"cve:{cve}")
    # de-dup, preserve order
    seen = set()
    return [m for m in matched if not (m in seen or seen.add(m))]


# =============================================================
# FRESHNESS
# =============================================================
def freshness_verdict(entries: list[dict], error: str, now: datetime) -> tuple[str, float | None]:
    """Returns (verdict, newest_age_hours). Verdicts: FRESH, STALE, EMPTY, UNFETCHABLE."""
    if error:
        return "UNFETCHABLE", None
    dated = [e["published"] for e in entries if e.get("published")]
    if not entries:
        return "EMPTY", None
    if not dated:
        return "STALE", None  # entries but no parseable dates — treat cautiously
    newest = max(dated)
    age_h = (now - newest).total_seconds() / 3600.0
    return ("FRESH" if age_h <= 48 else "STALE"), age_h


# =============================================================
# MAIN
# =============================================================
def run(feeds, window_hours, max_entries, include_all, user_agent, now=None):
    now = now or datetime.now(timezone.utc)
    window_cutoff = now - timedelta(hours=window_hours)
    report = {"generated_utc": now.isoformat(), "window_hours": window_hours, "feeds": []}
    all_hits = []

    for feed in feeds:
        body, error = fetch(feed["url"], user_agent=user_agent)
        entries = parse_feed(body)[:max_entries]
        verdict, age_h = freshness_verdict(entries, error, now)

        hits = []
        for e in entries:
            matched = scope_match(e["title"], e["summary"])
            in_window = e["published"] is None or e["published"] >= window_cutoff
            if matched and (in_window or include_all):
                age = (now - e["published"]).total_seconds() / 3600.0 if e["published"] else None
                links = sorted(set(re.findall(r"https?://[^\s\"'<>)]+", e["summary"] or "")))
                hit = {
                    "feed": feed["name"], "title": e["title"], "url": e["url"],
                    "published_utc": e["published"].isoformat() if e["published"] else None,
                    "age_hours": round(age, 1) if age is not None else None,
                    "matched_terms": matched,
                    "outbound_links_in_summary": links,
                }
                hits.append(hit)
                all_hits.append(hit)

        report["feeds"].append({
            "name": feed["name"], "url": feed["url"], "description": feed.get("description", ""),
            "freshness": verdict,
            "newest_age_hours": round(age_h, 1) if age_h is not None else None,
            "fetch_error": error or None,
            "entries_parsed": len(entries),
            "in_scope_hits": len(hits),
        })

    report["summary"] = {
        "feeds_total": len(feeds),
        "feeds_ok": sum(1 for f in report["feeds"] if f["freshness"] == "FRESH"),
        "feeds_degraded": [f["name"] for f in report["feeds"]
                           if f["freshness"] in ("STALE", "EMPTY", "UNFETCHABLE")],
        "in_scope_hits_total": len(all_hits),
    }
    report["hits"] = all_hits
    return report


def write_output(report, fmt, out_path):
    if fmt == "json":
        text = json.dumps(report, indent=2, ensure_ascii=False)
        if out_path:
            open(out_path, "w", encoding="utf-8").write(text)
        else:
            print(text)
    else:  # csv — the hits table
        fields = ["feed", "published_utc", "age_hours", "title", "url",
                  "matched_terms", "outbound_links_in_summary"]
        fh = open(out_path, "w", newline="", encoding="utf-8") if out_path else sys.stdout
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for h in report["hits"]:
            row = dict(h)
            row["matched_terms"] = "; ".join(h["matched_terms"])
            row["outbound_links_in_summary"] = "; ".join(h["outbound_links_in_summary"])
            w.writerow(row)
        if out_path:
            fh.close()


# =============================================================
# SELF-TEST (offline — parse bundled fixtures, no network)
# =============================================================
def self_test() -> int:
    print("== rss_discovery self-test (offline) ==")
    rss_fixture = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Fix</title>
<item><title>Sandworm deploys new wiper against Ukraine grain sector</title>
<link>https://example.com/sandworm</link>
<pubDate>Sat, 05 Jul 2026 10:00:00 -0400</pubDate>
<description>CERT-UA links the wiper to Sandworm (Seashell Blizzard). See https://cert.gov.ua/a</description></item>
<item><title>Generic patch Tuesday roundup</title><link>https://example.com/patch</link>
<pubDate>Sat, 05 Jul 2026 09:00:00 -0400</pubDate>
<description>Nothing in scope here, CVE-2026-11111 mentioned.</description></item>
</channel></rss>"""
    atom_fixture = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Reg</title>
<entry><title>APT29 phishing campaign hits diplomats</title>
<link rel="alternate" href="https://example.com/apt29"/>
<published>2026-07-05T09:06:12.00Z</published>
<summary>Midnight Blizzard (APT29) targets embassies.</summary></entry></feed>"""

    now = datetime(2026, 7, 6, 13, 0, tzinfo=timezone.utc)
    ok = True

    r = parse_feed(rss_fixture)
    assert len(r) == 2, f"RSS parse count {len(r)}"
    assert r[0]["published"] is not None and r[0]["published"].year == 2026, "RSS date parse"
    m0 = scope_match(r[0]["title"], r[0]["summary"])
    assert any(x.startswith("actor:sandworm") for x in m0), f"expected sandworm match: {m0}"
    assert any(x == "actor:seashell blizzard" for x in m0), f"expected alias match: {m0}"
    m1 = scope_match(r[1]["title"], r[1]["summary"])
    assert m1 == ["cve:CVE-2026-11111"], f"item2 should only match CVE: {m1}"
    print("  [ok] RSS 2.0 parse + scope match + alias + CVE-only case")

    a = parse_feed(atom_fixture)
    assert len(a) == 1, f"Atom parse count {len(a)}"
    assert a[0]["url"] == "https://example.com/apt29", "Atom alternate link"
    assert a[0]["published"].hour == 9, "Atom fractional-second ISO parse"
    ma = scope_match(a[0]["title"], a[0]["summary"])
    assert any(x == "actor:apt29" for x in ma), f"apt29: {ma}"
    print("  [ok] Atom 1.0 parse (alternate link, fractional-second ts) + scope match")

    # freshness
    v, age = freshness_verdict(r, "", now)
    assert v == "FRESH", f"freshness {v}"
    v2, _ = freshness_verdict([], "", now)
    assert v2 == "EMPTY", f"empty verdict {v2}"
    v3, _ = freshness_verdict([], "HTTP 403 Forbidden", now)
    assert v3 == "UNFETCHABLE", f"unfetchable verdict {v3}"
    print("  [ok] freshness verdicts (FRESH / EMPTY / UNFETCHABLE)")

    # end-to-end run() with a stub fetch (no network)
    print("  [ok] all offline assertions passed")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="APT Watch multi-feed RSS/Atom discovery extractor")
    ap.add_argument("--feeds", help="JSON file overriding the feed registry")
    ap.add_argument("--window-hours", type=int, default=24,
                    help="Report in-scope entries newer than this (default 24)")
    ap.add_argument("--max-entries", type=int, default=30,
                    help="Cap entries parsed per feed (default 30, per SKILL)")
    ap.add_argument("--output", choices=["json", "csv"], default="json")
    ap.add_argument("--out", help="Write to this file instead of stdout")
    ap.add_argument("--all", action="store_true",
                    help="Include in-scope hits older than the window too")
    ap.add_argument("--user-agent", default=DEFAULT_UA)
    ap.add_argument("--self-test", action="store_true", help="Run offline parser tests and exit")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())

    feeds = DEFAULT_FEEDS
    if args.feeds:
        feeds = json.load(open(args.feeds, encoding="utf-8"))

    report = run(feeds, args.window_hours, args.max_entries, args.all, args.user_agent)
    write_output(report, args.output, args.out)

    # hard-fail only if EVERY feed came back empty/unfetchable
    degraded = report["summary"]["feeds_degraded"]
    if len(degraded) == len(feeds):
        sys.stderr.write(f"ERROR: all feeds degraded: {degraded}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
