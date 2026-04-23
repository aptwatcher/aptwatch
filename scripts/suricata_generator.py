#!/usr/bin/env python3
"""
APT Watch — Suricata Rule Auto-Generator (Phase 2b)
====================================================
Generates Suricata detection rules from campaign_iocs in the APT Intel DB.

Features:
  - Reads last SID from existing .rules files (auto-increment)
  - Templates per IOC type: IP, domain, hash (MD5/SHA1/SHA256), URL, email
  - Skips IOCs already covered in existing rule files
  - Groups rules by campaign with proper headers
  - Integrates with IOC collector pipeline (--from-yaml for YAML submissions)

Usage:
  # Generate from DB for all campaigns
  python3 suricata_generator.py --db /opt/apt-intel/database/apt_intel.db

  # Generate for specific campaign(s)
  python3 suricata_generator.py --db apt_intel.db --campaigns "Pawn Storm" "Gamaredon"

  # Generate from YAML submission files (local mode)
  python3 suricata_generator.py --from-yaml submissions/*.yaml

  # Dry-run (preview rules, don't write files)
  python3 suricata_generator.py --db apt_intel.db --dry-run

  # Custom output directory
  python3 suricata_generator.py --db apt_intel.db --output-dir /opt/apt-intel/repo/iocs/suricata/
"""

import argparse
import glob
import json
import os
import re
import sqlite3
import sys
from datetime import datetime

# ── Constants ──────────────────────────────────────────────────
DEFAULT_SURICATA_DIR = "apt-intel/repo/iocs/suricata"
SID_PATTERN = re.compile(r"sid:(\d+);")
DATE_TODAY = datetime.now().strftime("%Y_%m_%d")
DATE_ISO = datetime.now().strftime("%Y-%m-%d")

# IOC type → Suricata rule action mapping
IOC_TEMPLATES = {
    "ipv4": {
        "action": "alert ip",
        "header": '$HOME_NET any -> {value} any',
        "options": (
            'msg:"APTWATCH {actor} C2 IP {value}"; '
            'classtype:trojan-activity; '
            'sid:{sid}; rev:1; '
            'metadata:created_at {date}, actor {actor_meta}, campaign {campaign_meta}, mitre_attack T1071.001;'
        ),
    },
    "domain": {
        "action": "alert dns",
        "header": '$HOME_NET any -> any any',
        "options": (
            'msg:"APTWATCH {actor} C2 domain {value}"; '
            'dns.query; content:"{value}"; nocase; '
            'classtype:trojan-activity; '
            'sid:{sid}; rev:1; '
            'metadata:created_at {date}, actor {actor_meta}, campaign {campaign_meta};'
        ),
    },
    "sha256": {
        "action": "alert http",
        "header": '$HOME_NET any -> $EXTERNAL_NET any',
        "options": (
            'msg:"APTWATCH {actor} malware hash SHA256 {short_value}"; '
            'flow:established,to_server; '
            'filesha256:{value}; '
            'classtype:trojan-activity; '
            'sid:{sid}; rev:1; '
            'metadata:created_at {date}, actor {actor_meta}, campaign {campaign_meta};'
        ),
    },
    "sha1": {
        "action": "alert http",
        "header": '$HOME_NET any -> $EXTERNAL_NET any',
        "options": (
            'msg:"APTWATCH {actor} malware hash SHA1 {short_value}"; '
            'flow:established,to_server; '
            'filesha1:{value}; '
            'classtype:trojan-activity; '
            'sid:{sid}; rev:1; '
            'metadata:created_at {date}, actor {actor_meta}, campaign {campaign_meta};'
        ),
    },
    "md5": {
        "action": "alert http",
        "header": '$HOME_NET any -> $EXTERNAL_NET any',
        "options": (
            'msg:"APTWATCH {actor} malware hash MD5 {short_value}"; '
            'flow:established,to_server; '
            'filemd5:{value}; '
            'classtype:trojan-activity; '
            'sid:{sid}; rev:1; '
            'metadata:created_at {date}, actor {actor_meta}, campaign {campaign_meta};'
        ),
    },
    "url": {
        "action": "alert http",
        "header": '$HOME_NET any -> $EXTERNAL_NET any',
        "options": (
            'msg:"APTWATCH {actor} malicious URL {short_value}"; '
            'flow:established,to_server; '
            'http.uri; content:"{uri_path}"; nocase; '
            'classtype:trojan-activity; '
            'sid:{sid}; rev:1; '
            'metadata:created_at {date}, actor {actor_meta}, campaign {campaign_meta};'
        ),
    },
    "email": {
        "action": "alert smtp",
        "header": '$HOME_NET any -> $EXTERNAL_NET any',
        "options": (
            'msg:"APTWATCH {actor} phishing email {value}"; '
            'flow:established,to_server; '
            'content:"{value}"; nocase; '
            'classtype:trojan-activity; '
            'sid:{sid}; rev:1; '
            'metadata:created_at {date}, actor {actor_meta}, campaign {campaign_meta};'
        ),
    },
}

# Supported IOC types for rule generation
SUPPORTED_IOC_TYPES = set(IOC_TEMPLATES.keys())


def find_last_sid(suricata_dir):
    """Scan all .rules files and return the highest SID found."""
    max_sid = 0
    rules_files = glob.glob(os.path.join(suricata_dir, "*.rules"))
    for rf in rules_files:
        try:
            with open(rf, "r") as f:
                for line in f:
                    for m in SID_PATTERN.finditer(line):
                        sid = int(m.group(1))
                        if sid > max_sid:
                            max_sid = sid
        except Exception:
            pass
    return max_sid


def collect_existing_iocs(suricata_dir):
    """Collect all IOC values already in existing rules to avoid duplicates."""
    existing = set()
    ip_pattern = re.compile(r'-> ([\d.]+) any')
    domain_pattern = re.compile(r'content:"([^"]+)";\s*nocase;.*classtype')
    hash_pattern = re.compile(r'file(?:sha256|sha1|md5):([a-fA-F0-9]+);')

    rules_files = glob.glob(os.path.join(suricata_dir, "*.rules"))
    for rf in rules_files:
        try:
            with open(rf, "r") as f:
                for line in f:
                    if not line.startswith("alert"):
                        continue
                    # Extract IPs
                    m = ip_pattern.search(line)
                    if m and not m.group(1).startswith("$"):
                        existing.add(m.group(1))
                    # Extract domains
                    m = domain_pattern.search(line)
                    if m:
                        existing.add(m.group(1).lower())
                    # Extract hashes
                    m = hash_pattern.search(line)
                    if m:
                        existing.add(m.group(1).lower())
        except Exception:
            pass
    return existing


def normalize_ioc_type(raw_type):
    """Normalize IOC type strings from DB to our template keys."""
    raw = raw_type.lower().strip()
    mapping = {
        "ip": "ipv4", "ipv4": "ipv4", "ip_address": "ipv4", "ipv4_address": "ipv4",
        "domain": "domain", "domain_name": "domain", "fqdn": "domain",
        "sha256": "sha256", "sha-256": "sha256", "hash_sha256": "sha256",
        "sha1": "sha1", "sha-1": "sha1", "hash_sha1": "sha1",
        "md5": "md5", "hash_md5": "md5",
        "url": "url", "uri": "url",
        "email": "email", "email_address": "email",
    }
    return mapping.get(raw, raw)


def sanitize_filename(name):
    """Convert campaign name to safe filename."""
    return re.sub(r'[^a-z0-9_-]', '-', name.lower().strip()).strip('-')


def sanitize_meta(value):
    """Sanitize metadata values (no spaces in Suricata metadata)."""
    return re.sub(r'\s+', '_', value.strip())


def extract_uri_path(url):
    """Extract the path portion from a URL for content matching."""
    url = re.sub(r'^https?://', '', url)
    idx = url.find('/')
    if idx >= 0:
        return url[idx:]
    return "/" + url


def fetch_campaign_iocs(db_path, campaign_filter=None, min_confidence=0.3):
    """Fetch IOCs from campaign_iocs joined with campaigns."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    query = """
        SELECT
            c.campaign_name,
            c.aliases,
            ci.ioc_type,
            ci.ioc_value,
            ci.role,
            ci.confidence_score,
            ci.notes
        FROM campaign_iocs ci
        JOIN campaigns c ON ci.campaign_id = c.id
        WHERE ci.confidence_score >= ?
    """
    params = [min_confidence]

    if campaign_filter:
        placeholders = ','.join('?' * len(campaign_filter))
        query += f" AND c.campaign_name IN ({placeholders})"
        params.extend(campaign_filter)

    query += " ORDER BY c.campaign_name, ci.ioc_type, ci.ioc_value"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    # Group by campaign
    campaigns = {}
    for row in rows:
        name = row["campaign_name"]
        if name not in campaigns:
            campaigns[name] = {
                "aliases": row["aliases"] or "",
                "iocs": [],
            }
        campaigns[name]["iocs"].append({
            "type": row["ioc_type"],
            "value": row["ioc_value"],
            "role": row["role"] or "",
            "confidence": row["confidence_score"],
            "notes": row["notes"] or "",
        })

    return campaigns


def load_yaml_submissions(yaml_files):
    """Load IOCs from YAML submission files (local contributor mode)."""
    try:
        import yaml
    except ImportError:
        print("[!] PyYAML required for --from-yaml. Install: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    campaigns = {}
    for yf in yaml_files:
        try:
            with open(yf, "r") as f:
                data = yaml.safe_load(f)
            if not data:
                continue
            name = data.get("campaign", data.get("group", os.path.basename(yf).replace(".yaml", "")))
            if name not in campaigns:
                campaigns[name] = {"aliases": data.get("aliases", ""), "iocs": []}
            for ioc in data.get("iocs", []):
                campaigns[name]["iocs"].append({
                    "type": ioc.get("type", ""),
                    "value": ioc.get("value", ""),
                    "role": ioc.get("role", ""),
                    "confidence": ioc.get("confidence", 0.5),
                    "notes": ioc.get("notes", ""),
                })
        except Exception as e:
            print(f"[!] Error loading {yf}: {e}", file=sys.stderr)

    return campaigns


def generate_rule(template_key, value, actor, campaign, sid):
    """Generate a single Suricata rule line."""
    tmpl = IOC_TEMPLATES[template_key]
    actor_meta = sanitize_meta(actor)
    campaign_meta = sanitize_meta(campaign)

    # Short value for msg field (truncate hashes)
    short_value = value[:16] + "..." if len(value) > 20 else value

    # URI path for URL rules
    uri_path = extract_uri_path(value) if template_key == "url" else ""

    header = tmpl["header"].format(value=value)
    options = tmpl["options"].format(
        value=value,
        short_value=short_value,
        actor=actor,
        actor_meta=actor_meta,
        campaign=campaign,
        campaign_meta=campaign_meta,
        sid=sid,
        date=DATE_TODAY,
        uri_path=uri_path,
    )

    return f'{tmpl["action"]} {header} ({options})'


def generate_rules(campaigns, existing_iocs, next_sid, min_confidence=0.3):
    """Generate rules for all campaigns, returning dict of filename → rules list."""
    output = {}  # filename → {"header": str, "rules": list, "sid_start": int, "sid_end": int}
    sid = next_sid
    stats = {"total": 0, "skipped_existing": 0, "skipped_type": 0, "skipped_confidence": 0}

    for campaign_name, data in sorted(campaigns.items()):
        rules = []
        aliases = data["aliases"]

        # Determine actor name (first word of campaign or campaign itself)
        actor = campaign_name.split("/")[0].split("(")[0].strip()

        for ioc in data["iocs"]:
            ioc_type = normalize_ioc_type(ioc["type"])
            value = ioc["value"].strip()

            if not value:
                continue

            # Skip unsupported types
            if ioc_type not in SUPPORTED_IOC_TYPES:
                stats["skipped_type"] += 1
                continue

            # Skip low confidence
            if ioc.get("confidence", 0.5) < min_confidence:
                stats["skipped_confidence"] += 1
                continue

            # Skip already existing
            check_val = value.lower()
            if check_val in existing_iocs:
                stats["skipped_existing"] += 1
                continue

            # Generate rule
            rule = generate_rule(ioc_type, value, actor, campaign_name, sid)
            rules.append(rule)
            existing_iocs.add(check_val)  # Prevent intra-run duplicates
            sid += 1
            stats["total"] += 1

        if rules:
            filename = f"auto-{sanitize_filename(campaign_name)}.rules"
            header = (
                f"# {'=' * 70}\n"
                f"# APT Watch — Auto-Generated Suricata Rules\n"
                f"# Campaign: {campaign_name}\n"
            )
            if aliases:
                header += f"# Aliases: {aliases}\n"
            header += (
                f"# Generated: {DATE_ISO}\n"
                f"# Generator: suricata_generator.py (Phase 2b)\n"
                f"# {'=' * 70}\n"
            )

            if filename in output:
                output[filename]["rules"].extend(rules)
                output[filename]["sid_end"] = sid - 1
            else:
                output[filename] = {
                    "header": header,
                    "rules": rules,
                    "sid_start": rules[0].split("sid:")[1].split(";")[0] if rules else sid,
                    "sid_end": sid - 1,
                }

    return output, sid, stats


def write_rules(output, output_dir, dry_run=False):
    """Write rule files to disk."""
    written = []
    for filename, data in sorted(output.items()):
        filepath = os.path.join(output_dir, filename)
        content = data["header"] + "\n"
        # Group by IOC type (IP, DNS, hash, etc.)
        ip_rules = [r for r in data["rules"] if r.startswith("alert ip ")]
        dns_rules = [r for r in data["rules"] if r.startswith("alert dns ")]
        http_rules = [r for r in data["rules"] if r.startswith("alert http ")]
        smtp_rules = [r for r in data["rules"] if r.startswith("alert smtp ")]

        for label, group in [
            ("C2 IP Detection", ip_rules),
            ("DNS/Domain Detection", dns_rules),
            ("HTTP/Hash/URL Detection", http_rules),
            ("SMTP/Email Detection", smtp_rules),
        ]:
            if group:
                content += f"\n# --- {label} ---\n\n"
                for rule in group:
                    content += rule + "\n\n"

        content += (
            f"# {'=' * 70}\n"
            f"# Total Rules: {len(data['rules'])}\n"
            f"# SID Range: {data['sid_start']} - {data['sid_end']}\n"
            f"# {'=' * 70}\n"
        )

        if dry_run:
            print(f"\n{'─' * 60}")
            print(f"[DRY-RUN] Would write: {filepath}")
            print(f"  Rules: {len(data['rules'])}")
            print(f"  SID range: {data['sid_start']} - {data['sid_end']}")
            # Show first 3 rules as preview
            for r in data["rules"][:3]:
                print(f"  │ {r[:120]}...")
            if len(data["rules"]) > 3:
                print(f"  │ ... +{len(data['rules']) - 3} more")
        else:
            os.makedirs(output_dir, exist_ok=True)
            with open(filepath, "w") as f:
                f.write(content)
            written.append(filepath)
            print(f"[+] Written: {filepath} ({len(data['rules'])} rules)")

    return written


def update_sid_tracker(next_sid, output_dir):
    """Write .last_sid file for pipeline integration."""
    sid_file = os.path.join(output_dir, ".last_sid")
    with open(sid_file, "w") as f:
        f.write(str(next_sid))
    return sid_file


def main():
    parser = argparse.ArgumentParser(
        description="APT Watch — Suricata Rule Auto-Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db", help="Path to apt_intel.db")
    parser.add_argument("--from-yaml", nargs="+", help="YAML submission files (local mode)")
    parser.add_argument("--campaigns", nargs="+", help="Filter specific campaigns")
    parser.add_argument("--output-dir", default=DEFAULT_SURICATA_DIR,
                        help=f"Output directory (default: {DEFAULT_SURICATA_DIR})")
    parser.add_argument("--suricata-dir", default=None,
                        help="Existing rules directory to scan for SID/dedup (default: same as --output-dir)")
    parser.add_argument("--min-confidence", type=float, default=0.3,
                        help="Minimum confidence_score to include (default: 0.3)")
    parser.add_argument("--dry-run", action="store_true", help="Preview rules without writing")
    parser.add_argument("--json-report", help="Write generation report as JSON")

    args = parser.parse_args()

    if not args.db and not args.from_yaml:
        parser.error("Either --db or --from-yaml is required")

    suricata_dir = args.suricata_dir or args.output_dir

    # ── Step 1: Find last SID ──────────────────────────────────
    print(f"[*] Scanning existing rules in: {suricata_dir}")
    last_sid = find_last_sid(suricata_dir)
    if last_sid == 0:
        # Fallback to known range from TODO.md
        last_sid = 2026033412
        print(f"[*] No existing rules found, using fallback SID: {last_sid}")
    else:
        print(f"[*] Last SID found: {last_sid}")
    next_sid = last_sid + 1
    print(f"[*] Next SID: {next_sid}")

    # ── Step 2: Collect existing IOCs ──────────────────────────
    existing_iocs = collect_existing_iocs(suricata_dir)
    print(f"[*] Existing IOCs in rules: {len(existing_iocs)}")

    # ── Step 3: Load IOCs ──────────────────────────────────────
    if args.db:
        print(f"[*] Loading IOCs from DB: {args.db}")
        campaigns = fetch_campaign_iocs(args.db, args.campaigns, args.min_confidence)
    else:
        print(f"[*] Loading IOCs from YAML submissions")
        expanded = []
        for pattern in args.from_yaml:
            expanded.extend(glob.glob(pattern))
        campaigns = load_yaml_submissions(expanded)

    total_iocs = sum(len(d["iocs"]) for d in campaigns.values())
    print(f"[*] Loaded {total_iocs} IOCs across {len(campaigns)} campaigns")

    if not campaigns:
        print("[!] No campaigns found. Exiting.")
        sys.exit(0)

    # ── Step 4: Generate rules ─────────────────────────────────
    output, final_sid, stats = generate_rules(campaigns, existing_iocs, next_sid, args.min_confidence)

    # ── Step 5: Write output ───────────────────────────────────
    if output:
        written = write_rules(output, args.output_dir, args.dry_run)
        if not args.dry_run and written:
            sid_file = update_sid_tracker(final_sid, args.output_dir)
            print(f"[*] SID tracker updated: {sid_file} (next: {final_sid})")
    else:
        print("[*] No new rules to generate (all IOCs already covered or filtered).")

    # ── Summary ────────────────────────────────────────────────
    print(f"\n{'═' * 50}")
    print(f"  SURICATA GENERATION SUMMARY")
    print(f"{'═' * 50}")
    print(f"  New rules generated:    {stats['total']}")
    print(f"  Skipped (existing):     {stats['skipped_existing']}")
    print(f"  Skipped (unsupported):  {stats['skipped_type']}")
    print(f"  Skipped (confidence):   {stats['skipped_confidence']}")
    print(f"  SID range:              {next_sid} - {final_sid - 1 if final_sid > next_sid else 'N/A'}")
    print(f"  Files:                  {len(output)}")
    print(f"{'═' * 50}")

    # ── Optional JSON report ───────────────────────────────────
    if args.json_report:
        report = {
            "generated_at": DATE_ISO,
            "stats": stats,
            "sid_range": {"start": next_sid, "end": final_sid - 1},
            "files": {fn: {"rules": len(d["rules"]), "sid_start": d["sid_start"], "sid_end": d["sid_end"]}
                      for fn, d in output.items()},
        }
        with open(args.json_report, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] JSON report: {args.json_report}")


if __name__ == "__main__":
    main()
