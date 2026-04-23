#!/usr/bin/env python3
"""
db_health_check.py — APT Watch database health check, safelist validation,
and false-positive detection.

Checks:
  1. General stats (table counts, DB size)
  2. Orphan detection (campaign_iocs pointing to missing campaigns, etc.)
  3. Duplicate detection (same IOC in multiple places)
  4. Safelist validation (are any safelisted IPs/domains in campaign_iocs or ipv4_iocs?)
  5. Auto FP candidates (IPs appearing in 5+ different campaigns)
  6. Cross-campaign IOC overlap (legitimate shared infra vs duplicates)
  7. Missing indexes check
  8. Stale data detection (old lifecycle_state, unvalidated IOCs)

Usage:
    python3 db_health_check.py --db /opt/apt-intel/database/apt_intel.db
                               [--safelist server/scripts/safelist.yaml]
                               [--fix]  # Apply recommended fixes (add indexes, etc.)

Dependencies: pyyaml
"""

import argparse
import sqlite3
import os
import yaml
from datetime import datetime, timezone
from pathlib import Path

NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_safelist(path):
    """Load safelist.yaml and return structured data."""
    if not os.path.exists(path):
        print(f"  ⚠ Safelist not found: {path}")
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def run_check(db_path, safelist_path, fix=False):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    issues = []
    fixes_applied = []

    # ═══════════════════════════════════════════════════════════════
    # 1. GENERAL STATS
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  1. GENERAL STATS")
    print(f"{'═'*60}")

    db_size = os.path.getsize(db_path) / (1024 * 1024)
    print(f"  Database size: {db_size:.1f} MB")

    tables = [
        "ipv4_iocs", "ipv6_iocs", "domain_iocs", "url_iocs", "email_iocs",
        "hash_iocs", "cve_iocs", "scan_results", "campaigns", "campaign_iocs",
        "threat_actors", "hosting_providers", "ip_correlations", "cert_patterns",
        "subnets", "asn_info", "staging_servers", "validation_queue",
        "source_validations", "recon_candidates", "scan_campaigns",
    ]

    for t in tables:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            cnt = cur.fetchone()[0]
            if cnt > 0:
                print(f"  {t}: {cnt:,}")
        except sqlite3.OperationalError:
            pass  # Table doesn't exist

    # ═══════════════════════════════════════════════════════════════
    # 2. ORPHAN DETECTION
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  2. ORPHAN DETECTION")
    print(f"{'═'*60}")

    # campaign_iocs → campaigns
    try:
        cur.execute("""
            SELECT ci.id, ci.ioc_value, ci.campaign_id
            FROM campaign_iocs ci
            LEFT JOIN campaigns c ON ci.campaign_id = c.id
            WHERE c.id IS NULL
        """)
        orphans = cur.fetchall()
        if orphans:
            print(f"  ⚠ {len(orphans)} campaign_iocs with missing campaign:")
            for o in orphans[:10]:
                print(f"    ID {o['id']}: ioc={o['ioc_value']}, campaign_id={o['campaign_id']}")
            issues.append(f"{len(orphans)} orphan campaign_iocs")
        else:
            print(f"  ✓ No orphan campaign_iocs")
    except sqlite3.OperationalError as e:
        print(f"  Skip: {e}")

    # scan_results with NULL scan_id
    try:
        cur.execute("SELECT COUNT(*) FROM scan_results WHERE scan_id IS NULL")
        null_scans = cur.fetchone()[0]
        if null_scans:
            print(f"  ⚠ {null_scans:,} scan_results with NULL scan_id")
            issues.append(f"{null_scans} scan_results with NULL scan_id")
        else:
            print(f"  ✓ All scan_results have scan_id")
    except sqlite3.OperationalError:
        pass

    # ═══════════════════════════════════════════════════════════════
    # 3. DUPLICATE DETECTION
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  3. DUPLICATE DETECTION")
    print(f"{'═'*60}")

    # Duplicate IPs in ipv4_iocs
    cur.execute("SELECT ip, COUNT(*) as cnt FROM ipv4_iocs GROUP BY ip HAVING cnt > 1")
    dupes = cur.fetchall()
    if dupes:
        print(f"  ⚠ {len(dupes)} duplicate IPs in ipv4_iocs:")
        for d in dupes[:10]:
            print(f"    {d['ip']}: {d['cnt']}x")
        issues.append(f"{len(dupes)} duplicate IPs in ipv4_iocs")
    else:
        print(f"  ✓ No duplicate IPs in ipv4_iocs")

    # Duplicate campaigns by name
    cur.execute("SELECT campaign_name, COUNT(*) as cnt FROM campaigns GROUP BY campaign_name HAVING cnt > 1")
    camp_dupes = cur.fetchall()
    if camp_dupes:
        print(f"  ⚠ {len(camp_dupes)} duplicate campaign names:")
        for d in camp_dupes:
            print(f"    '{d['campaign_name']}': {d['cnt']}x")
        issues.append(f"{len(camp_dupes)} duplicate campaign names")
    else:
        print(f"  ✓ No duplicate campaign names")

    # Duplicate campaign_iocs (same ioc_value + campaign_id)
    cur.execute("""
        SELECT ioc_value, campaign_id, COUNT(*) as cnt
        FROM campaign_iocs GROUP BY ioc_value, campaign_id HAVING cnt > 1
    """)
    ci_dupes = cur.fetchall()
    if ci_dupes:
        print(f"  ⚠ {len(ci_dupes)} duplicate campaign_ioc entries:")
        for d in ci_dupes[:10]:
            print(f"    {d['ioc_value']} in campaign {d['campaign_id']}: {d['cnt']}x")
        issues.append(f"{len(ci_dupes)} duplicate campaign_iocs")
    else:
        print(f"  ✓ No duplicate campaign_iocs")

    # Duplicate threat actors
    cur.execute("SELECT name, COUNT(*) as cnt FROM threat_actors GROUP BY name HAVING cnt > 1")
    ta_dupes = cur.fetchall()
    if ta_dupes:
        print(f"  ⚠ {len(ta_dupes)} duplicate threat actor names:")
        for d in ta_dupes:
            print(f"    '{d['name']}': {d['cnt']}x")
        issues.append(f"{len(ta_dupes)} duplicate threat actors")
    else:
        print(f"  ✓ No duplicate threat actors")

    # ═══════════════════════════════════════════════════════════════
    # 4. SAFELIST VALIDATION
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  4. SAFELIST VALIDATION")
    print(f"{'═'*60}")

    safelist = load_safelist(safelist_path)
    if safelist:
        safe_ips = set(safelist.get("ips", []))
        safe_domains = set(safelist.get("domains", []))
        safe_ranges = safelist.get("ip_ranges", [])
        safe_patterns = safelist.get("domain_patterns", [])

        # Check safelisted IPs in ipv4_iocs
        fp_ips_iocs = []
        if safe_ips:
            placeholders = ",".join(["?" for _ in safe_ips])
            cur.execute(f"SELECT ip, composite_score, lifecycle_state FROM ipv4_iocs WHERE ip IN ({placeholders})",
                        list(safe_ips))
            fp_ips_iocs = cur.fetchall()

        # Check safelisted IPs in campaign_iocs
        fp_ips_camp = []
        if safe_ips:
            cur.execute(f"""
                SELECT ci.ioc_value, c.campaign_name, ci.confidence_score
                FROM campaign_iocs ci JOIN campaigns c ON ci.campaign_id = c.id
                WHERE ci.ioc_type = 'ipv4' AND ci.ioc_value IN ({placeholders})
            """, list(safe_ips))
            fp_ips_camp = cur.fetchall()

        # Check private/reserved ranges in ipv4_iocs
        fp_ranges = []
        for rng in safe_ranges:
            cur.execute("SELECT ip FROM ipv4_iocs WHERE ip LIKE ?", (f"{rng}%",))
            rows = cur.fetchall()
            for r in rows:
                fp_ranges.append({"ip": r["ip"], "range": rng})

        # Check safelisted domains in domain_iocs
        fp_domains = []
        if safe_domains:
            placeholders = ",".join(["?" for _ in safe_domains])
            try:
                cur.execute(f"SELECT domain FROM domain_iocs WHERE domain IN ({placeholders})",
                            list(safe_domains))
                fp_domains = cur.fetchall()
            except sqlite3.OperationalError:
                pass

        # Check domain patterns
        fp_domain_patterns = []
        for pat in safe_patterns:
            try:
                cur.execute("SELECT domain FROM domain_iocs WHERE domain LIKE ?", (f"%{pat}%",))
                rows = cur.fetchall()
                for r in rows:
                    fp_domain_patterns.append({"domain": r["domain"], "pattern": pat})
            except sqlite3.OperationalError:
                break  # No domain_iocs table

        # Report
        if fp_ips_iocs:
            print(f"  ⚠ {len(fp_ips_iocs)} safelisted IPs found in ipv4_iocs:")
            for r in fp_ips_iocs:
                print(f"    {r['ip']} (score={r['composite_score']}, state={r['lifecycle_state']})")
            issues.append(f"{len(fp_ips_iocs)} safelisted IPs in ipv4_iocs")
        else:
            print(f"  ✓ No safelisted IPs in ipv4_iocs")

        if fp_ips_camp:
            print(f"  ⚠ {len(fp_ips_camp)} safelisted IPs found in campaign_iocs:")
            for r in fp_ips_camp:
                print(f"    {r['ioc_value']} → campaign '{r['campaign_name']}' (conf={r['confidence_score']})")
            issues.append(f"{len(fp_ips_camp)} safelisted IPs in campaign_iocs")
        else:
            print(f"  ✓ No safelisted IPs in campaign_iocs")

        if fp_ranges:
            print(f"  ⚠ {len(fp_ranges)} private/reserved IPs found in ipv4_iocs:")
            for r in fp_ranges[:15]:
                print(f"    {r['ip']} (matches range {r['range']})")
            issues.append(f"{len(fp_ranges)} private/reserved IPs in ipv4_iocs")
        else:
            print(f"  ✓ No private/reserved IPs in ipv4_iocs")

        if fp_domains:
            print(f"  ⚠ {len(fp_domains)} safelisted domains in domain_iocs:")
            for r in fp_domains[:15]:
                print(f"    {r['domain']}")
            issues.append(f"{len(fp_domains)} safelisted domains in domain_iocs")
        else:
            print(f"  ✓ No safelisted domains in domain_iocs")

        if fp_domain_patterns:
            print(f"  ⚠ {len(fp_domain_patterns)} pattern-matched domains in domain_iocs:")
            for r in fp_domain_patterns[:15]:
                print(f"    {r['domain']} (pattern: {r['pattern']})")
            issues.append(f"{len(fp_domain_patterns)} pattern-matched FP domains")
        else:
            print(f"  ✓ No pattern-matched FP domains in domain_iocs")
    else:
        print(f"  Skipped — no safelist loaded")

    # ═══════════════════════════════════════════════════════════════
    # 5. AUTO FP CANDIDATES (IPs in 5+ campaigns)
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  5. AUTO FP CANDIDATES (IOCs in 5+ campaigns)")
    print(f"{'═'*60}")

    cur.execute("""
        SELECT ci.ioc_value, COUNT(DISTINCT ci.campaign_id) as camp_count,
               GROUP_CONCAT(DISTINCT c.campaign_name) as campaigns
        FROM campaign_iocs ci
        JOIN campaigns c ON ci.campaign_id = c.id
        WHERE ci.ioc_type IN ('ipv4', 'domain')
        GROUP BY ci.ioc_value
        HAVING camp_count >= 5
        ORDER BY camp_count DESC
    """)
    fp_candidates = cur.fetchall()
    if fp_candidates:
        print(f"  ⚠ {len(fp_candidates)} IOCs appear in 5+ campaigns (potential FP or shared infra):")
        for r in fp_candidates[:20]:
            print(f"    {r['ioc_value']} → {r['camp_count']} campaigns: {r['campaigns'][:80]}")
        issues.append(f"{len(fp_candidates)} IOCs in 5+ campaigns (review needed)")
    else:
        print(f"  ✓ No IOCs in 5+ campaigns")

    # Also check 3-4 campaigns for awareness
    cur.execute("""
        SELECT ci.ioc_value, COUNT(DISTINCT ci.campaign_id) as camp_count,
               GROUP_CONCAT(DISTINCT c.campaign_name) as campaigns
        FROM campaign_iocs ci
        JOIN campaigns c ON ci.campaign_id = c.id
        WHERE ci.ioc_type IN ('ipv4', 'domain')
        GROUP BY ci.ioc_value
        HAVING camp_count BETWEEN 3 AND 4
        ORDER BY camp_count DESC
    """)
    shared = cur.fetchall()
    if shared:
        print(f"\n  ℹ {len(shared)} IOCs in 3-4 campaigns (likely shared infra, not FP):")
        for r in shared[:15]:
            print(f"    {r['ioc_value']} → {r['camp_count']} campaigns: {r['campaigns'][:80]}")

    # ═══════════════════════════════════════════════════════════════
    # 6. CROSS-CAMPAIGN IOC OVERLAP
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  6. CROSS-CAMPAIGN IOC OVERLAP")
    print(f"{'═'*60}")

    cur.execute("""
        SELECT ci.ioc_value, ci.ioc_type, COUNT(DISTINCT ci.campaign_id) as cnt,
               GROUP_CONCAT(DISTINCT c.campaign_name) as campaigns
        FROM campaign_iocs ci
        JOIN campaigns c ON ci.campaign_id = c.id
        GROUP BY ci.ioc_value, ci.ioc_type
        HAVING cnt > 1
        ORDER BY cnt DESC
        LIMIT 25
    """)
    overlaps = cur.fetchall()
    if overlaps:
        print(f"  {len(overlaps)} IOCs shared across campaigns (top 25):")
        for r in overlaps:
            print(f"    [{r['ioc_type']}] {r['ioc_value']} → {r['cnt']} campaigns: {r['campaigns'][:80]}")
    else:
        print(f"  No cross-campaign IOC overlap")

    # ═══════════════════════════════════════════════════════════════
    # 7. MISSING INDEXES
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  7. INDEX CHECK")
    print(f"{'═'*60}")

    cur.execute("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name")
    existing_indexes = {r["name"] for r in cur.fetchall()}

    recommended = {
        "idx_campaign_iocs_value": "CREATE INDEX IF NOT EXISTS idx_campaign_iocs_value ON campaign_iocs(ioc_value)",
        "idx_campaign_iocs_campaign": "CREATE INDEX IF NOT EXISTS idx_campaign_iocs_campaign ON campaign_iocs(campaign_id)",
        "idx_scan_results_ip": "CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip)",
        "idx_scan_results_class": "CREATE INDEX IF NOT EXISTS idx_scan_results_class ON scan_results(classification)",
        "idx_ip_correlations_ip1": "CREATE INDEX IF NOT EXISTS idx_ip_correlations_ip1 ON ip_correlations(ip1)",
        "idx_ip_correlations_ip2": "CREATE INDEX IF NOT EXISTS idx_ip_correlations_ip2 ON ip_correlations(ip2)",
        "idx_staging_servers_ip": "CREATE INDEX IF NOT EXISTS idx_staging_servers_ip ON staging_servers(ip)",
    }

    missing = {k: v for k, v in recommended.items() if k not in existing_indexes}
    if missing:
        print(f"  ⚠ {len(missing)} recommended indexes missing:")
        for name, sql in missing.items():
            print(f"    {name}")
            if fix:
                cur.execute(sql)
                fixes_applied.append(f"Created index {name}")
                print(f"      → Created")
        issues.append(f"{len(missing)} missing indexes")
    else:
        print(f"  ✓ All recommended indexes present")

    print(f"\n  Existing indexes: {len(existing_indexes)}")

    # ═══════════════════════════════════════════════════════════════
    # 8. STALE DATA
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  8. DATA QUALITY")
    print(f"{'═'*60}")

    # Unvalidated IOCs
    cur.execute("SELECT COUNT(*) FROM ipv4_iocs WHERE validation_status = 'unvalidated'")
    unvalidated = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM ipv4_iocs")
    total_ipv4 = cur.fetchone()[0]
    pct = (unvalidated / total_ipv4 * 100) if total_ipv4 else 0
    print(f"  Unvalidated IOCs: {unvalidated:,} / {total_ipv4:,} ({pct:.1f}%)")

    # Lifecycle distribution
    cur.execute("SELECT lifecycle_state, COUNT(*) as cnt FROM ipv4_iocs GROUP BY lifecycle_state ORDER BY cnt DESC")
    print(f"\n  Lifecycle distribution:")
    for r in cur.fetchall():
        print(f"    {r['lifecycle_state'] or 'NULL'}: {r['cnt']:,}")

    # Score distribution
    cur.execute("""
        SELECT
            SUM(CASE WHEN composite_score >= 0.8 THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN composite_score >= 0.5 AND composite_score < 0.8 THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN composite_score > 0 AND composite_score < 0.5 THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN composite_score = 0 THEN 1 ELSE 0 END) as unscored
        FROM ipv4_iocs
    """)
    scores = cur.fetchone()
    print(f"\n  Composite score distribution:")
    print(f"    Critical (≥0.8): {scores['critical']:,}")
    print(f"    High (0.5-0.8):  {scores['high']:,}")
    print(f"    Medium (>0):     {scores['medium']:,}")
    print(f"    Unscored (0):    {scores['unscored']:,}")

    # Scan results classification
    cur.execute("SELECT classification, COUNT(*) as cnt FROM scan_results GROUP BY classification ORDER BY cnt DESC")
    print(f"\n  Scan results by classification:")
    for r in cur.fetchall():
        print(f"    {r['classification'] or 'NULL'}: {r['cnt']:,}")

    # Reports coverage check — sources
    print(f"\n  Data sources in campaign_iocs:")
    cur.execute("""
        SELECT c.campaign_name, COUNT(ci.id) as ioc_count
        FROM campaigns c
        LEFT JOIN campaign_iocs ci ON c.id = ci.campaign_id
        GROUP BY c.id
        ORDER BY ioc_count DESC
    """)
    for r in cur.fetchall():
        print(f"    {r['campaign_name']}: {r['ioc_count']} IOCs")

    # ═══════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'═'*60}")
    print(f"  SUMMARY")
    print(f"{'═'*60}")

    if issues:
        print(f"\n  ⚠ {len(issues)} issues found:")
        for i, issue in enumerate(issues, 1):
            print(f"    {i}. {issue}")
    else:
        print(f"\n  ✓ No issues found — database is healthy")

    if fixes_applied:
        print(f"\n  Fixes applied:")
        for f in fixes_applied:
            print(f"    ✓ {f}")
        conn.commit()

    conn.close()
    return issues


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APT Watch DB health check")
    parser.add_argument("--db", default="apt-intel/database/apt_intel.db")
    parser.add_argument("--safelist", default="apt-intel/server/scripts/safelist.yaml")
    parser.add_argument("--fix", action="store_true", help="Apply recommended fixes (indexes)")
    args = parser.parse_args()
    run_check(args.db, args.safelist, args.fix)
