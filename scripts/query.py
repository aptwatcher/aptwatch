#!/usr/bin/env python3
"""
Database query utilities for APT intelligence analysis (schema v2)

Usage:
    python database/query.py coverage              # Scan coverage by tier
    python database/query.py critical [limit]      # Top critical IPs
    python database/query.py unscanned [tier]      # Unscanned priority targets
    python database/query.py search <ip_pattern>   # Search IP across all tables
    python database/query.py domains <pattern>     # Search domain IOCs
    python database/query.py cves                  # List all CVEs
    python database/query.py vulnscan <ip>           # Vulnerability findings for IP
    python database/query.py stats                 # Full database statistics
    python database/query.py ip <ip>               # Full profile for a single IP
"""

import sqlite3
import json
from pathlib import Path
import sys

DB_PATH = Path(__file__).parent.parent / 'database' / 'apt_intel.db'


def get_connection():
    if not DB_PATH.exists():
        print(f"ERROR: Database not found at {DB_PATH}")
        print("Run rebuild_db.py first.")
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =============================================================
# EXISTING QUERIES (preserved)
# =============================================================

def get_unscanned_priority_targets(tier=None, limit=None):
    with get_connection() as conn:
        query = """
            SELECT cidr, ioc_count, tier, scanned_count, critical_count, scan_status
            FROM subnets
            WHERE scan_status IN ('UNSCANNED', 'PARTIAL')
        """
        params = []
        if tier:
            query += " AND tier = ?"
            params.append(tier)
        query += """ ORDER BY CASE tier
            WHEN 'TIER_S' THEN 1 WHEN 'TIER_A' THEN 2
            WHEN 'TIER_B' THEN 3 WHEN 'TIER_C' THEN 4
            ELSE 5 END, ioc_count DESC"""
        if limit:
            query += f" LIMIT {limit}"
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def get_subnet_details(cidr):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM subnets WHERE cidr = ?", (cidr,)).fetchone()
        if not row:
            return None
        subnet = dict(row)
        prefix = cidr.rsplit('.', 1)[0]

        subnet['iocs'] = [dict(r) for r in conn.execute(
            "SELECT ip, pulse_count, first_seen, last_seen FROM ipv4_iocs WHERE ip LIKE ? || '%' ORDER BY pulse_count DESC",
            (prefix,)
        ).fetchall()]

        subnet['scan_results'] = [dict(r) for r in conn.execute(
            "SELECT ip, risk_score, classification, scan_date FROM scan_results WHERE ip LIKE ? || '%' ORDER BY risk_score DESC",
            (prefix,)
        ).fetchall()]
        return subnet


def get_top_critical_ips(limit=20):
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT sr.ip, sr.risk_score, sr.classification, sr.services,
                   sr.c2_indicators, sr.open_ports, sr.vuln_count, sr.source_file,
                   i.pulse_count
            FROM scan_results sr
            LEFT JOIN ipv4_iocs i ON sr.ip = i.ip
            WHERE sr.classification = 'CRITICAL'
            ORDER BY sr.risk_score DESC
            LIMIT ?
        """, (limit,)).fetchall()]


def get_coverage_stats():
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT tier, COUNT(*) as total_subnets,
                SUM(CASE WHEN scan_status = 'UNSCANNED' THEN 1 ELSE 0 END) as unscanned,
                SUM(CASE WHEN scan_status = 'PARTIAL' THEN 1 ELSE 0 END) as partial,
                SUM(CASE WHEN scan_status = 'COMPLETE' THEN 1 ELSE 0 END) as complete,
                SUM(ioc_count) as total_iocs,
                SUM(scanned_count) as total_scanned,
                SUM(critical_count) as total_critical
            FROM subnets WHERE tier IS NOT NULL
            GROUP BY tier
            ORDER BY CASE tier
                WHEN 'TIER_S' THEN 1 WHEN 'TIER_A' THEN 2
                WHEN 'TIER_B' THEN 3 WHEN 'TIER_C' THEN 4
                ELSE 5 END
        """).fetchall()]


def search_ip(pattern):
    with get_connection() as conn:
        results = {}
        results['ipv4_iocs'] = [dict(r) for r in conn.execute(
            "SELECT * FROM ipv4_iocs WHERE ip LIKE ?", (f"%{pattern}%",)
        ).fetchall()]
        results['scan_results'] = [dict(r) for r in conn.execute(
            "SELECT ip, risk_score, classification, services, c2_indicators, source_file FROM scan_results WHERE ip LIKE ? ORDER BY risk_score DESC",
            (f"%{pattern}%",)
        ).fetchall()]
        results['vulnfindings'] = [dict(r) for r in conn.execute(
            "SELECT host, risk, plugin_name, cve, cvss_score, port FROM vulnerability_findings WHERE host LIKE ? ORDER BY cvss_score DESC LIMIT 20",
            (f"%{pattern}%",)
        ).fetchall()]
        return results


# =============================================================
# NEW QUERIES (v2)
# =============================================================

def search_domains(pattern):
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT domain, source_file, first_seen FROM domains WHERE domain LIKE ? LIMIT 50",
            (f"%{pattern}%",)
        ).fetchall()]


def list_cves():
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT cve_id, source_file, first_seen FROM cves ORDER BY cve_id"
        ).fetchall()]


def get_vulnfindings_for_ip(ip):
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT plugin_id, cve, cvss_score, risk, port, protocol,
                   plugin_name, synopsis, solution, source_file
            FROM vulnerability_findings WHERE host = ?
            ORDER BY cvss_score DESC
        """, (ip,)).fetchall()]


def get_ip_profile(ip):
    """Get complete profile for a single IP across all tables."""
    with get_connection() as conn:
        profile = {'ip': ip}

        # IPv4 IOC
        row = conn.execute("SELECT * FROM ipv4_iocs WHERE ip = ?", (ip,)).fetchone()
        profile['ioc'] = dict(row) if row else None

        # Scan results
        profile['scans'] = [dict(r) for r in conn.execute(
            "SELECT * FROM scan_results WHERE ip = ? ORDER BY risk_score DESC", (ip,)
        ).fetchall()]

        # Vulnerability findings
        profile['vulnfindings'] = [dict(r) for r in conn.execute(
            "SELECT plugin_id, cve, cvss_score, risk, port, plugin_name FROM vulnerability_findings WHERE host = ? ORDER BY cvss_score DESC",
            (ip,)
        ).fetchall()]

        # URL IOCs referencing this IP
        profile['urls'] = [dict(r) for r in conn.execute(
            "SELECT url FROM urls WHERE host = ? LIMIT 20", (ip,)
        ).fetchall()]

        # Subnet
        try:
            import ipaddress
            net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            row = conn.execute("SELECT * FROM subnets WHERE cidr = ?", (net,)).fetchone()
            profile['subnet'] = dict(row) if row else None
        except Exception:
            profile['subnet'] = None

        return profile


def get_full_stats():
    with get_connection() as conn:
        stats = {}
        tables = [
            'ipv4_iocs', 'ipv6_iocs', 'domains', 'urls', 'cves',
            'emails', 'cidr_iocs', 'subnets', 'scan_results', 'vulnerability_findings',
            'asn_info', 'scan_campaigns', 'scan_queue', 'ip_correlations'
        ]
        for t in tables:
            try:
                stats[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            except Exception:
                stats[t] = 'N/A'

        # Classification breakdown
        stats['classifications'] = {r[0]: r[1] for r in conn.execute(
            "SELECT classification, COUNT(*) FROM scan_results GROUP BY classification"
        ).fetchall()}

        # Tier breakdown
        stats['tiers'] = {r[0] or 'UNTIERED': r[1] for r in conn.execute(
            "SELECT tier, COUNT(*) FROM subnets GROUP BY tier"
        ).fetchall()}

        # Metadata
        stats['metadata'] = {r[0]: r[1] for r in conn.execute(
            "SELECT key, value FROM metadata"
        ).fetchall()}

        return stats


# =============================================================
# CLI
# =============================================================

def generate_scan_targets(tier=None, exclude_scanned=True, output_file=None):
    targets = get_unscanned_priority_targets(tier=tier)
    if exclude_scanned:
        targets = [t for t in targets if t['scan_status'] == 'UNSCANNED']
    if output_file:
        with open(output_file, 'w') as f:
            f.write(f"# Scan targets - {tier or 'ALL'}\n")
            f.write(f"# Total: {len(targets)} subnets\n\n")
            for t in targets:
                f.write(f"{t['cidr']:20} # {t['ioc_count']} IOCs, {t['tier']}\n")
        print(f"Wrote {len(targets)} targets to {output_file}")
    return targets


USAGE = """
Usage: python query.py <command> [args]

Commands:
  stats                  Full database statistics
  coverage               Scan coverage by tier
  critical [limit]       Top critical IPs (default: 20)
  unscanned [tier]       Unscanned priority targets
  search <ip_pattern>    Search IP across all tables
  ip <ip_address>        Full profile for a single IP
  domains <pattern>      Search domain IOCs
  cves                   List all tracked CVEs
  vulnscan <ip>            Vulnerability findings for an IP
"""

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'stats':
        stats = get_full_stats()
        print("\nDatabase Statistics (schema v2)")
        print("=" * 50)
        for table, count in {k: v for k, v in stats.items() if k not in ('classifications', 'tiers', 'metadata')}.items():
            print(f"  {table:20s}: {count:>12,}" if isinstance(count, int) else f"  {table:20s}: {count}")
        print("\nClassifications:")
        for c, n in sorted(stats['classifications'].items()):
            print(f"  {c or 'NULL':12s}: {n:,}")
        print("\nSubnet tiers:")
        for t, n in sorted(stats['tiers'].items()):
            print(f"  {t:12s}: {n:,}")
        print(f"\nSchema: v{stats['metadata'].get('schema_version', '?')}")
        print(f"Last rebuild: {stats['metadata'].get('last_rebuild', 'never')}")

    elif cmd == 'coverage':
        stats = get_coverage_stats()
        print("\nScan coverage by tier:\n")
        for s in stats:
            pct = (s['total_scanned'] / s['total_iocs'] * 100) if s['total_iocs'] > 0 else 0
            print(f"  {s['tier']:10} : {s['total_subnets']} subnets, {s['unscanned']} unscanned, {pct:.0f}% coverage")

    elif cmd == 'critical':
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        ips = get_top_critical_ips(limit)
        print(f"\nTop {limit} critical IPs:\n")
        for d in ips:
            svc = d.get('services') or ''
            if len(svc) > 40:
                svc = svc[:40] + '...'
            print(f"  {d['ip']:15} Risk:{d['risk_score']:4}  IOCs:{d.get('pulse_count') or 0:2}  {svc}")

    elif cmd == 'unscanned':
        tier = sys.argv[2] if len(sys.argv) > 2 else None
        targets = get_unscanned_priority_targets(tier=tier, limit=20)
        print(f"\nTop unscanned targets ({tier or 'ALL'}):\n")
        for t in targets:
            print(f"  {t['cidr']:20} - {t['ioc_count']:3} IOCs - {t['tier']}")

    elif cmd == 'search' and len(sys.argv) >= 3:
        pattern = sys.argv[2]
        results = search_ip(pattern)
        print(f"\nSearch: {pattern}\n")
        if results['ipv4_iocs']:
            print(f"IPv4 IOCs: {len(results['ipv4_iocs'])}")
            for r in results['ipv4_iocs'][:5]:
                print(f"  {r['ip']} (pulses: {r.get('pulse_count', 0)})")
        if results['scan_results']:
            print(f"\nScan results: {len(results['scan_results'])}")
            for r in results['scan_results'][:5]:
                print(f"  {r['ip']} - {r['classification']} - Risk: {r['risk_score']}")
        if results['vulnfindings']:
            print(f"\nVulnerability findings: {len(results['vulnfindings'])}")
            for r in results['vulnfindings'][:5]:
                print(f"  {r['host']}:{r['port']} - {r['risk']} - {r['plugin_name']}")

    elif cmd == 'ip' and len(sys.argv) >= 3:
        profile = get_ip_profile(sys.argv[2])
        print(f"\nIP Profile: {profile['ip']}")
        print("=" * 50)
        if profile['ioc']:
            print(f"IOC: Yes (pulses: {profile['ioc'].get('pulse_count', 0)})")
        else:
            print("IOC: No")
        if profile['scans']:
            print(f"\nScan results ({len(profile['scans'])}):")
            for s in profile['scans']:
                print(f"  {s['classification']} Risk:{s['risk_score']} Source:{s.get('source_file','?')}")
                if s.get('open_ports'):
                    print(f"    Ports: {s['open_ports']}")
                if s.get('c2_indicators'):
                    print(f"    C2: {s['c2_indicators']}")
        if profile['vulnfindings']:
            print(f"\nVulnerability findings ({len(profile['vulnfindings'])}):")
            for n in profile['vulnfindings'][:10]:
                print(f"  Port:{n['port']} CVSS:{n['cvss_score']} {n['risk']} - {n['plugin_name']}")
        if profile['urls']:
            print(f"\nURL IOCs ({len(profile['urls'])}):")
            for u in profile['urls']:
                print(f"  {u['url']}")
        if profile['subnet']:
            s = profile['subnet']
            print(f"\nSubnet: {s['cidr']} ({s['ioc_count']} IOCs, tier: {s.get('tier','none')})")

    elif cmd == 'domains' and len(sys.argv) >= 3:
        results = search_domains(sys.argv[2])
        print(f"\nDomain search: {sys.argv[2]} ({len(results)} results)\n")
        for r in results:
            print(f"  {r['domain']}")

    elif cmd == 'cves':
        cves = list_cves()
        print(f"\nTracked CVEs ({len(cves)}):\n")
        for c in cves:
            print(f"  {c['cve_id']}")

    elif cmd == 'vulnscan' and len(sys.argv) >= 3:
        findings = get_vulnfindings_for_ip(sys.argv[2])
        print(f"\nVulnerability findings for {sys.argv[2]} ({len(findings)} total):\n")
        for f in findings[:30]:
            cve_str = f" [{f['cve']}]" if f['cve'] else ""
            print(f"  {f['risk']:8} CVSS:{f['cvss_score']:4}  Port:{f['port']:5}/{f['protocol']}  {f['plugin_name']}{cve_str}")

    else:
        print(USAGE)
        sys.exit(1)
