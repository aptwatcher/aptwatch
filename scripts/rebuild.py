#!/usr/bin/env python3
"""
Full rebuild of APT Intelligence Database (schema v2)
Wipes and recreates DB from all source files.

Usage:
    python database/rebuild_db.py              # Rebuild (backs up existing)
    python database/rebuild_db.py --no-backup  # Rebuild without backup
    python database/rebuild_db.py --skip-domains  # Skip 1.5M domain import (faster)
"""

import sqlite3
import csv
import json
import re
import ipaddress
import sys
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

# Paths
BASE_DIR = Path(__file__).parent.parent
DB_DIR = Path(__file__).parent.parent / 'database'
DB_PATH = DB_DIR / 'apt_intel.db'
SCHEMA_PATH = DB_DIR / 'schema_v2.sql'
IOCS_DIR = BASE_DIR / 'iocs'
REPORTS_DIR = BASE_DIR / 'reports'
SCANS_DIR = BASE_DIR / 'scans'

BATCH_SIZE = 10000


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def init_db():
    """Create fresh database from schema_v2.sql."""
    log("Initializing database from schema_v2.sql")
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(SCHEMA_PATH.read_text())
    log("Schema created")


def update_meta(conn, key, value):
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value, updated_at) VALUES (?, ?, ?)",
        (key, str(value), datetime.now().isoformat())
    )


# =============================================================
# IOC IMPORTERS
# =============================================================

def import_ipv4(conn):
    """Import IPv4 IOCs from iocs/ipv4.txt."""
    filepath = IOCS_DIR / 'ipv4.txt'
    if not filepath.exists():
        log("SKIP: ipv4.txt not found")
        return 0

    log("Importing IPv4 IOCs...")
    now = datetime.now().isoformat()
    count = 0
    batch = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            ip = line.strip()
            if not ip or ip.startswith('#'):
                continue
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            batch.append((ip, 'ipv4.txt', now, now))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT OR IGNORE INTO ipv4_iocs (ip, source_file, first_seen, last_seen) VALUES (?,?,?,?)",
                    batch
                )
                count += len(batch)
                batch.clear()

    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO ipv4_iocs (ip, source_file, first_seen, last_seen) VALUES (?,?,?,?)",
            batch
        )
        count += len(batch)

    conn.commit()
    log(f"  IPv4: {count} imported")
    update_meta(conn, 'ipv4_count', count)
    return count


def import_ipv6(conn):
    """Import IPv6 IOCs from iocs/ipv6.txt."""
    filepath = IOCS_DIR / 'ipv6.txt'
    if not filepath.exists():
        log("SKIP: ipv6.txt not found")
        return 0

    log("Importing IPv6 IOCs...")
    now = datetime.now().isoformat()
    count = 0
    batch = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            ip = line.strip()
            if not ip or ip.startswith('#'):
                continue
            try:
                ipaddress.IPv6Address(ip)
            except ValueError:
                continue
            batch.append((ip, 'ipv6.txt', now))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT OR IGNORE INTO ipv6_iocs (ip, source_file, first_seen) VALUES (?,?,?)",
                    batch
                )
                count += len(batch)
                batch.clear()

    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO ipv6_iocs (ip, source_file, first_seen) VALUES (?,?,?)",
            batch
        )
        count += len(batch)

    conn.commit()
    log(f"  IPv6: {count} imported")
    update_meta(conn, 'ipv6_count', count)
    return count


def import_domains(conn):
    """Import domain IOCs from iocs/domains.txt."""
    filepath = IOCS_DIR / 'domains.txt'
    if not filepath.exists():
        log("SKIP: domains.txt not found")
        return 0

    log("Importing domains (this may take a moment)...")
    now = datetime.now().isoformat()
    count = 0
    batch = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            domain = line.strip()
            if not domain or domain.startswith('#'):
                continue
            batch.append((domain, 'domains.txt', now))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT OR IGNORE INTO domains (domain, source_file, first_seen) VALUES (?,?,?)",
                    batch
                )
                conn.commit()
                count += len(batch)
                if count % 100000 == 0:
                    log(f"  Domains: {count:,} so far...")
                batch.clear()

    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO domains (domain, source_file, first_seen) VALUES (?,?,?)",
            batch
        )
        count += len(batch)

    conn.commit()
    log(f"  Domains: {count:,} imported")
    update_meta(conn, 'domain_count', count)
    return count


def import_urls(conn):
    """Import URL IOCs from iocs/urls.txt, extracting host/port/path."""
    filepath = IOCS_DIR / 'urls.txt'
    if not filepath.exists():
        log("SKIP: urls.txt not found")
        return 0

    log("Importing URLs...")
    now = datetime.now().isoformat()
    count = 0
    batch = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith('#'):
                continue

            # Parse host:port/path format or full URLs
            host, port, path = None, None, None
            if '://' in url:
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname
                    port = parsed.port
                    path = parsed.path or None
                except Exception:
                    pass
            else:
                # Format like 1.2.3.4:443/path
                match = re.match(r'^([^:/]+)(?::(\d+))?(/.*)?$', url)
                if match:
                    host = match.group(1)
                    port = int(match.group(2)) if match.group(2) else None
                    path = match.group(3)

            batch.append((url, host, port, path, 'urls.txt', now))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT OR IGNORE INTO urls (url, host, port, path, source_file, first_seen) VALUES (?,?,?,?,?,?)",
                    batch
                )
                conn.commit()
                count += len(batch)
                if count % 50000 == 0:
                    log(f"  URLs: {count:,} so far...")
                batch.clear()

    if batch:
        conn.executemany(
            "INSERT OR IGNORE INTO urls (url, host, port, path, source_file, first_seen) VALUES (?,?,?,?,?,?)",
            batch
        )
        count += len(batch)

    conn.commit()
    log(f"  URLs: {count:,} imported")
    update_meta(conn, 'url_count', count)
    return count


def import_cves(conn):
    """Import CVE identifiers from iocs/cves.txt."""
    filepath = IOCS_DIR / 'cves.txt'
    if not filepath.exists():
        log("SKIP: cves.txt not found")
        return 0

    log("Importing CVEs...")
    now = datetime.now().isoformat()
    count = 0

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            cve = line.strip().upper()
            if not cve or cve.startswith('#'):
                continue
            if not cve.startswith('CVE-'):
                cve = cve  # keep as-is
            conn.execute(
                "INSERT OR IGNORE INTO cves (cve_id, source_file, first_seen) VALUES (?,?,?)",
                (cve, 'cves.txt', now)
            )
            count += 1

    conn.commit()
    log(f"  CVEs: {count} imported")
    update_meta(conn, 'cve_count', count)
    return count


def import_emails(conn):
    """Import email IOCs from iocs/emails.txt."""
    filepath = IOCS_DIR / 'emails.txt'
    if not filepath.exists():
        log("SKIP: emails.txt not found")
        return 0

    log("Importing emails...")
    now = datetime.now().isoformat()
    count = 0

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            email = line.strip()
            if not email or email.startswith('#'):
                continue
            domain = email.split('@')[1] if '@' in email else None
            conn.execute(
                "INSERT OR IGNORE INTO emails (email, domain, source_file, first_seen) VALUES (?,?,?,?)",
                (email, domain, 'emails.txt', now)
            )
            count += 1

    conn.commit()
    log(f"  Emails: {count} imported")
    update_meta(conn, 'email_count', count)
    return count


def import_cidrs(conn):
    """Import CIDR IOCs from iocs/cidr.txt."""
    filepath = IOCS_DIR / 'cidr.txt'
    if not filepath.exists():
        log("SKIP: cidr.txt not found")
        return 0

    log("Importing CIDRs...")
    now = datetime.now().isoformat()
    count = 0

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            cidr = line.strip()
            if not cidr or cidr.startswith('#'):
                continue
            conn.execute(
                "INSERT OR IGNORE INTO cidr_iocs (cidr, source_file, first_seen) VALUES (?,?,?)",
                (cidr, 'cidr.txt', now)
            )
            count += 1

    conn.commit()
    log(f"  CIDRs: {count} imported")
    update_meta(conn, 'cidr_count', count)
    return count


# =============================================================
# SUBNET GENERATION
# =============================================================

def generate_subnets(conn):
    """Generate /24 subnet aggregations from IPv4 IOCs with tier classification."""
    log("Generating subnet aggregations...")

    rows = conn.execute("SELECT ip FROM ipv4_iocs").fetchall()
    subnet_counts = defaultdict(int)

    for (ip,) in rows:
        try:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            subnet_counts[str(net)] += 1
        except ValueError:
            continue

    count = 0
    for cidr, ioc_count in subnet_counts.items():
        if ioc_count >= 50:
            tier = 'TIER_S'
        elif ioc_count >= 20:
            tier = 'TIER_A'
        elif ioc_count >= 10:
            tier = 'TIER_B'
        elif ioc_count >= 5:
            tier = 'TIER_C'
        else:
            tier = None

        conn.execute(
            "INSERT OR REPLACE INTO subnets (cidr, ioc_count, tier, scan_status) VALUES (?,?,?,?)",
            (cidr, ioc_count, tier, 'UNSCANNED')
        )
        count += 1

    conn.commit()
    tiered = conn.execute("SELECT COUNT(*) FROM subnets WHERE tier IS NOT NULL").fetchone()[0]
    log(f"  Subnets: {count} generated ({tiered} with tier classification)")
    return count


# =============================================================
# SCAN RESULTS IMPORT
# =============================================================

def import_master_reports(conn):
    """Import C2-INFRASTRUCTURE-MASTER.txt and CRITICAL-TARGETS-MASTER.txt."""
    master_files = ['C2-INFRASTRUCTURE-MASTER.txt', 'CRITICAL-TARGETS-MASTER.txt']
    total = 0

    for filename in master_files:
        filepath = REPORTS_DIR / filename
        if not filepath.exists():
            log(f"SKIP: {filename} not found")
            continue

        log(f"Importing {filename}...")
        now = datetime.now().isoformat()
        count = 0

        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = [p.strip() for p in line.split('|')]

                if len(parts) >= 3:
                    ip = parts[0]
                    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        continue
                    risk_score = int(parts[1]) if parts[1].isdigit() else 0
                    services = parts[2] if len(parts) > 2 else ''
                else:
                    # Simple format: IP # comment
                    parts2 = line.split('#')
                    ip = parts2[0].strip()
                    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        continue
                    risk_score = 50
                    services = parts2[1].strip() if len(parts2) > 1 else ''

                # Classify
                if risk_score >= 500:
                    classification = 'CRITICAL'
                elif risk_score >= 200:
                    classification = 'HIGH'
                elif risk_score >= 100:
                    classification = 'MEDIUM'
                else:
                    classification = 'LOW'

                # Extract C2 indicators
                c2_keywords = ['gh0st_rat', 'empire', 'metasploit', 'custom_c2',
                               'back_orifice', 'cobalt_strike']
                c2_found = [kw for kw in c2_keywords if kw in services.lower()]

                conn.execute("""
                    INSERT INTO scan_results
                    (ip, scan_date, source_file, risk_score, classification, services, c2_indicators)
                    VALUES (?,?,?,?,?,?,?)
                """, (
                    ip, now, filename, risk_score, classification,
                    services, ','.join(c2_found) if c2_found else None
                ))
                count += 1

        conn.commit()
        log(f"  {filename}: {count} hosts")
        total += count

    return total


def import_apt_reports(conn):
    """Import detailed APT-TARGETS-*.md reports with ports, services, vulns."""
    apt_dir = REPORTS_DIR / 'apt-targets'
    if not apt_dir.exists():
        log("SKIP: reports/apt-targets/ not found")
        return 0

    report_files = list(apt_dir.glob('APT-TARGETS-*.md'))
    if not report_files:
        log("SKIP: No APT-TARGETS-*.md files found")
        return 0

    total = 0

    for report_file in report_files:
        log(f"Importing {report_file.name}...")

        with open(report_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Metadata
        scan_date_match = re.search(r'\*\*Generated:\*\* ([\d-]+ [\d:]+)', content)
        scan_date = scan_date_match.group(1) if scan_date_match else datetime.now().isoformat()
        scan_id = report_file.stem.replace('APT-TARGETS-', '')

        # Parse host blocks
        # Split on ### headers
        blocks = re.split(r'\n(?=### \d)', content)
        count = 0

        for block in blocks:
            header = re.search(r'### ([\d.]+) \(Risk Score: (\d+)\)', block)
            if not header:
                continue

            ip = header.group(1)
            risk_score = int(header.group(2))

            frameworks = re.search(r'\*\*C2 Frameworks:\*\* (.+)', block)
            lateral = re.search(r'\*\*Lateral Movement:\*\* (.+)', block)
            ports = re.search(r'\*\*Open Ports:\*\* (.+)', block)
            vulns = re.search(r'\*\*Vulnerabilities:\*\* (\d+)', block)
            indicators = re.findall(r'- Port signature: (.+)', block)

            c2_list = frameworks.group(1).strip().split(', ') if frameworks else []
            lateral_list = lateral.group(1).strip().split(', ') if lateral else []
            port_list = [p.strip() for p in ports.group(1).split(',')] if ports else []
            vuln_count = int(vulns.group(1)) if vulns else 0

            if risk_score >= 500:
                classification = 'CRITICAL'
            elif risk_score >= 200:
                classification = 'HIGH'
            elif risk_score >= 100:
                classification = 'MEDIUM'
            else:
                classification = 'LOW'

            conn.execute("""
                INSERT INTO scan_results
                (ip, scan_id, scan_date, source_file, risk_score, classification,
                 open_ports, services, vulnerabilities, vuln_count,
                 c2_indicators, lateral_movement, raw_data)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ip, scan_id, scan_date, report_file.name,
                risk_score, classification,
                json.dumps(port_list),
                json.dumps({'c2_frameworks': c2_list, 'lateral_movement': lateral_list}),
                json.dumps({'count': vuln_count}),
                vuln_count,
                json.dumps(c2_list),
                json.dumps(lateral_list),
                block[:2000]  # Truncate raw block
            ))
            count += 1

        conn.commit()
        log(f"  {report_file.name}: {count} hosts")
        total += count

    return total


# =============================================================
# VULNERABILITY SCAN CSV IMPORT
# =============================================================

def import_vulnscan_csvs(conn):
    """Import vulnerability scan results from scans/ directory."""
    csv_files = list(SCANS_DIR.glob('*.csv')) if SCANS_DIR.exists() else []

    if not csv_files:
        log("SKIP: No CSV files in scans/")
        return 0

    total = 0

    for csv_file in csv_files:
        log(f"Importing scan: {csv_file.name}...")
        count = 0
        batch = []

        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    batch.append((
                        int(row.get('Plugin ID', 0) or 0),
                        row.get('CVE', '') or None,
                        float(row.get('CVSS v2.0 Base Score', 0) or 0),
                        row.get('Risk', '') or None,
                        row.get('Host', '') or None,
                        row.get('Protocol', '') or None,
                        int(row.get('Port', 0) or 0),
                        row.get('Name', '') or None,
                        row.get('Synopsis', '') or None,
                        row.get('Solution', '') or None,
                        csv_file.name,
                        datetime.now().isoformat()
                    ))
                except (ValueError, TypeError):
                    continue

                if len(batch) >= BATCH_SIZE:
                    conn.executemany("""
                        INSERT INTO vulnerability_findings
                        (plugin_id, cve, cvss_score, risk, host, protocol, port,
                         plugin_name, synopsis, solution, source_file, scan_date)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """, batch)
                    count += len(batch)
                    batch.clear()

        if batch:
            conn.executemany("""
                INSERT INTO vulnerability_findings
                (plugin_id, cve, cvss_score, risk, host, protocol, port,
                 plugin_name, synopsis, solution, source_file, scan_date)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, batch)
            count += len(batch)

        conn.commit()
        log(f"  {csv_file.name}: {count} findings")
        total += count

    update_meta(conn, 'vulnerability_finding_count', total)
    return total


# =============================================================
# MAIN REBUILD
# =============================================================

def rebuild(skip_domains=False, no_backup=False):
    """Full database rebuild."""
    print("=" * 60)
    print("OTX RUSSIAN APT ANALYTICS — DATABASE REBUILD (v2)")
    print("=" * 60)
    print()

    # Backup
    if DB_PATH.exists() and not no_backup:
        backup = DB_PATH.with_suffix('.db.bak')
        shutil.copy2(DB_PATH, backup)
        log(f"Backed up existing DB to {backup.name}")

    # Delete and recreate
    if DB_PATH.exists():
        DB_PATH.unlink()

    init_db()

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    try:
        # 1. Import all IOC types
        log("\n--- PHASE 1: IOC IMPORT ---")
        import_ipv4(conn)
        import_ipv6(conn)
        if not skip_domains:
            import_domains(conn)
        else:
            log("SKIP: domains (--skip-domains)")
        import_urls(conn)
        import_cves(conn)
        import_emails(conn)
        import_cidrs(conn)

        # 2. Generate subnets
        log("\n--- PHASE 2: SUBNET GENERATION ---")
        generate_subnets(conn)

        # 3. Import scan results
        log("\n--- PHASE 3: SCAN RESULTS ---")
        master_count = import_master_reports(conn)
        apt_count = import_apt_reports(conn)
        update_meta(conn, 'scan_result_count', master_count + apt_count)

        # 4. Import vulnerability scan data
        log("\n--- PHASE 4: VULNERABILITY SCAN FINDINGS ---")
        import_vulnscan_csvs(conn)

        # 5. Update metadata
        update_meta(conn, 'last_rebuild', datetime.now().isoformat())
        update_meta(conn, 'schema_version', '2.0')
        conn.commit()

        # Print summary
        print()
        print("=" * 60)
        print("REBUILD COMPLETE — SUMMARY")
        print("=" * 60)

        tables = [
            'ipv4_iocs', 'ipv6_iocs', 'domains', 'urls', 'cves',
            'emails', 'cidr_iocs', 'subnets', 'scan_results', 'vulnerability_findings'
        ]
        for table in tables:
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  {table:20s}: {count:>12,}")

        # Scan classification breakdown
        print()
        print("Scan classifications:")
        for row in conn.execute(
            "SELECT classification, COUNT(*) FROM scan_results GROUP BY classification ORDER BY COUNT(*) DESC"
        ).fetchall():
            print(f"  {row[0] or 'NULL':12s}: {row[1]:,}")

        # Subnet tiers
        print()
        print("Subnet tiers:")
        for row in conn.execute(
            "SELECT COALESCE(tier, 'UNTIERED'), COUNT(*), SUM(ioc_count) FROM subnets GROUP BY tier ORDER BY tier"
        ).fetchall():
            print(f"  {row[0]:12s}: {row[1]:,} subnets, {row[2]:,} IOCs")

        print()
        print(f"Database: {DB_PATH}")
        print(f"Size: {DB_PATH.stat().st_size / 1024 / 1024:.1f} MB")

    finally:
        conn.close()


if __name__ == '__main__':
    skip_domains = '--skip-domains' in sys.argv
    no_backup = '--no-backup' in sys.argv
    rebuild(skip_domains=skip_domains, no_backup=no_backup)
