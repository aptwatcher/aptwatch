#!/usr/bin/env python3
"""
Incremental importer for APT Intelligence Database (schema v2)
Add new data without wiping the database.

Usage:
    python database/import_incremental.py iocs                     # Re-import all IOC files
    python database/import_incremental.py ipv4 path/to/new_ips.txt # Import new IPv4 list
    python database/import_incremental.py domains path/to/file.txt # Import new domains
    python database/import_incremental.py vulnscan path/to/scan.csv  # Import vulnerability scan CSV
    python database/import_incremental.py apt-report path/to/APT-TARGETS-xxx.md
    python database/import_incremental.py master path/to/C2-xxx.txt
    python database/import_incremental.py stats                    # Show current counts
"""

import sqlite3
import csv
import json
import re
import ipaddress
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

BASE_DIR = Path(__file__).parent.parent
DB_PATH = Path(__file__).parent.parent / 'database' / 'apt_intel.db'
IOCS_DIR = BASE_DIR / 'iocs'
BATCH_SIZE = 10000


def get_conn():
    if not DB_PATH.exists():
        print(f"ERROR: Database not found at {DB_PATH}")
        print("Run rebuild_db.py first.")
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    # Track imported files to avoid re-processing
    conn.execute("""
        CREATE TABLE IF NOT EXISTS imported_files (
            filepath TEXT PRIMARY KEY,
            file_size INTEGER,
            file_mtime TEXT,
            imported_at TEXT,
            record_count INTEGER
        )
    """)
    return conn


def _file_signature(filepath):
    """Get file size + mtime as a change signature."""
    p = Path(filepath)
    stat = p.stat()
    return stat.st_size, datetime.fromtimestamp(stat.st_mtime).isoformat()


def is_already_imported(conn, filepath):
    """Check if a file has already been imported (same size + mtime)."""
    p = Path(filepath).resolve()
    size, mtime = _file_signature(p)
    row = conn.execute(
        "SELECT file_size, file_mtime FROM imported_files WHERE filepath=?",
        (str(p),)
    ).fetchone()
    if row and row[0] == size and row[1] == mtime:
        return True
    return False


def mark_imported(conn, filepath, record_count):
    """Record that a file has been imported."""
    p = Path(filepath).resolve()
    size, mtime = _file_signature(p)
    conn.execute("""
        INSERT OR REPLACE INTO imported_files (filepath, file_size, file_mtime, imported_at, record_count)
        VALUES (?, ?, ?, ?, ?)
    """, (str(p), size, mtime, datetime.now().isoformat(), record_count))
    conn.commit()


def update_meta(conn, key, value):
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value, updated_at) VALUES (?,?,?)",
        (key, str(value), datetime.now().isoformat())
    )


def cmd_stats():
    """Show current database counts."""
    conn = get_conn()
    tables = [
        'ipv4_iocs', 'ipv6_iocs', 'domains', 'urls', 'cves',
        'emails', 'cidr_iocs', 'subnets', 'scan_results', 'vulnerability_findings'
    ]
    print("Database statistics:")
    for t in tables:
        c = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"  {t:20s}: {c:>12,}")
    conn.close()


def cmd_import_ipv4(filepath):
    """Import IPv4 addresses from a text file."""
    conn = get_conn()
    now = datetime.now().isoformat()
    source = Path(filepath).name
    added = 0

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        batch = []
        for line in f:
            ip = line.strip()
            if not ip or ip.startswith('#'):
                continue
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            batch.append((ip, source, now, now))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT OR IGNORE INTO ipv4_iocs (ip, source_file, first_seen, last_seen) VALUES (?,?,?,?)",
                    batch
                )
                added += len(batch)
                batch.clear()
        if batch:
            conn.executemany(
                "INSERT OR IGNORE INTO ipv4_iocs (ip, source_file, first_seen, last_seen) VALUES (?,?,?,?)",
                batch
            )
            added += len(batch)

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM ipv4_iocs").fetchone()[0]
    update_meta(conn, 'ipv4_count', total)
    update_meta(conn, 'last_incremental', now)
    conn.close()
    print(f"Processed {added} IPs from {source} (total IPv4: {total:,})")


def cmd_import_domains(filepath):
    """Import domains from a text file."""
    conn = get_conn()
    now = datetime.now().isoformat()
    source = Path(filepath).name
    added = 0

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        batch = []
        for line in f:
            domain = line.strip()
            if not domain or domain.startswith('#'):
                continue
            batch.append((domain, source, now))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT OR IGNORE INTO domains (domain, source_file, first_seen) VALUES (?,?,?)",
                    batch
                )
                conn.commit()
                added += len(batch)
                batch.clear()
        if batch:
            conn.executemany(
                "INSERT OR IGNORE INTO domains (domain, source_file, first_seen) VALUES (?,?,?)",
                batch
            )
            added += len(batch)

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
    update_meta(conn, 'domain_count', total)
    update_meta(conn, 'last_incremental', now)
    conn.close()
    print(f"Processed {added} domains from {source} (total: {total:,})")


def cmd_import_vulnscan(filepath):
    """Import a vulnerability scan CSV file (skips if already imported and unchanged)."""
    conn = get_conn()

    if is_already_imported(conn, filepath):
        print(f"  SKIP {Path(filepath).name}: already imported (unchanged)")
        conn.close()
        return

    now = datetime.now().isoformat()
    source = Path(filepath).name
    count = 0

    # Delete previous import of this file to avoid duplicates on re-import
    conn.execute("DELETE FROM vulnerability_findings WHERE source_file=?", (source,))

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        batch = []
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
                    source, now
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
    mark_imported(conn, filepath, count)
    total = conn.execute("SELECT COUNT(*) FROM vulnerability_findings").fetchone()[0]
    update_meta(conn, 'vulnerability_finding_count', total)
    update_meta(conn, 'last_incremental', now)
    conn.close()
    print(f"Imported {count} vulnerability findings from {source} (total: {total:,})")


def cmd_import_apt_report(filepath):
    """Import an APT-TARGETS-*.md report (skips if already imported and unchanged)."""
    conn = get_conn()

    if is_already_imported(conn, filepath):
        print(f"  SKIP {Path(filepath).name}: already imported (unchanged)")
        conn.close()
        return

    now = datetime.now().isoformat()
    filepath = Path(filepath)

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    scan_date_match = re.search(r'\*\*Generated:\*\* ([\d-]+ [\d:]+)', content)
    scan_date = scan_date_match.group(1) if scan_date_match else now
    scan_id = filepath.stem.replace('APT-TARGETS-', '')

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

        # Check if already exists
        existing = conn.execute(
            "SELECT id FROM scan_results WHERE ip = ? AND scan_id = ?",
            (ip, scan_id)
        ).fetchone()

        if existing:
            conn.execute("""
                UPDATE scan_results SET risk_score=?, classification=?, open_ports=?,
                services=?, vulnerabilities=?, vuln_count=?, c2_indicators=?,
                lateral_movement=? WHERE id=?
            """, (
                risk_score, classification, json.dumps(port_list),
                json.dumps({'c2_frameworks': c2_list, 'lateral_movement': lateral_list}),
                json.dumps({'count': vuln_count}), vuln_count,
                json.dumps(c2_list), json.dumps(lateral_list), existing[0]
            ))
        else:
            conn.execute("""
                INSERT INTO scan_results
                (ip, scan_id, scan_date, source_file, risk_score, classification,
                 open_ports, services, vulnerabilities, vuln_count,
                 c2_indicators, lateral_movement)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ip, scan_id, scan_date, filepath.name,
                risk_score, classification,
                json.dumps(port_list),
                json.dumps({'c2_frameworks': c2_list, 'lateral_movement': lateral_list}),
                json.dumps({'count': vuln_count}), vuln_count,
                json.dumps(c2_list), json.dumps(lateral_list)
            ))
        count += 1

    conn.commit()
    mark_imported(conn, filepath, count)
    total = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
    update_meta(conn, 'scan_result_count', total)
    update_meta(conn, 'last_incremental', now)
    conn.close()
    print(f"Imported {count} hosts from {filepath.name} (total scan_results: {total:,})")


def cmd_import_master(filepath):
    """Import a master report (C2-INFRASTRUCTURE or CRITICAL-TARGETS format).
    Skips if already imported and unchanged."""
    conn = get_conn()

    if is_already_imported(conn, filepath):
        print(f"  SKIP {Path(filepath).name}: already imported (unchanged)")
        conn.close()
        return

    now = datetime.now().isoformat()
    source = Path(filepath).name
    count = 0

    # Delete previous import of this file to avoid duplicates on re-import
    conn.execute("DELETE FROM scan_results WHERE source_file=? AND scan_id IS NULL", (source,))

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
                services = parts[2]
            else:
                parts2 = line.split('#')
                ip = parts2[0].strip()
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    continue
                risk_score = 50
                services = parts2[1].strip() if len(parts2) > 1 else ''

            if risk_score >= 500:
                classification = 'CRITICAL'
            elif risk_score >= 200:
                classification = 'HIGH'
            elif risk_score >= 100:
                classification = 'MEDIUM'
            else:
                classification = 'LOW'

            c2_keywords = ['gh0st_rat', 'empire', 'metasploit', 'custom_c2',
                           'back_orifice', 'cobalt_strike']
            c2_found = [kw for kw in c2_keywords if kw in services.lower()]

            conn.execute("""
                INSERT INTO scan_results
                (ip, scan_date, source_file, risk_score, classification, services, c2_indicators)
                VALUES (?,?,?,?,?,?,?)
            """, (ip, now, source, risk_score, classification,
                  services, ','.join(c2_found) if c2_found else None))
            count += 1

    conn.commit()
    mark_imported(conn, filepath, count)
    total = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
    update_meta(conn, 'scan_result_count', total)
    update_meta(conn, 'last_incremental', now)
    conn.close()
    print(f"Imported {count} hosts from {source} (total scan_results: {total:,})")


def cmd_import_urls(filepath):
    """Import URLs from a text file."""
    conn = get_conn()
    now = datetime.now().isoformat()
    source = Path(filepath).name
    added = 0

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        batch = []
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith('#'):
                continue
            # Normalize defanged notation for parsing
            clean = raw.replace('[.]', '.').replace('hxxp', 'http')
            try:
                parsed = urlparse(clean)
                host = parsed.hostname or ''
                port = parsed.port
                path = parsed.path or '/'
            except Exception:
                host, port, path = '', None, '/'
            batch.append((raw, host, port, path, source, now))
            if len(batch) >= BATCH_SIZE:
                conn.executemany(
                    "INSERT OR IGNORE INTO urls (url, host, port, path, source_file, first_seen) VALUES (?,?,?,?,?,?)",
                    batch
                )
                added += len(batch)
                batch.clear()
        if batch:
            conn.executemany(
                "INSERT OR IGNORE INTO urls (url, host, port, path, source_file, first_seen) VALUES (?,?,?,?,?,?)",
                batch
            )
            added += len(batch)

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
    update_meta(conn, 'url_count', total)
    update_meta(conn, 'last_incremental', now)
    conn.close()
    print(f"Processed {added} URLs from {source} (total URLs: {total:,})")


def cmd_import_all_iocs():
    """Re-import all IOC files from iocs/ directory."""
    files = {
        'ipv4.txt': cmd_import_ipv4,
        'domains.txt': cmd_import_domains,
        'urls.txt': cmd_import_urls,
    }
    for fname, func in files.items():
        fp = IOCS_DIR / fname
        if fp.exists():
            func(str(fp))

    # Handle smaller files inline
    conn = get_conn()
    now = datetime.now().isoformat()

    for fname, table, field in [
        ('ipv6.txt', 'ipv6_iocs', 'ip'),
        ('cves.txt', 'cves', 'cve_id'),
        ('emails.txt', 'emails', 'email'),
        ('cidr.txt', 'cidr_iocs', 'cidr'),
    ]:
        fp = IOCS_DIR / fname
        if not fp.exists():
            continue
        count = 0
        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                val = line.strip()
                if val.startswith('cve-'):
                    val = val.upper()
                if not val or val.startswith('#'):
                    continue
                extra = ""
                if table == 'emails':
                    domain = val.split('@')[1] if '@' in val else None
                    conn.execute(
                        f"INSERT OR IGNORE INTO {table} ({field}, domain, source_file, first_seen) VALUES (?,?,?,?)",
                        (val, domain, fname, now)
                    )
                else:
                    conn.execute(
                        f"INSERT OR IGNORE INTO {table} ({field}, source_file, first_seen) VALUES (?,?,?)",
                        (val, fname, now)
                    )
                count += 1
        conn.commit()
        print(f"  {fname}: {count} processed")

    conn.close()


def cmd_migrate_v3():
    """Apply schema v3 migration (scoring, lifecycle, attribution, STIX)."""
    migration_path = BASE_DIR / 'database' / 'schema_v3_migration.sql'
    if not migration_path.exists():
        print(f"ERROR: Migration file not found at {migration_path}")
        sys.exit(1)

    conn = get_conn()
    # Check if already migrated
    row = conn.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
    if row and row[0] == '3.0':
        print("Database already at schema v3. Skipping migration.")
        conn.close()
        return

    print("Applying schema v3 migration...")
    sql = migration_path.read_text()

    # Phase 1: ALTER TABLE statements first (add columns before indexes reference them)
    # Phase 2: Everything else (CREATE TABLE, CREATE INDEX, INSERT, UPDATE, PRAGMA)
    alter_statements = []
    other_lines = []

    for line in sql.split('\n'):
        stripped = line.strip().upper()
        if stripped.startswith('ALTER TABLE'):
            alter_statements.append(line.strip())
        else:
            other_lines.append(line)

    # 1) Run ALTER TABLE individually (ignore duplicate column on re-run)
    for stmt in alter_statements:
        try:
            conn.execute(stmt)
        except Exception as e:
            if 'duplicate column' not in str(e).lower():
                print(f"  ALTER: {e}")
    conn.commit()
    print(f"  Applied {len(alter_statements)} ALTER TABLE statements")

    # 2) Run everything else via executescript (handles multi-line CREATE TABLE etc.)
    other_sql = '\n'.join(other_lines)
    try:
        conn.executescript(other_sql)
        print("  Created new tables, indexes, and seed data")
    except Exception as e:
        print(f"  Warning during table creation: {e}")

    conn.commit()
    print("Schema v3 migration applied successfully.")
    conn.close()


def cmd_score_all():
    """Run composite scoring on all IOCs (v3)."""
    try:
        from scoring import batch_score_all
        conn = get_conn()
        limit = int(sys.argv[2]) if len(sys.argv) >= 3 else 5000
        count = batch_score_all(conn, limit=limit)
        print(f"Scored {count} IOCs")
        conn.close()
    except ImportError:
        print("ERROR: scoring.py not found in scripts/")
        sys.exit(1)


def cmd_lifecycle():
    """Run lifecycle assessment on all IOCs (v3)."""
    try:
        from lifecycle import batch_assess_all
        conn = get_conn()
        limit = int(sys.argv[2]) if len(sys.argv) >= 3 else None
        stats = batch_assess_all(conn, limit=limit)
        print(f"Lifecycle: {stats}")
        conn.close()
    except ImportError:
        print("ERROR: lifecycle.py not found in scripts/")
        sys.exit(1)


def cmd_classify_asns():
    """Classify ASNs and populate cloud ranges (v3)."""
    try:
        from fp_suppression import classify_all_asns, populate_cloud_ranges
        conn = get_conn()
        cr = populate_cloud_ranges(conn)
        print(f"Cloud ranges: {cr} inserted")
        ca = classify_all_asns(conn)
        print(f"ASNs classified: {ca}")
        conn.close()
    except ImportError:
        print("ERROR: fp_suppression.py not found in scripts/")
        sys.exit(1)


USAGE = """
Usage: python import_incremental.py <command> [args]

Commands:
  stats                          Show database counts
  iocs                           Re-import all IOC files from iocs/
  ipv4 <file>                    Import IPv4 list
  domains <file>                 Import domain list
  urls <file>                    Import URL list
  vulnscan <file.csv>            Import vulnerability scan CSV
  apt-report <APT-TARGETS-*.md>  Import APT report
  master <C2-*.txt>              Import master report

  migrate-v3                     Apply schema v3 migration
  score [limit]                  Recalculate composite scores (v3)
  lifecycle [limit]              Run lifecycle assessment (v3)
  classify-asns                  Classify ASNs + populate cloud ranges (v3)
"""

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'stats':
        cmd_stats()
    elif cmd == 'iocs':
        cmd_import_all_iocs()
    elif cmd == 'ipv4' and len(sys.argv) >= 3:
        cmd_import_ipv4(sys.argv[2])
    elif cmd == 'domains' and len(sys.argv) >= 3:
        cmd_import_domains(sys.argv[2])
    elif cmd == 'urls' and len(sys.argv) >= 3:
        cmd_import_urls(sys.argv[2])
    elif cmd == 'vulnscan' and len(sys.argv) >= 3:
        cmd_import_vulnscan(sys.argv[2])
    elif cmd == 'apt-report' and len(sys.argv) >= 3:
        cmd_import_apt_report(sys.argv[2])
    elif cmd == 'master' and len(sys.argv) >= 3:
        cmd_import_master(sys.argv[2])
    elif cmd == 'migrate-v3':
        cmd_migrate_v3()
    elif cmd == 'score':
        cmd_score_all()
    elif cmd == 'lifecycle':
        cmd_lifecycle()
    elif cmd == 'classify-asns':
        cmd_classify_asns()
    else:
        print(USAGE)
        sys.exit(1)
