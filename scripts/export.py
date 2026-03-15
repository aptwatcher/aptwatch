#!/usr/bin/env python3
"""
Export a lightweight version of apt_intel.db for browser-based dashboard.
Builds a new DB from scratch, copying all tables EXCEPT the massive
domains (1.5M) and urls (254K) tables. Stores summary counts in metadata.

Usage:
    python database/export_web_db.py
    # Creates apt_intel_web.db (~5 MB) in the project root
"""

import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DB_PATH = Path(__file__).parent.parent / 'database' / 'apt_intel.db'
SCHEMA_PATH = Path(__file__).parent.parent / 'database' / 'schema_v2.sql'
WEB_DB_PATH = BASE_DIR / 'apt_intel_web.db'

# Tables to copy (excludes domains and urls)
COPY_TABLES = [
    'ipv4_iocs', 'ipv6_iocs', 'cves', 'emails', 'cidr_iocs',
    'subnets', 'asn_info', 'scan_results', 'vulnerability_findings',
    'scan_campaigns', 'scan_queue', 'ip_correlations', 'metadata',
    'recon_candidates', 'enrichment_results', 'staging_servers',
    'validation_queue'
]


def export():
    if not DB_PATH.exists():
        print(f"ERROR: {DB_PATH} not found. Run rebuild_db.py first.")
        return

    # Remove old export
    if WEB_DB_PATH.exists():
        WEB_DB_PATH.unlink()

    src = sqlite3.connect(str(DB_PATH))
    dst = sqlite3.connect(str(WEB_DB_PATH))

    # Create schema
    print("Creating web DB schema...")
    dst.executescript(SCHEMA_PATH.read_text())

    # Get domain/url counts from source
    domain_count = src.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
    url_count = src.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
    print(f"Source domains: {domain_count:,} (excluded from web DB)")
    print(f"Source urls: {url_count:,} (excluded from web DB)")

    # Copy each table (handle column mismatches between source and dest)
    for table in COPY_TABLES:
        try:
            src_cols = [desc[0] for desc in src.execute(f"SELECT * FROM {table} LIMIT 1").description]
            dst_cols = [desc[0] for desc in dst.execute(f"SELECT * FROM {table} LIMIT 1").description]

            # Use only columns that exist in BOTH source and dest
            common_cols = [c for c in src_cols if c in dst_cols]
            col_names = ','.join(common_cols)
            placeholders = ','.join(['?'] * len(common_cols))

            # For enrichment_results, truncate raw_data to save space in web DB
            if table == 'enrichment_results' and 'raw_data' in common_cols:
                select_cols = [f"SUBSTR({c},1,500)" if c == 'raw_data' else c for c in common_cols]
                rows = src.execute(f"SELECT {','.join(select_cols)} FROM {table}").fetchall()
            # For vulnerability_findings, strip synopsis/description to reduce size
            elif table == 'vulnerability_findings':
                strip = {'synopsis', 'description', 'solution', 'plugin_output'}
                select_cols = [f"SUBSTR({c},1,200)" if c in strip else c for c in common_cols]
                rows = src.execute(f"SELECT {','.join(select_cols)} FROM {table}").fetchall()
            else:
                rows = src.execute(f"SELECT {col_names} FROM {table}").fetchall()
            if not rows:
                continue

            # Clear target first (metadata has defaults from schema)
            if table == 'metadata':
                dst.execute(f"DELETE FROM {table}")

            dst.executemany(f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})", rows)
            dst.commit()
            extra = f" (skipped cols: {set(src_cols)-set(dst_cols)})" if set(src_cols) != set(dst_cols) else ""
            print(f"  {table}: {len(rows):,} rows{extra}")
        except Exception as e:
            print(f"  {table}: SKIP ({e})")

    # Store summary counts for domains/urls
    dst.execute("INSERT OR REPLACE INTO metadata (key,value,updated_at) VALUES ('web_domain_count',?,datetime('now'))", (str(domain_count),))
    dst.execute("INSERT OR REPLACE INTO metadata (key,value,updated_at) VALUES ('web_url_count',?,datetime('now'))", (str(url_count),))
    dst.execute("INSERT OR REPLACE INTO metadata (key,value,updated_at) VALUES ('web_export','true',datetime('now'))")

    # Drop the empty domain/url tables created by schema
    dst.execute("DROP TABLE IF EXISTS domains")
    dst.execute("DROP TABLE IF EXISTS urls")
    dst.commit()

    src.close()
    dst.close()

    size_mb = WEB_DB_PATH.stat().st_size / 1024 / 1024
    print(f"\nExported: {WEB_DB_PATH}")
    print(f"Size: {size_mb:.1f} MB")
    print("Load this file in apt_intel_dashboard.html for fast browsing.")


if __name__ == '__main__':
    export()
