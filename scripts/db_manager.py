#!/usr/bin/env python3
"""
Database initialization and management for OTX Russian APT Analytics
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent.parent / 'database' / 'apt_intel.db'
SCHEMA_PATH = Path(__file__).parent.parent / 'database' / 'schema.sql'

def init_database(force=False):
    """Initialize database with schema."""
    if DB_PATH.exists() and not force:
        print(f"✓ Database exists: {DB_PATH}")
        return
    
    if force and DB_PATH.exists():
        DB_PATH.unlink()
        print(f"Removed existing database")
    
    print(f"Creating database: {DB_PATH}")
    
    with sqlite3.connect(DB_PATH) as conn:
        with open(SCHEMA_PATH, 'r') as f:
            schema = f.read()
        conn.executescript(schema)
    
    print(f"✓ Database initialized")

def get_connection():
    """Get database connection."""
    return sqlite3.connect(DB_PATH)

def update_metadata(key, value):
    """Update metadata table."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE metadata SET value = ?, updated_at = ? WHERE key = ?",
            (str(value), datetime.now().isoformat(), key)
        )

def get_stats():
    """Get database statistics."""
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        stats = {}
        
        # IOC stats
        cur.execute("SELECT COUNT(*) as count FROM iocs")
        stats['total_iocs'] = cur.fetchone()['count']
        
        # Subnet stats
        cur.execute("""
            SELECT tier, COUNT(*) as count, SUM(ioc_count) as iocs
            FROM subnets GROUP BY tier
        """)
        stats['subnets_by_tier'] = {row['tier']: {'count': row['count'], 'iocs': row['iocs']} 
                                     for row in cur.fetchall()}
        
        # Scan stats
        cur.execute("""
            SELECT classification, COUNT(*) as count 
            FROM scan_results 
            GROUP BY classification
        """)
        stats['scans_by_classification'] = {row['classification']: row['count'] 
                                            for row in cur.fetchall()}
        
        cur.execute("SELECT COUNT(DISTINCT ip) as count FROM scan_results")
        stats['unique_scanned_ips'] = cur.fetchone()['count']
        
        # ASN stats
        cur.execute("SELECT COUNT(*) as count FROM asn_info")
        stats['total_asns'] = cur.fetchone()['count']
        
        # Scan queue
        cur.execute("SELECT status, COUNT(*) as count FROM scan_queue GROUP BY status")
        stats['queue_by_status'] = {row['status']: row['count'] for row in cur.fetchall()}
        
        return stats

def print_stats():
    """Print database statistics."""
    stats = get_stats()
    
    print("\n" + "="*60)
    print("DATABASE STATISTICS")
    print("="*60)
    
    print(f"\nIOCs: {stats['total_iocs']:,}")
    
    if stats['subnets_by_tier']:
        print(f"\nSubnets by Tier:")
        tier_order = {'TIER_S': 1, 'TIER_A': 2, 'TIER_B': 3, 'TIER_C': 4}
        sorted_tiers = sorted(stats['subnets_by_tier'].items(), 
                             key=lambda x: tier_order.get(x[0], 99) if x[0] else 100)
        for tier, data in sorted_tiers:
            if tier:
                print(f"  {tier:10} : {data['count']:3} subnets, {data['iocs']:4} IOCs")
    
    if stats['scans_by_classification']:
        print(f"\nScan Results:")
        print(f"  Unique IPs: {stats['unique_scanned_ips']:,}")
        for classification, count in sorted(stats['scans_by_classification'].items()):
            if classification:
                print(f"  {classification:10} : {count:,}")
    
    if stats['total_asns'] > 0:
        print(f"\nASNs tracked: {stats['total_asns']}")
    
    if stats['queue_by_status']:
        print(f"\nScan Queue:")
        for status, count in sorted(stats['queue_by_status'].items()):
            print(f"  {status:10} : {count}")
    
    print()

if __name__ == '__main__':
    import sys
    
    force = '--force' in sys.argv
    init_database(force=force)
    print_stats()
