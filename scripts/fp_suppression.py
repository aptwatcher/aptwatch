#!/usr/bin/env python3
"""
False-positive suppression and provider classification module for APTWatch.
Classifies ASNs, manages cloud IP ranges, and calculates suppression factors.
"""

import sqlite3
import ipaddress
import re
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Tuple


DB_PATH = Path(__file__).parent.parent / "database" / "apt_intel.db"


# Cloud provider regex patterns
CLOUD_PATTERNS = re.compile(
    r"(Amazon|AWS|Microsoft|Azure|Google|GCP|Cloudflare|DigitalOcean|Linode|Vultr|OVH|Hetzner)",
    re.IGNORECASE
)

# Bulletproof hosting patterns
BPH_PATTERNS = re.compile(
    r"(ELITETEAM|Global-Data|swissnetwork|SERVERASTRA|VIRTUALCOLO)",
    re.IGNORECASE
)

# Risk scores for provider types
PROVIDER_RISK_SCORES = {
    "cloud_provider": 0.10,
    "bulletproof_hosting": 0.95,
    "abuse_tolerant": 0.80,
    "datacenter": 0.50,
    "isp": 0.30,
}

# Cloud provider CIDR ranges (well-known, hardcoded)
CLOUD_RANGES = [
    # AWS (approximate ranges)
    ("AWS", "52.0.0.0/8", "compute"),
    ("AWS", "54.0.0.0/8", "compute"),

    # Azure
    ("Azure", "13.64.0.0/10", "compute"),
    ("Azure", "20.0.0.0/8", "compute"),
    ("Azure", "40.64.0.0/10", "compute"),

    # Google Cloud
    ("GCP", "34.64.0.0/10", "compute"),
    ("GCP", "35.184.0.0/13", "compute"),

    # Cloudflare
    ("Cloudflare", "104.16.0.0/12", "cdn"),
    ("Cloudflare", "172.64.0.0/13", "cdn"),
    ("Cloudflare", "173.245.48.0/20", "cdn"),
    ("Cloudflare", "103.21.244.0/22", "cdn"),
    ("Cloudflare", "103.22.200.0/22", "cdn"),
    ("Cloudflare", "103.31.4.0/22", "cdn"),
    ("Cloudflare", "141.101.64.0/18", "cdn"),
    ("Cloudflare", "108.162.192.0/18", "cdn"),
    ("Cloudflare", "190.93.240.0/20", "cdn"),
    ("Cloudflare", "188.114.96.0/20", "cdn"),
    ("Cloudflare", "197.234.240.0/22", "cdn"),
    ("Cloudflare", "198.41.128.0/17", "cdn"),

    # DigitalOcean
    ("DigitalOcean", "64.225.0.0/16", "compute"),
    ("DigitalOcean", "68.183.0.0/16", "compute"),
    ("DigitalOcean", "134.209.0.0/16", "compute"),
    ("DigitalOcean", "137.184.0.0/16", "compute"),
    ("DigitalOcean", "142.93.0.0/16", "compute"),
    ("DigitalOcean", "143.198.0.0/16", "compute"),
    ("DigitalOcean", "143.244.128.0/17", "compute"),
    ("DigitalOcean", "144.126.192.0/18", "compute"),
    ("DigitalOcean", "146.190.0.0/15", "compute"),
    ("DigitalOcean", "147.182.128.0/17", "compute"),
    ("DigitalOcean", "157.230.0.0/16", "compute"),
    ("DigitalOcean", "159.65.0.0/16", "compute"),
    ("DigitalOcean", "159.89.0.0/16", "compute"),
    ("DigitalOcean", "159.203.0.0/16", "compute"),
    ("DigitalOcean", "161.35.0.0/16", "compute"),
    ("DigitalOcean", "162.243.0.0/16", "compute"),
    ("DigitalOcean", "164.90.0.0/16", "compute"),
    ("DigitalOcean", "164.92.0.0/16", "compute"),
    ("DigitalOcean", "165.22.0.0/16", "compute"),
    ("DigitalOcean", "165.227.0.0/16", "compute"),
    ("DigitalOcean", "167.71.0.0/16", "compute"),
    ("DigitalOcean", "167.172.0.0/16", "compute"),
    ("DigitalOcean", "167.99.0.0/16", "compute"),
    ("DigitalOcean", "174.138.0.0/16", "compute"),
    ("DigitalOcean", "178.128.0.0/16", "compute"),
    ("DigitalOcean", "178.62.0.0/16", "compute"),
    ("DigitalOcean", "188.166.0.0/16", "compute"),
]


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Get database connection."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def classify_asn(asn_number: int, conn: sqlite3.Connection) -> Dict:
    """
    Classify an ASN and return provider type and risk score.
    First checks if already classified, otherwise uses org_name patterns.

    Args:
        asn_number: ASN to classify
        conn: Database connection

    Returns:
        Dictionary with 'provider_type' and 'fp_risk_score'
    """
    cursor = conn.cursor()

    # Check if already classified
    cursor.execute(
        "SELECT provider_type, fp_risk_score FROM asn_info WHERE asn = ?",
        (asn_number,)
    )
    row = cursor.fetchone()

    if row and row[0] not in (None, "unknown"):
        return {
            "provider_type": row[0],
            "fp_risk_score": row[1],
        }

    # Get org_name for pattern matching
    cursor.execute(
        "SELECT org_name FROM asn_info WHERE asn = ?",
        (asn_number,)
    )
    row = cursor.fetchone()
    org_name = row[0] if row else ""

    # Classify based on org_name patterns
    provider_type = "datacenter"

    if CLOUD_PATTERNS.search(org_name):
        provider_type = "cloud_provider"
    elif BPH_PATTERNS.search(org_name):
        provider_type = "bulletproof_hosting"

    fp_risk_score = PROVIDER_RISK_SCORES.get(provider_type, 0.50)

    # Update database
    cursor.execute(
        """
        UPDATE asn_info
        SET provider_type = ?, fp_risk_score = ?
        WHERE asn = ?
        """,
        (provider_type, fp_risk_score, asn_number)
    )
    conn.commit()

    return {
        "provider_type": provider_type,
        "fp_risk_score": fp_risk_score,
    }


def classify_all_asns(conn: sqlite3.Connection) -> int:
    """
    Classify all unclassified ASNs and compute IOC density.

    Args:
        conn: Database connection

    Returns:
        Count of classified ASNs
    """
    cursor = conn.cursor()

    # Get all unclassified ASNs
    cursor.execute(
        """
        SELECT asn FROM asn_info
        WHERE provider_type IS NULL OR provider_type = 'unknown'
        """
    )
    asns = [row[0] for row in cursor.fetchall()]

    count = 0
    for asn in asns:
        classify_asn(asn, conn)

        # Calculate IOC density
        ioc_density = calculate_ioc_density(asn, conn)

        # Update asn_info with ioc_density if available
        if ioc_density is not None:
            cursor.execute(
                "UPDATE asn_info SET ioc_density = ? WHERE asn = ?",
                (ioc_density, asn)
            )

        count += 1

    conn.commit()
    return count


def calculate_ioc_density(asn_number: int, conn: sqlite3.Connection) -> Optional[float]:
    """
    Calculate IOC density: ioc_count / total_ips_announced.

    Args:
        asn_number: ASN to analyze
        conn: Database connection

    Returns:
        IOC density as percentage, or None if data unavailable
    """
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT ioc_count, total_ips_announced FROM asn_info
        WHERE asn = ?
        """,
        (asn_number,)
    )
    row = cursor.fetchone()

    if not row or row[0] is None or row[1] is None:
        return None

    ioc_count = row[0]
    total_ips = row[1]

    if total_ips == 0:
        return 0.0

    density = (ioc_count / total_ips) * 100
    return density


def ip_in_cloud_range(ip: str, conn: sqlite3.Connection) -> Optional[Dict]:
    """
    Check if IP falls within any CIDR in cloud_ip_ranges.

    Args:
        ip: IP address to check
        conn: Database connection

    Returns:
        Dictionary with provider, cidr, service_type, or None
    """
    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    cursor = conn.cursor()
    cursor.execute("SELECT provider, cidr, service_type FROM cloud_ip_ranges")

    for row in cursor.fetchall():
        try:
            cidr = ipaddress.ip_network(row[1], strict=False)
            if ip_addr in cidr:
                return {
                    "provider": row[0],
                    "cidr": row[1],
                    "service_type": row[2],
                }
        except ValueError:
            continue

    return None


def get_fp_suppression_factor(ip: str, conn: sqlite3.Connection) -> float:
    """
    Calculate false-positive suppression factor for an IP.
    1.0 = no suppression (treat normally)
    Lower values suppress the score
    Higher values boost the score

    Args:
        ip: IP address to evaluate
        conn: Database connection

    Returns:
        Suppression factor (0.0-1.5+)
    """
    # Check if IP in cloud_ip_ranges
    cloud_match = ip_in_cloud_range(ip, conn)
    if cloud_match:
        return 0.3

    # Look up ASN for this IP
    cursor = conn.cursor()
    cursor.execute(
        "SELECT asn FROM enrichment_results WHERE indicator = ?",
        (ip,)
    )
    row = cursor.fetchone()

    if not row:
        return 1.0

    asn = row[0]

    # Get ASN classification
    cursor.execute(
        "SELECT provider_type, ioc_density FROM asn_info WHERE asn = ?",
        (asn,)
    )
    asn_row = cursor.fetchone()

    if not asn_row:
        return 1.0

    provider_type = asn_row[0]
    ioc_density = asn_row[1]

    # Apply suppression based on provider type
    if provider_type == "cloud_provider":
        return 0.4
    elif provider_type == "bulletproof_hosting":
        return 1.5
    elif provider_type == "abuse_tolerant":
        return 1.2
    elif provider_type == "datacenter":
        # Low IOC density datacenter: suppress
        if ioc_density is not None and ioc_density < 0.1:
            return 0.6
        return 1.0

    return 1.0


def populate_cloud_ranges(conn: sqlite3.Connection) -> int:
    """
    Populate cloud_ip_ranges table with well-known cloud provider CIDRs.

    Args:
        conn: Database connection

    Returns:
        Count of ranges inserted
    """
    cursor = conn.cursor()

    # Clear existing ranges
    cursor.execute("DELETE FROM cloud_ip_ranges")

    # Insert cloud ranges
    for provider, cidr, service_type in CLOUD_RANGES:
        cursor.execute(
            """
            INSERT INTO cloud_ip_ranges (provider, cidr, service_type, last_updated)
            VALUES (?, ?, ?, ?)
            """,
            (provider, cidr, service_type, datetime.utcnow().isoformat())
        )

    conn.commit()
    return len(CLOUD_RANGES)


def batch_update_provider_risk(conn: sqlite3.Connection, limit: Optional[int] = None) -> int:
    """
    Update provider_risk_level for all ipv4_iocs based on ASN classification.
    Updates in batches of 500.

    Args:
        conn: Database connection
        limit: Maximum number of IOCs to update (None for all)

    Returns:
        Count of IOCs updated
    """
    cursor = conn.cursor()

    # Get all IOCs that need update
    if limit:
        cursor.execute(
            """
            SELECT i.ip, e.asn FROM ipv4_iocs i
            LEFT JOIN enrichment_results e ON i.ip = e.indicator
            LIMIT ?
            """,
            (limit,)
        )
    else:
        cursor.execute(
            """
            SELECT i.ip, e.asn FROM ipv4_iocs i
            LEFT JOIN enrichment_results e ON i.ip = e.indicator
            """
        )

    iocs = cursor.fetchall()

    # Batch update
    batch_size = 500
    count = 0

    for i in range(0, len(iocs), batch_size):
        batch = iocs[i:i + batch_size]

        for ip, asn in batch:
            if not asn:
                # No ASN found, use neutral risk level
                risk_level = "neutral"
            else:
                # Get ASN classification
                cursor.execute(
                    "SELECT provider_type FROM asn_info WHERE asn = ?",
                    (asn,)
                )
                asn_row = cursor.fetchone()

                if not asn_row or not asn_row[0]:
                    risk_level = "neutral"
                else:
                    # Map provider type to risk level
                    provider_type = asn_row[0]
                    if provider_type == "bulletproof_hosting":
                        risk_level = "critical"
                    elif provider_type == "abuse_tolerant":
                        risk_level = "high"
                    elif provider_type == "cloud_provider":
                        risk_level = "low"
                    else:
                        risk_level = "medium"

            # Update ipv4_iocs
            cursor.execute(
                "UPDATE ipv4_iocs SET provider_risk_level = ? WHERE ip = ?",
                (risk_level, ip)
            )
            count += 1

        conn.commit()

    return count


def show_classification_stats(conn: sqlite3.Connection):
    """Show classification statistics."""
    cursor = conn.cursor()

    # Count by provider type
    cursor.execute(
        """
        SELECT provider_type, COUNT(*) as count
        FROM asn_info
        WHERE provider_type IS NOT NULL
        GROUP BY provider_type
        ORDER BY count DESC
        """
    )

    print("\n=== Provider Classification Stats ===")
    for row in cursor.fetchall():
        provider_type = row[0] if row[0] else "unknown"
        count = row[1]
        print(f"  {provider_type}: {count}")

    # Cloud ranges count
    cursor.execute("SELECT COUNT(*) FROM cloud_ip_ranges")
    cloud_count = cursor.fetchone()[0]
    print(f"\n  Cloud IP ranges loaded: {cloud_count}")

    # Average risk scores
    cursor.execute(
        """
        SELECT provider_type, AVG(fp_risk_score) as avg_risk
        FROM asn_info
        WHERE fp_risk_score IS NOT NULL
        GROUP BY provider_type
        ORDER BY avg_risk DESC
        """
    )

    print("\n=== Average Risk Scores by Provider ===")
    for row in cursor.fetchall():
        provider_type = row[0] if row[0] else "unknown"
        avg_risk = row[1]
        print(f"  {provider_type}: {avg_risk:.3f}")


def check_ip_suppression(ip: str, conn: sqlite3.Connection):
    """Check FP suppression factor for an IP."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"Error: Invalid IP address '{ip}'")
        return

    factor = get_fp_suppression_factor(ip, conn)
    cloud_match = ip_in_cloud_range(ip, conn)

    cursor = conn.cursor()
    cursor.execute(
        "SELECT asn FROM enrichment_results WHERE indicator = ?",
        (ip,)
    )
    enrichment_row = cursor.fetchone()

    print(f"\n=== FP Suppression Check: {ip} ===")

    if cloud_match:
        print(f"  Cloud Range Match: {cloud_match['provider']}")
        print(f"  CIDR: {cloud_match['cidr']}")
        print(f"  Service Type: {cloud_match['service_type']}")

    if enrichment_row:
        asn = enrichment_row[0]
        cursor.execute(
            "SELECT provider_type, fp_risk_score FROM asn_info WHERE asn = ?",
            (asn,)
        )
        asn_row = cursor.fetchone()
        if asn_row:
            print(f"  ASN: {asn}")
            print(f"  Provider Type: {asn_row[0]}")
            print(f"  FP Risk Score: {asn_row[1]:.3f}")

    print(f"  Suppression Factor: {factor:.2f}")
    print(f"  Interpretation: ", end="")

    if factor < 0.5:
        print("Strong suppression (low false-positive risk)")
    elif factor < 1.0:
        print("Moderate suppression (reduced false-positive risk)")
    elif factor == 1.0:
        print("No suppression (treat normally)")
    else:
        print("Risk boost (increase vigilance)")


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python fp_suppression.py classify          # Classify all ASNs")
        print("  python fp_suppression.py cloud-ranges      # Populate cloud IP ranges")
        print("  python fp_suppression.py check <ip>        # Check FP suppression for IP")
        print("  python fp_suppression.py update-risk       # Update provider_risk_level")
        print("  python fp_suppression.py stats             # Show classification stats")
        sys.exit(0)

    command = sys.argv[1]

    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}")
        sys.exit(1)

    conn = get_connection(DB_PATH)

    try:
        if command == "classify":
            count = classify_all_asns(conn)
            print(f"Classified {count} ASNs")

        elif command == "cloud-ranges":
            count = populate_cloud_ranges(conn)
            print(f"Loaded {count} cloud IP ranges")

        elif command == "check":
            if len(sys.argv) < 3:
                print("Usage: python fp_suppression.py check <ip>")
                sys.exit(1)
            ip = sys.argv[2]
            check_ip_suppression(ip, conn)

        elif command == "update-risk":
            count = batch_update_provider_risk(conn)
            print(f"Updated provider risk for {count} IOCs")

        elif command == "stats":
            show_classification_stats(conn)

        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

    finally:
        conn.close()


if __name__ == "__main__":
    main()
