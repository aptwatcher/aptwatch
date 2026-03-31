#!/usr/bin/env python3
"""
IOC-level attribution confidence module for APTWatch.
Manages threat actor attribution for indicators of compromise using SQLite database.
"""

import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from datetime import datetime


DB_PATH = Path(__file__).parent.parent / "database" / "apt_intel.db"

# Evidence type max confidence contributions
EVIDENCE_MAXES = {
    "malware_sample": 0.30,
    "passive_dns": 0.25,
    "infrastructure_overlap": 0.20,
    "cert_pattern": 0.15,
    "threat_feed": 0.10,
    "manual_analysis": 0.25,
}


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Get database connection with row factory enabled."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def calculate_ioc_attribution_confidence(campaign_ioc_id: int, conn: sqlite3.Connection) -> float:
    """
    Calculate attribution confidence for a campaign IOC based on evidence chain.

    Fetches all evidence from ioc_evidence_chain, sums confidence contributions
    (capped at type max), and normalizes to 0.0-1.0 range.

    Args:
        campaign_ioc_id: ID from campaign_iocs table
        conn: Database connection

    Returns:
        Confidence score 0.0-1.0
    """
    cursor = conn.cursor()

    # Fetch all evidence for this IOC
    cursor.execute("""
        SELECT evidence_type, confidence_contribution
        FROM ioc_evidence_chain
        WHERE campaign_ioc_id = ?
    """, (campaign_ioc_id,))

    evidence_rows = cursor.fetchall()

    # Sum contributions by type, capped at type maximum
    total_confidence = 0.0
    type_contributions = defaultdict(float)

    for row in evidence_rows:
        evidence_type = row["evidence_type"]
        contribution = row["confidence_contribution"]
        max_for_type = EVIDENCE_MAXES.get(evidence_type, 0.0)

        # Add to type total, capped at max
        type_contributions[evidence_type] += contribution
        if type_contributions[evidence_type] > max_for_type:
            type_contributions[evidence_type] = max_for_type

    # Sum all type totals
    total_confidence = sum(type_contributions.values())

    # Normalize: max possible is sum of all maxes ≈ 1.25, cap at 1.0
    max_possible = sum(EVIDENCE_MAXES.values())
    if max_possible > 0:
        normalized = min(total_confidence / max_possible, 1.0)
    else:
        normalized = 0.0

    evidence_count = len(evidence_rows)

    # Update campaign_iocs with calculated confidence
    cursor.execute("""
        UPDATE campaign_iocs
        SET confidence_score = ?, evidence_count = ?
        WHERE id = ?
    """, (normalized, evidence_count, campaign_ioc_id))

    conn.commit()

    return normalized


def calculate_actor_attribution_for_ip(ip: str, conn: sqlite3.Connection) -> Dict:
    """
    Calculate threat actor attribution for an IP address.

    Finds all campaign_iocs matching this IP, selects highest confidence match,
    and updates ipv4_iocs table.

    Args:
        ip: IPv4 address
        conn: Database connection

    Returns:
        Dict with keys: actor, confidence, link_type, campaign_id
    """
    cursor = conn.cursor()

    # Find all campaign_iocs for this IP
    cursor.execute("""
        SELECT
            ci.id,
            ci.campaign_id,
            ci.confidence_score,
            ci.role,
            c.campaign_name,
            c.threat_actor_type
        FROM campaign_iocs ci
        JOIN campaigns c ON ci.campaign_id = c.id
        WHERE ci.ioc_value = ? AND ci.ioc_type = 'ipv4'
        ORDER BY ci.confidence_score DESC
        LIMIT 1
    """, (ip,))

    match = cursor.fetchone()

    if not match:
        # No attribution found
        result = {
            "actor": None,
            "confidence": 0.0,
            "link_type": None,
            "campaign_id": None,
        }
    else:
        result = {
            "actor": match["campaign_name"],
            "confidence": match["confidence_score"] or 0.0,
            "link_type": match["role"],
            "campaign_id": match["campaign_id"],
        }

        # Update ipv4_iocs table
        cursor.execute("""
            SELECT * FROM ipv4_iocs WHERE ip = ?
        """, (ip,))

        ip_record = cursor.fetchone()

        if ip_record:
            cursor.execute("""
                UPDATE ipv4_iocs
                SET actor_attribution_score = ?, actor_attribution_actor = ?
                WHERE ip = ?
            """, (result["confidence"], result["actor"], ip))
        else:
            cursor.execute("""
                INSERT INTO ipv4_iocs (ip, actor_attribution_score, actor_attribution_actor)
                VALUES (?, ?, ?)
            """, (ip, result["confidence"], result["actor"]))

        conn.commit()

    return result


def add_evidence(
    campaign_ioc_id: int,
    evidence_type: str,
    detail: str,
    contribution: float,
    source_ref: str,
    conn: sqlite3.Connection,
) -> int:
    """
    Add evidence to ioc_evidence_chain and recalculate confidence.

    Args:
        campaign_ioc_id: ID from campaign_iocs table
        evidence_type: Type of evidence (from EVIDENCE_MAXES)
        detail: Evidence detail/description
        contribution: Confidence contribution (0.0-1.0)
        source_ref: Source reference/URL
        conn: Database connection

    Returns:
        ID of inserted evidence record
    """
    cursor = conn.cursor()

    # Insert evidence
    cursor.execute("""
        INSERT INTO ioc_evidence_chain
        (campaign_ioc_id, evidence_type, evidence_detail, confidence_contribution, source_reference)
        VALUES (?, ?, ?, ?, ?)
    """, (campaign_ioc_id, evidence_type, detail, contribution, source_ref))

    evidence_id = cursor.lastrowid
    conn.commit()

    # Recalculate confidence for this IOC
    calculate_ioc_attribution_confidence(campaign_ioc_id, conn)

    return evidence_id


def batch_update_attribution(conn: sqlite3.Connection, limit: Optional[int] = None) -> int:
    """
    Recalculate attribution confidence for all campaign_iocs and update ipv4_iocs.

    Args:
        conn: Database connection
        limit: Maximum number to process (None = all)

    Returns:
        Count of updated records
    """
    cursor = conn.cursor()

    # Get all campaign_iocs
    query = "SELECT id FROM campaign_iocs"
    if limit:
        query += " LIMIT ?"

    cursor.execute(query, (limit,) if limit else ())
    ioc_ids = [row["id"] for row in cursor.fetchall()]

    # Recalculate confidence for each
    updated_count = 0
    for ioc_id in ioc_ids:
        calculate_ioc_attribution_confidence(ioc_id, conn)
        updated_count += 1

    # Update actor attribution for all ipv4_iocs that appear in campaign_iocs
    cursor.execute("""
        SELECT DISTINCT ioc_value FROM campaign_iocs
        WHERE ioc_type = 'ipv4'
    """)

    ips = [row["ioc_value"] for row in cursor.fetchall()]

    for ip in ips:
        calculate_actor_attribution_for_ip(ip, conn)
        updated_count += 1

    return updated_count


def get_attribution_summary(ip: str, conn: sqlite3.Connection) -> Dict:
    """
    Get full attribution breakdown for an IP address.

    Returns actor, confidence, evidence chain, and campaign details.

    Args:
        ip: IPv4 address
        conn: Database connection

    Returns:
        Dict with: actor, confidence, evidence_chain, campaign_info, infrastructure_risk
    """
    cursor = conn.cursor()

    # Get actor attribution
    actor_result = calculate_actor_attribution_for_ip(ip, conn)

    # Get full evidence chain
    cursor.execute("""
        SELECT
            e.evidence_type,
            e.evidence_detail,
            e.confidence_contribution,
            e.source_reference,
            ci.role,
            c.campaign_name,
            c.origin_country,
            c.confidence,
            s.report_title,
            s.publish_date
        FROM campaign_iocs ci
        JOIN campaigns c ON ci.campaign_id = c.id
        LEFT JOIN ioc_evidence_chain e ON ci.id = e.campaign_ioc_id
        LEFT JOIN attribution_sources s ON ci.attribution_source_id = s.id
        WHERE ci.ioc_value = ? AND ci.ioc_type = 'ipv4'
        ORDER BY ci.confidence_score DESC, e.confidence_contribution DESC
    """, (ip,))

    rows = cursor.fetchall()

    if not rows:
        return {
            "ip": ip,
            "actor": None,
            "confidence": 0.0,
            "evidence_chain": [],
            "campaign_info": {},
            "infrastructure_risk": None,
        }

    # Build evidence chain
    evidence_chain = []
    campaign_info = {}
    infrastructure_risk = None

    for row in rows:
        if not campaign_info:
            campaign_info = {
                "campaign_name": row["campaign_name"],
                "origin_country": row["origin_country"],
                "campaign_confidence": row["confidence"],
                "ioc_role": row["role"],
                "report_title": row["report_title"],
                "publish_date": row["publish_date"],
            }

        if row["evidence_type"] and row["evidence_type"] not in [e["type"] for e in evidence_chain]:
            evidence_chain.append({
                "type": row["evidence_type"],
                "detail": row["evidence_detail"],
                "contribution": row["confidence_contribution"],
                "source": row["source_reference"],
            })

    # Get infrastructure risk
    cursor.execute("""
        SELECT infrastructure_risk FROM campaign_iocs
        WHERE ioc_value = ? AND ioc_type = 'ipv4'
        LIMIT 1
    """, (ip,))

    risk_row = cursor.fetchone()
    if risk_row:
        infrastructure_risk = risk_row["infrastructure_risk"]

    return {
        "ip": ip,
        "actor": actor_result["actor"],
        "confidence": actor_result["confidence"],
        "evidence_chain": evidence_chain,
        "campaign_info": campaign_info,
        "infrastructure_risk": infrastructure_risk,
    }


def cross_reference_infrastructure(ip: str, conn: sqlite3.Connection) -> List[Dict]:
    """
    Find other IPs sharing same ASN, hosting provider, or subnet.

    Returns IPs that are also in campaign_iocs as potential infrastructure overlap.

    Args:
        ip: IPv4 address
        conn: Database connection

    Returns:
        List of dicts with: ip, asn, provider, shared_actor, confidence
    """
    cursor = conn.cursor()

    # Get enrichment data for input IP
    cursor.execute("""
        SELECT asn, asn_org, hosting_provider FROM enrichment_results
        WHERE indicator = ?
    """, (ip,))

    enrichment = cursor.fetchone()

    if not enrichment:
        return []

    asn = enrichment["asn"]
    provider = enrichment["hosting_provider"]

    related_ips = []

    if asn:
        # Find IPs sharing same ASN
        cursor.execute("""
            SELECT DISTINCT e.indicator
            FROM enrichment_results e
            WHERE e.asn = ? AND e.indicator != ?
        """, (asn, ip))

        asn_ips = [row["indicator"] for row in cursor.fetchall()]

        # Check which are in campaign_iocs
        for related_ip in asn_ips:
            cursor.execute("""
                SELECT ci.confidence_score, c.campaign_name
                FROM campaign_iocs ci
                JOIN campaigns c ON ci.campaign_id = c.id
                WHERE ci.ioc_value = ? AND ci.ioc_type = 'ipv4'
                ORDER BY ci.confidence_score DESC
                LIMIT 1
            """, (related_ip,))

            match = cursor.fetchone()
            if match:
                related_ips.append({
                    "ip": related_ip,
                    "asn": asn,
                    "provider": provider,
                    "shared_actor": match["campaign_name"],
                    "confidence": match["confidence_score"] or 0.0,
                    "overlap_type": "asn",
                })

    if provider:
        # Find IPs sharing same hosting provider
        cursor.execute("""
            SELECT DISTINCT e.indicator, e.asn, e.asn_org
            FROM enrichment_results e
            WHERE e.hosting_provider = ? AND e.indicator != ?
        """, (provider, ip))

        provider_ips = [row["indicator"] for row in cursor.fetchall()]

        # Check which are in campaign_iocs (avoid duplicates)
        for related_ip in provider_ips:
            if any(r["ip"] == related_ip for r in related_ips):
                continue

            cursor.execute("""
                SELECT ci.confidence_score, c.campaign_name
                FROM campaign_iocs ci
                JOIN campaigns c ON ci.campaign_id = c.id
                WHERE ci.ioc_value = ? AND ci.ioc_type = 'ipv4'
                ORDER BY ci.confidence_score DESC
                LIMIT 1
            """, (related_ip,))

            match = cursor.fetchone()
            if match:
                cursor.execute("""
                    SELECT asn FROM enrichment_results WHERE indicator = ?
                """, (related_ip,))
                asn_row = cursor.fetchone()
                related_asn = asn_row["asn"] if asn_row else None

                related_ips.append({
                    "ip": related_ip,
                    "asn": related_asn,
                    "provider": provider,
                    "shared_actor": match["campaign_name"],
                    "confidence": match["confidence_score"] or 0.0,
                    "overlap_type": "provider",
                })

    return related_ips


def import_threat_actors(conn: sqlite3.Connection) -> int:
    """
    Populate threat_actors table from existing campaigns.

    Maps campaign_name to threat_actors.name, avoiding duplicates.

    Args:
        conn: Database connection

    Returns:
        Count of inserted threat actor records
    """
    cursor = conn.cursor()

    # Get unique campaigns
    cursor.execute("""
        SELECT DISTINCT c.campaign_name, c.aliases, c.origin_country, c.threat_actor_type, c.ttps
        FROM campaigns c
    """)

    campaigns = cursor.fetchall()
    inserted = 0

    for campaign in campaigns:
        # Check if actor already exists
        cursor.execute("""
            SELECT id FROM threat_actors WHERE name = ?
        """, (campaign["campaign_name"],))

        if cursor.fetchone():
            continue

        # Insert as new threat actor
        cursor.execute("""
            INSERT INTO threat_actors (name, aliases, origin_country, threat_type, ttps)
            VALUES (?, ?, ?, ?, ?)
        """, (
            campaign["campaign_name"],
            campaign["aliases"],
            campaign["origin_country"],
            campaign["threat_actor_type"],
            campaign["ttps"],
        ))

        inserted += 1

    conn.commit()
    return inserted


def cmd_recalc(args):
    """Command: recalc [limit] - Recalculate all attribution confidence."""
    limit = int(args[0]) if args else None

    conn = get_connection()
    try:
        count = batch_update_attribution(conn, limit)
        print(f"Updated {count} attribution records")
    finally:
        conn.close()


def cmd_show(args):
    """Command: show <ip> - Show attribution for IP."""
    if not args:
        print("Error: IP address required")
        sys.exit(1)

    ip = args[0]
    conn = get_connection()

    try:
        summary = get_attribution_summary(ip, conn)

        print(f"\n=== Attribution Summary for {ip} ===")
        print(f"Actor: {summary['actor'] or 'Unknown'}")
        print(f"Confidence: {summary['confidence']:.2%}")

        if summary["campaign_info"]:
            print(f"\nCampaign Details:")
            for key, val in summary["campaign_info"].items():
                print(f"  {key}: {val}")

        if summary["infrastructure_risk"]:
            print(f"\nInfrastructure Risk: {summary['infrastructure_risk']}")

        if summary["evidence_chain"]:
            print(f"\nEvidence Chain ({len(summary['evidence_chain'])} items):")
            for i, evidence in enumerate(summary["evidence_chain"], 1):
                print(f"  {i}. {evidence['type']} (+{evidence['contribution']:.2%})")
                print(f"     {evidence['detail']}")
                if evidence["source"]:
                    print(f"     Source: {evidence['source']}")
        else:
            print("\nNo evidence found")

    finally:
        conn.close()


def cmd_actors(args):
    """Command: actors - List all threat actors."""
    conn = get_connection()

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name, origin_country, threat_type, ttps
            FROM threat_actors
            ORDER BY name
        """)

        actors = cursor.fetchall()

        print(f"\n=== Threat Actors ({len(actors)}) ===")
        for actor in actors:
            print(f"\n{actor['name']}")
            print(f"  Country: {actor['origin_country'] or 'Unknown'}")
            print(f"  Type: {actor['threat_type'] or 'Unknown'}")
            if actor['ttps']:
                print(f"  TTPs: {actor['ttps']}")

    finally:
        conn.close()


def cmd_evidence(args):
    """Command: evidence <ip> - Show evidence chain for IP."""
    if not args:
        print("Error: IP address required")
        sys.exit(1)

    ip = args[0]
    conn = get_connection()

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                e.evidence_type,
                e.evidence_detail,
                e.confidence_contribution,
                e.source_reference,
                ci.campaign_id,
                c.campaign_name
            FROM campaign_iocs ci
            JOIN campaigns c ON ci.campaign_id = c.id
            LEFT JOIN ioc_evidence_chain e ON ci.id = e.campaign_ioc_id
            WHERE ci.ioc_value = ? AND ci.ioc_type = 'ipv4'
            ORDER BY ci.confidence_score DESC, e.confidence_contribution DESC
        """, (ip,))

        rows = cursor.fetchall()

        if not rows:
            print(f"No evidence found for {ip}")
            return

        print(f"\n=== Evidence Chain for {ip} ===")

        campaign_groups = defaultdict(list)
        for row in rows:
            campaign_groups[row["campaign_name"]].append(row)

        for campaign_name, evidence_list in campaign_groups.items():
            print(f"\nCampaign: {campaign_name}")
            for evidence in evidence_list:
                if evidence["evidence_type"]:
                    print(f"  - {evidence['evidence_type']} (+{evidence['confidence_contribution']:.2%})")
                    print(f"    {evidence['evidence_detail']}")
                    if evidence["source_reference"]:
                        print(f"    Source: {evidence['source_reference']}")

    finally:
        conn.close()


def cmd_cross_ref(args):
    """Command: cross-ref <ip> - Cross-reference infrastructure."""
    if not args:
        print("Error: IP address required")
        sys.exit(1)

    ip = args[0]
    conn = get_connection()

    try:
        results = cross_reference_infrastructure(ip, conn)

        print(f"\n=== Infrastructure Cross-Reference for {ip} ===")

        if not results:
            print("No related infrastructure found")
            return

        print(f"\nFound {len(results)} related IPs:")

        for result in results:
            print(f"\n  {result['ip']}")
            print(f"    Overlap Type: {result['overlap_type']}")
            if result["asn"]:
                print(f"    ASN: {result['asn']}")
            print(f"    Provider: {result['provider']}")
            print(f"    Shared Actor: {result['shared_actor']}")
            print(f"    Confidence: {result['confidence']:.2%}")

    finally:
        conn.close()


def cmd_stats(args):
    """Command: stats - Attribution statistics."""
    conn = get_connection()

    try:
        cursor = conn.cursor()

        # Count statistics
        cursor.execute("SELECT COUNT(*) as count FROM campaign_iocs WHERE ioc_type = 'ipv4'")
        ipv4_count = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM campaigns")
        campaign_count = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM threat_actors")
        actor_count = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM ioc_evidence_chain")
        evidence_count = cursor.fetchone()["count"]

        # Average confidence
        cursor.execute("""
            SELECT AVG(confidence_score) as avg_conf, MAX(confidence_score) as max_conf
            FROM campaign_iocs WHERE ioc_type = 'ipv4'
        """)
        conf_stats = cursor.fetchone()
        avg_conf = conf_stats["avg_conf"] or 0.0
        max_conf = conf_stats["max_conf"] or 0.0

        # Evidence type distribution
        cursor.execute("""
            SELECT evidence_type, COUNT(*) as count
            FROM ioc_evidence_chain
            GROUP BY evidence_type
            ORDER BY count DESC
        """)

        evidence_types = cursor.fetchall()

        print("\n=== Attribution Statistics ===")
        print(f"\nCounts:")
        print(f"  Campaigns: {campaign_count}")
        print(f"  Threat Actors: {actor_count}")
        print(f"  IPv4 IOCs: {ipv4_count}")
        print(f"  Evidence Records: {evidence_count}")

        print(f"\nConfidence Metrics:")
        print(f"  Average: {avg_conf:.2%}")
        print(f"  Maximum: {max_conf:.2%}")

        print(f"\nEvidence Type Distribution:")
        for row in evidence_types:
            print(f"  {row['evidence_type']}: {row['count']}")

    finally:
        conn.close()


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python attribution.py <command> [args]")
        print("\nCommands:")
        print("  recalc [limit]    Recalculate all attribution confidence")
        print("  show <ip>         Show attribution for IP")
        print("  actors            List all threat actors")
        print("  evidence <ip>     Show evidence chain for IP")
        print("  cross-ref <ip>    Cross-reference infrastructure")
        print("  stats             Attribution statistics")
        sys.exit(1)

    command = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        "recalc": cmd_recalc,
        "show": cmd_show,
        "actors": cmd_actors,
        "evidence": cmd_evidence,
        "cross-ref": cmd_cross_ref,
        "stats": cmd_stats,
    }

    if command not in commands:
        print(f"Unknown command: {command}")
        sys.exit(1)

    try:
        commands[command](args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
