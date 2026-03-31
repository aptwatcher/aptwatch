#!/usr/bin/env python3
"""
STIX 2.1 Export Module for APTWatch
Converts APT intelligence data from SQLite to STIX 2.1 bundle format.
"""

import json
import uuid
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

DB_PATH = Path(__file__).parent.parent / "database" / "apt_intel.db"

# STIX TLP Marking Definition IDs (per STIX 2.1 spec)
TLP_MARKINGS = {
    "WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# APTWatch UUID namespace (deterministic UUIDs)
APTWATCH_NAMESPACE = uuid.UUID("550e8400-e29b-41d4-a716-446655440000")


def generate_stix_id(stix_type: str, seed: str = "") -> str:
    """
    Generate a deterministic STIX object ID using UUID5.

    Args:
        stix_type: STIX object type (e.g., 'indicator', 'campaign')
        seed: Optional seed for UUID generation (for determinism)

    Returns:
        STIX ID string like "indicator--<uuid5>"
    """
    if seed:
        obj_uuid = uuid.uuid5(APTWATCH_NAMESPACE, seed)
    else:
        obj_uuid = uuid.uuid4()
    return f"{stix_type}--{obj_uuid}"


def get_kill_chain_phases(conn: sqlite3.Connection, ioc_value: str) -> List[Dict[str, str]]:
    """
    Get MITRE kill chain phases for an IOC based on technique mapping.

    Args:
        conn: Database connection
        ioc_value: IOC value (IP, domain, etc.)

    Returns:
        List of kill chain phase dicts with phase_name and kill_chain_name
    """
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT tactic FROM mitre_mapping
        WHERE ioc_value = ?
    """, (ioc_value,))

    tactics = cursor.fetchall()
    phases = []
    for (tactic,) in tactics:
        if tactic:
            phases.append({
                "kill_chain_name": "mitre-attack",
                "phase_name": tactic.lower().replace(" ", "-")
            })

    return phases


def get_infrastructure_risk_label(score: float) -> str:
    """
    Map infrastructure risk score to STIX label.

    Args:
        score: Infrastructure risk score (0-1 or 0-100)

    Returns:
        STIX label string
    """
    # Normalize to 0-1 if needed
    if score > 1:
        score = score / 100.0

    if score >= 0.8:
        return "malicious-activity"
    elif score >= 0.5:
        return "malware-activity"
    elif score >= 0.3:
        return "suspicious-activity"
    else:
        return "anomalous-activity"


def ip_to_stix_indicator(ip_row: tuple, conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Convert an IPv4 IOC row to a STIX 2.1 indicator object.

    Args:
        ip_row: Tuple from ipv4_iocs table
        conn: Database connection for related data

    Returns:
        STIX indicator object (dict)
    """
    (ip, composite_score, infra_risk, actor_score, actor_name, lifecycle,
     first_seen, last_seen, validation_count, stix_id, mitre_techniques) = ip_row

    # Generate STIX ID if not present
    if not stix_id:
        stix_id = generate_stix_id("indicator", f"ipv4-{ip}")

    # Parse timestamps
    created = datetime.fromisoformat(first_seen) if first_seen else datetime.utcnow()
    valid_from = created.isoformat() + "Z"

    # Calculate valid_until (last_seen + 90 days, or None if active)
    if last_seen and lifecycle != "active":
        valid_until_dt = datetime.fromisoformat(last_seen) + timedelta(days=90)
        valid_until = valid_until_dt.isoformat() + "Z"
    else:
        valid_until = None

    # Confidence: normalize composite_score to 0-100
    confidence = int(composite_score * 100) if composite_score <= 1 else int(composite_score)

    # Determine indicator type based on infrastructure risk
    if infra_risk >= 0.7:
        indicator_types = ["malicious-activity"]
    else:
        indicator_types = ["anomalous-activity"]

    # Build labels
    labels = [get_infrastructure_risk_label(infra_risk)]
    if actor_name:
        labels.append(f"actor--{actor_name.lower().replace(' ', '-')}")

    # Get kill chain phases
    kill_chain_phases = get_kill_chain_phases(conn, ip)

    # Build the indicator object
    indicator = {
        "type": "indicator",
        "id": stix_id,
        "created": valid_from,
        "modified": valid_from,
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "pattern_type": "stix",
        "valid_from": valid_from,
        "labels": labels,
        "indicator_types": indicator_types,
        "confidence": confidence,
        "object_marking_refs": [TLP_MARKINGS["WHITE"]],
    }

    if valid_until:
        indicator["valid_until"] = valid_until

    if kill_chain_phases:
        indicator["kill_chain_phases"] = kill_chain_phases

    # Add external references
    indicator["external_references"] = [
        {
            "source_name": "APTWatch",
            "url": f"https://api.aptwatch.org/api/ioc/{ip}"
        }
    ]

    # Add custom properties
    if validation_count:
        indicator["x_validation_count"] = validation_count
    if actor_score:
        indicator["x_actor_attribution_score"] = float(actor_score)

    return indicator


def domain_to_stix_indicator(domain_row: tuple) -> Dict[str, Any]:
    """
    Convert a domain IOC row to a STIX 2.1 indicator object.

    Args:
        domain_row: Tuple from domains table (domain, first_seen)

    Returns:
        STIX indicator object (dict)
    """
    domain, first_seen = domain_row

    created = datetime.fromisoformat(first_seen) if first_seen else datetime.utcnow()
    timestamp = created.isoformat() + "Z"

    indicator = {
        "type": "indicator",
        "id": generate_stix_id("indicator", f"domain-{domain}"),
        "created": timestamp,
        "modified": timestamp,
        "pattern": f"[domain-name:value = '{domain}']",
        "pattern_type": "stix",
        "valid_from": timestamp,
        "labels": ["malicious-activity"],
        "indicator_types": ["malicious-activity"],
        "confidence": 75,
        "object_marking_refs": [TLP_MARKINGS["WHITE"]],
        "external_references": [
            {
                "source_name": "APTWatch",
                "url": f"https://api.aptwatch.org/api/ioc/{domain}"
            }
        ]
    }

    return indicator


def url_to_stix_indicator(url_row: tuple) -> Dict[str, Any]:
    """
    Convert a URL IOC row to a STIX 2.1 indicator object.

    Args:
        url_row: Tuple from urls table (url, host, first_seen)

    Returns:
        STIX indicator object (dict)
    """
    url, host, first_seen = url_row

    created = datetime.fromisoformat(first_seen) if first_seen else datetime.utcnow()
    timestamp = created.isoformat() + "Z"

    indicator = {
        "type": "indicator",
        "id": generate_stix_id("indicator", f"url-{url}"),
        "created": timestamp,
        "modified": timestamp,
        "pattern": f"[url:value = '{url}']",
        "pattern_type": "stix",
        "valid_from": timestamp,
        "labels": ["malicious-activity"],
        "indicator_types": ["malicious-activity"],
        "confidence": 70,
        "object_marking_refs": [TLP_MARKINGS["WHITE"]],
        "external_references": [
            {
                "source_name": "APTWatch",
                "url": f"https://api.aptwatch.org/api/ioc/{url}"
            }
        ]
    }

    return indicator


def campaign_to_stix(campaign_row: tuple, conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """
    Convert a campaign row to STIX objects (campaign + intrusion-set + relationships).

    Args:
        campaign_row: Tuple from campaigns table
        conn: Database connection for related data

    Returns:
        List of STIX objects (campaign, intrusion-set, relationships)
    """
    (campaign_id, name, aliases, threat_actor_type, origin_country,
     description, ttps) = campaign_row

    timestamp = datetime.utcnow().isoformat() + "Z"
    objects = []

    # Parse aliases
    alias_list = [a.strip() for a in aliases.split(",")] if aliases else []

    # Create campaign object
    campaign_id_stix = generate_stix_id("campaign", f"campaign-{name}")
    campaign_obj = {
        "type": "campaign",
        "id": campaign_id_stix,
        "created": timestamp,
        "modified": timestamp,
        "name": name,
        "description": description or f"Campaign: {name}",
        "object_marking_refs": [TLP_MARKINGS["WHITE"]],
    }

    if alias_list:
        campaign_obj["aliases"] = alias_list

    objects.append(campaign_obj)

    # Create intrusion-set object for threat actor
    intrusion_set_id = generate_stix_id("intrusion-set", f"actor-{name}")
    intrusion_set = {
        "type": "intrusion-set",
        "id": intrusion_set_id,
        "created": timestamp,
        "modified": timestamp,
        "name": name,
        "description": f"Threat actor behind campaign: {name}",
        "object_marking_refs": [TLP_MARKINGS["WHITE"]],
    }

    if alias_list:
        intrusion_set["aliases"] = alias_list

    if origin_country:
        intrusion_set["x_origin_country"] = origin_country

    if threat_actor_type:
        intrusion_set["x_threat_actor_type"] = threat_actor_type

    objects.append(intrusion_set)

    # Create relationship between campaign and intrusion-set
    relationship = {
        "type": "relationship",
        "id": generate_stix_id("relationship", f"{campaign_id_stix}-{intrusion_set_id}"),
        "created": timestamp,
        "modified": timestamp,
        "relationship_type": "attributed-to",
        "source_ref": campaign_id_stix,
        "target_ref": intrusion_set_id,
        "object_marking_refs": [TLP_MARKINGS["WHITE"]],
    }

    objects.append(relationship)

    return objects


def get_identity_object() -> Dict[str, Any]:
    """
    Create the APTWatch identity object.

    Returns:
        STIX identity object
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    return {
        "type": "identity",
        "id": "identity--aptwatch-org",
        "created": timestamp,
        "modified": timestamp,
        "name": "APTWatch",
        "identity_class": "organization",
        "description": "APT Intelligence Analysis Platform",
        "contact_information": "https://aptwatch.org"
    }


def get_tlp_marking_definitions() -> List[Dict[str, Any]]:
    """
    Create STIX TLP marking definition objects.

    Returns:
        List of TLP marking definition objects
    """
    timestamp = datetime.utcnow().isoformat() + "Z"

    definitions = []
    tlp_data = {
        "WHITE": {
            "definition": {
                "tlp": "white"
            },
            "x_color": "ffffff"
        },
        "GREEN": {
            "definition": {
                "tlp": "green"
            },
            "x_color": "33cc33"
        },
        "AMBER": {
            "definition": {
                "tlp": "amber"
            },
            "x_color": "ffbf00"
        },
        "RED": {
            "definition": {
                "tlp": "red"
            },
            "x_color": "ff2b2b"
        },
    }

    for level, data in tlp_data.items():
        definitions.append({
            "type": "marking-definition",
            "id": TLP_MARKINGS[level],
            "created": "2017-01-20T00:00:00.000Z",
            "modified": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": f"TLP:{level}",
            "definition": data["definition"],
            "x_color": data["x_color"]
        })

    return definitions


def generate_stix_bundle(
    conn: sqlite3.Connection,
    min_score: float = 0.0,
    lifecycle_states: Optional[List[str]] = None,
    actor: Optional[str] = None,
    limit: int = 1000
) -> Dict[str, Any]:
    """
    Generate a complete STIX 2.1 bundle.

    Args:
        conn: Database connection
        min_score: Minimum composite_score for IOCs
        lifecycle_states: List of lifecycle states to include (default: all)
        actor: Filter by actor name
        limit: Maximum number of IOCs to include

    Returns:
        STIX 2.1 bundle object
    """
    cursor = conn.cursor()
    objects = []

    # Add identity and marking definitions
    objects.append(get_identity_object())
    objects.extend(get_tlp_marking_definitions())

    # Fetch and add IP indicators
    query = """
        SELECT ip, composite_score, infrastructure_risk_score,
               actor_attribution_score, actor_attribution_actor,
               lifecycle_state, first_seen, last_seen, validation_count,
               stix_id, mitre_techniques
        FROM ipv4_iocs
        WHERE composite_score >= ?
    """
    params = [min_score]

    if lifecycle_states:
        placeholders = ",".join("?" * len(lifecycle_states))
        query += f" AND lifecycle_state IN ({placeholders})"
        params.extend(lifecycle_states)

    if actor:
        query += " AND actor_attribution_actor = ?"
        params.append(actor)

    query += " LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    ip_rows = cursor.fetchall()

    for ip_row in ip_rows:
        indicator = ip_to_stix_indicator(ip_row, conn)
        objects.append(indicator)

    # Fetch and add domain indicators
    cursor.execute("""
        SELECT domain, first_seen FROM domains
        ORDER BY first_seen DESC
        LIMIT ?
    """, (limit // 2,))

    domain_rows = cursor.fetchall()
    for domain_row in domain_rows:
        indicator = domain_to_stix_indicator(domain_row)
        objects.append(indicator)

    # Fetch and add URL indicators
    cursor.execute("""
        SELECT url, host, first_seen FROM urls
        ORDER BY first_seen DESC
        LIMIT ?
    """, (limit // 2,))

    url_rows = cursor.fetchall()
    for url_row in url_rows:
        indicator = url_to_stix_indicator(url_row)
        objects.append(indicator)

    # Fetch and add campaigns with related intrusion-sets
    cursor.execute("""
        SELECT id, campaign_name, aliases, threat_actor_type,
               origin_country, description, ttps
        FROM campaigns
        LIMIT ?
    """, (limit // 4,))

    campaign_rows = cursor.fetchall()
    for campaign_row in campaign_rows:
        campaign_objects = campaign_to_stix(campaign_row, conn)
        objects.extend(campaign_objects)

    # Create relationships between indicators and campaigns
    cursor.execute("""
        SELECT DISTINCT ci.ioc_value, c.campaign_name, c.id
        FROM campaign_iocs ci
        JOIN campaigns c ON ci.campaign_id = c.id
        WHERE ci.ioc_type = 'ipv4'
    """)

    relationships = cursor.fetchall()
    timestamp = datetime.utcnow().isoformat() + "Z"

    for ioc_value, campaign_name, campaign_id in relationships:
        # Find matching indicator IDs
        ip_id = generate_stix_id("indicator", f"ipv4-{ioc_value}")
        campaign_id_stix = generate_stix_id("campaign", f"campaign-{campaign_name}")

        relationship = {
            "type": "relationship",
            "id": generate_stix_id("relationship", f"{ip_id}-{campaign_id_stix}"),
            "created": timestamp,
            "modified": timestamp,
            "relationship_type": "indicates",
            "source_ref": ip_id,
            "target_ref": campaign_id_stix,
            "object_marking_refs": [TLP_MARKINGS["WHITE"]],
        }
        objects.append(relationship)

    # Build bundle
    bundle = {
        "type": "bundle",
        "id": generate_stix_id("bundle", f"aptwatch-{datetime.utcnow().isoformat()}"),
        "objects": objects
    }

    return bundle


def assign_stix_ids(conn: sqlite3.Connection) -> int:
    """
    Generate and store STIX IDs for all ipv4_iocs without one.

    Args:
        conn: Database connection

    Returns:
        Number of IDs assigned
    """
    cursor = conn.cursor()

    # Find rows without stix_id
    cursor.execute("SELECT ip FROM ipv4_iocs WHERE stix_id IS NULL")
    rows = cursor.fetchall()

    count = 0
    for (ip,) in rows:
        stix_id = generate_stix_id("indicator", f"ipv4-{ip}")
        cursor.execute("UPDATE ipv4_iocs SET stix_id = ? WHERE ip = ?", (stix_id, ip))
        count += 1

    conn.commit()
    return count


def export_to_file(
    filepath: str,
    conn: sqlite3.Connection,
    **kwargs
) -> None:
    """
    Generate STIX bundle and write to JSON file.

    Args:
        filepath: Output file path
        conn: Database connection
        **kwargs: Additional arguments for generate_stix_bundle
    """
    bundle = generate_stix_bundle(conn, **kwargs)

    with open(filepath, "w") as f:
        json.dump(bundle, f, indent=2)

    print(f"Exported STIX bundle to {filepath}")
    print(f"Total objects: {len(bundle['objects'])}")


def get_export_stats(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Get statistics about the data available for export.

    Args:
        conn: Database connection

    Returns:
        Dictionary with export statistics
    """
    cursor = conn.cursor()

    stats = {}

    # Count IOCs
    cursor.execute("SELECT COUNT(*) FROM ipv4_iocs")
    stats["ipv4_iocs"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM domains")
    stats["domains"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM urls")
    stats["urls"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM campaigns")
    stats["campaigns"] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_actors")
    stats["threat_actors"] = cursor.fetchone()[0]

    # Count by lifecycle state
    cursor.execute("""
        SELECT lifecycle_state, COUNT(*) as count
        FROM ipv4_iocs
        GROUP BY lifecycle_state
    """)
    stats["by_lifecycle_state"] = {row[0]: row[1] for row in cursor.fetchall()}

    # Count by score
    cursor.execute("""
        SELECT
            SUM(CASE WHEN composite_score >= 0.8 THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN composite_score >= 0.5 AND composite_score < 0.8 THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN composite_score < 0.5 THEN 1 ELSE 0 END) as low
        FROM ipv4_iocs
    """)
    row = cursor.fetchone()
    stats["by_confidence"] = {
        "high": row[0] or 0,
        "medium": row[1] or 0,
        "low": row[2] or 0,
    }

    # Count IDs assigned
    cursor.execute("SELECT COUNT(*) FROM ipv4_iocs WHERE stix_id IS NOT NULL")
    stats["stix_ids_assigned"] = cursor.fetchone()[0]

    return stats


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="STIX 2.1 export module for APTWatch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python export_stix.py bundle --output bundle.json
  python export_stix.py bundle --min-score 0.6 --state active
  python export_stix.py bundle --actor APT29 --limit 500
  python export_stix.py assign-ids
  python export_stix.py stats
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Bundle command
    bundle_parser = subparsers.add_parser("bundle", help="Generate STIX bundle")
    bundle_parser.add_argument(
        "--min-score", type=float, default=0.0,
        help="Minimum composite score (0-1)"
    )
    bundle_parser.add_argument(
        "--state", dest="states", action="append",
        help="Lifecycle state to include (can be specified multiple times)"
    )
    bundle_parser.add_argument(
        "--actor", help="Filter by threat actor name"
    )
    bundle_parser.add_argument(
        "--limit", type=int, default=1000,
        help="Maximum number of IOCs to export"
    )
    bundle_parser.add_argument(
        "--output", default="stix_bundle.json",
        help="Output file path"
    )

    # Assign IDs command
    subparsers.add_parser("assign-ids", help="Assign STIX IDs to all IOCs")

    # Stats command
    subparsers.add_parser("stats", help="Show export statistics")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Connect to database
    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)

    try:
        if args.command == "bundle":
            export_to_file(
                args.output,
                conn,
                min_score=args.min_score,
                lifecycle_states=args.states,
                actor=args.actor,
                limit=args.limit
            )

        elif args.command == "assign-ids":
            count = assign_stix_ids(conn)
            print(f"Assigned {count} STIX IDs")

        elif args.command == "stats":
            stats = get_export_stats(conn)
            print("\nAPTWatch Export Statistics:")
            print("=" * 50)
            for key, value in stats.items():
                if isinstance(value, dict):
                    print(f"\n{key.replace('_', ' ').title()}:")
                    for k, v in value.items():
                        print(f"  {k}: {v}")
                else:
                    print(f"{key.replace('_', ' ').title()}: {value}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
