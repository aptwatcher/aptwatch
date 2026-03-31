#!/usr/bin/env python3
"""
Suricata/Snort IDS rule export module for APTWatch.
Generates detection rules from APT Intelligence database with configurable filters.
"""

import sqlite3
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Tuple


DB_PATH = Path(__file__).parent.parent / "database" / "apt_intel.db"

# Rule SID allocation ranges
SID_RANGES = {
    "ip": 9100001,
    "domain": 9200001,
    "subnet": 9300001,
}

# Score tiers for reporting
SCORE_TIERS = {
    "critical": (0.9, 1.0),
    "high": (0.7, 0.9),
    "medium": (0.5, 0.7),
    "low": (0.0, 0.5),
}


def generate_ip_rule(ip: str, sid: int, actor: Optional[str] = None,
                     role: Optional[str] = None, score: float = 0.0) -> Tuple[str, str]:
    """
    Generate forward and reverse IP detection rules.

    Args:
        ip: IP address to detect
        sid: Suricata rule ID (base)
        actor: Threat actor attribution
        role: IOC role/classification
        score: Composite threat score (0.0-1.0)

    Returns:
        Tuple of (forward_rule, reverse_rule)
    """
    actor_str = actor if actor else "Threat"
    role_str = role if role else "Malicious IP"
    score_str = f"{score:.2f}"

    # Forward rule: detect traffic TO the malicious IP
    forward_rule = (
        f'alert ip any any -> {ip} any '
        f'(msg:"APTWatch | {actor_str} | {role_str} | score:{score_str}"; '
        f'reference:url,https://api.aptwatch.org/api/ioc/{ip}; '
        f'classtype:trojan-activity; '
        f'sid:{sid}; rev:1; '
        f'metadata:created_by APTWatch, score {score_str};)'
    )

    # Reverse rule: detect traffic FROM the malicious IP
    reverse_sid = sid + 50000
    reverse_rule = (
        f'alert ip {ip} any -> any any '
        f'(msg:"APTWatch | {actor_str} | {role_str} (outbound) | score:{score_str}"; '
        f'reference:url,https://api.aptwatch.org/api/ioc/{ip}; '
        f'classtype:trojan-activity; '
        f'sid:{reverse_sid}; rev:1; '
        f'metadata:created_by APTWatch, score {score_str};)'
    )

    return forward_rule, reverse_rule


def generate_domain_rule(domain: str, sid: int) -> str:
    """
    Generate DNS-based domain detection rule.

    Args:
        domain: Domain name to detect
        sid: Suricata rule ID

    Returns:
        DNS detection rule string
    """
    rule = (
        f'alert dns any any -> any any '
        f'(msg:"APTWatch | Malicious Domain | {domain}"; '
        f'dns.query; content:"{domain}"; nocase; '
        f'classtype:trojan-activity; '
        f'sid:{sid}; rev:1;)'
    )
    return rule


def generate_subnet_rule(cidr: str, sid: int, ioc_count: int = 0) -> str:
    """
    Generate subnet/CIDR detection rule.

    Args:
        cidr: CIDR notation (e.g., 192.168.1.0/24)
        sid: Suricata rule ID
        ioc_count: Number of IOCs in this subnet

    Returns:
        Subnet detection rule string
    """
    msg_suffix = f" ({ioc_count} known IOCs)" if ioc_count > 0 else ""
    rule = (
        f'alert ip any any -> {cidr} any '
        f'(msg:"APTWatch | Malicious Subnet{msg_suffix} | {cidr}"; '
        f'classtype:trojan-activity; '
        f'sid:{sid}; rev:1; '
        f'metadata:created_by APTWatch, ioc_count {ioc_count};)'
    )
    return rule


def get_export_stats(conn: sqlite3.Connection, min_score: float = 0.0) -> Dict:
    """
    Generate export statistics without creating rules.

    Args:
        conn: SQLite database connection
        min_score: Minimum composite score threshold

    Returns:
        Dictionary with export statistics
    """
    cursor = conn.cursor()

    # Count IPs by score tier and actor
    ip_stats = {"total": 0, "by_actor": {}, "by_score_tier": {}}

    for tier, (min_t, max_t) in SCORE_TIERS.items():
        cursor.execute(
            "SELECT COUNT(*) FROM ipv4_iocs WHERE composite_score >= ? AND composite_score < ?",
            (max(min_t, min_score), max_t)
        )
        count = cursor.fetchone()[0]
        ip_stats["by_score_tier"][tier] = count
        ip_stats["total"] += count

    # Count by actor
    cursor.execute(
        "SELECT actor_attribution_actor, COUNT(*) FROM ipv4_iocs "
        "WHERE composite_score >= ? AND actor_attribution_actor IS NOT NULL "
        "GROUP BY actor_attribution_actor ORDER BY COUNT(*) DESC",
        (min_score,)
    )
    for actor, count in cursor.fetchall():
        if actor:
            ip_stats["by_actor"][actor] = count

    # Count domains
    cursor.execute("SELECT COUNT(*) FROM domains")
    domain_count = cursor.fetchone()[0]

    # Count subnets with high density (>10% IOC density)
    cursor.execute(
        "SELECT COUNT(*) FROM subnets WHERE "
        "(SELECT COUNT(*) FROM ipv4_iocs WHERE ipv4_iocs.ip LIKE subnets.cidr) > 0"
    )
    subnet_count = cursor.fetchone()[0]

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "ip_stats": ip_stats,
        "domain_count": domain_count,
        "subnet_count": subnet_count,
        "filters": {
            "min_score": min_score,
        }
    }


def export_rules(conn: sqlite3.Connection, min_score: float = 0.0,
                 lifecycle_states: Optional[List[str]] = None,
                 actor: Optional[str] = None,
                 include_domains: bool = True,
                 include_subnets: bool = True,
                 limit: int = 5000) -> str:
    """
    Generate complete Suricata rules file content.

    Args:
        conn: SQLite database connection
        min_score: Minimum composite score threshold
        lifecycle_states: List of lifecycle states to include (e.g., ['active', 'confirmed'])
        actor: Specific actor to filter by
        include_domains: Include domain detection rules
        include_subnets: Include subnet detection rules for high-density subnets
        limit: Maximum number of IP rules to generate

    Returns:
        Complete .rules file content as string
    """
    cursor = conn.cursor()
    rules = []

    # Generate header
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"""# APTWatch Suricata/Snort Rule Export
# Generated: {timestamp}
# Source: APT Intelligence Database
#
# Filter Configuration:
#   Min Score: {min_score}
#   Lifecycle States: {lifecycle_states if lifecycle_states else 'All'}
#   Actor Filter: {actor if actor else 'None'}
#   Include Domains: {include_domains}
#   Include Subnets: {include_subnets}
#
# Rule SID Ranges:
#   IP Rules: 9100001-9149999
#   Reverse IP Rules: 9150001-9199999
#   Domain Rules: 9200001-9249999
#   Subnet Rules: 9300001-9399999
#

"""
    rules.append(header)

    # Generate IP rules
    ip_query = "SELECT ip, composite_score, actor_attribution_actor FROM ipv4_iocs WHERE composite_score >= ?"
    params = [min_score]

    if lifecycle_states:
        placeholders = ",".join("?" * len(lifecycle_states))
        ip_query += f" AND lifecycle_state IN ({placeholders})"
        params.extend(lifecycle_states)

    if actor:
        ip_query += " AND actor_attribution_actor = ?"
        params.append(actor)

    ip_query += " ORDER BY composite_score DESC LIMIT ?"
    params.append(limit)

    cursor.execute(ip_query, params)
    ip_rules = []
    sid_counter = SID_RANGES["ip"]

    for ip, score, ip_actor in cursor.fetchall():
        # Get role from campaign_iocs if available
        cursor.execute(
            "SELECT role FROM campaign_iocs WHERE ioc_value = ? LIMIT 1",
            (ip,)
        )
        role_row = cursor.fetchone()
        role = role_row[0] if role_row else None

        forward_rule, reverse_rule = generate_ip_rule(ip, sid_counter, ip_actor, role, score)
        ip_rules.append(forward_rule)
        ip_rules.append(reverse_rule)
        sid_counter += 1

    rules.append(f"# IP Rules ({len(ip_rules)} rules)\n")
    rules.extend(ip_rules)
    rules.append("\n")

    # Generate domain rules
    if include_domains:
        cursor.execute("SELECT domain FROM domains ORDER BY domain ASC LIMIT ?", (limit,))
        domain_rules = []
        sid_counter = SID_RANGES["domain"]

        for (domain,) in cursor.fetchall():
            rule = generate_domain_rule(domain, sid_counter)
            domain_rules.append(rule)
            sid_counter += 1

        rules.append(f"# Domain Rules ({len(domain_rules)} rules)\n")
        rules.extend(domain_rules)
        rules.append("\n")

    # Generate subnet rules for high-density subnets
    if include_subnets:
        cursor.execute("SELECT cidr, ioc_count FROM subnets WHERE ioc_count > 0 ORDER BY ioc_count DESC LIMIT ?", (limit // 10,))
        subnet_rules = []
        sid_counter = SID_RANGES["subnet"]

        for cidr, ioc_count in cursor.fetchall():
            rule = generate_subnet_rule(cidr, sid_counter, ioc_count)
            subnet_rules.append(rule)
            sid_counter += 1

        rules.append(f"# Subnet Rules ({len(subnet_rules)} rules)\n")
        rules.extend(subnet_rules)
        rules.append("\n")

    return "".join(rules)


def export_to_file(filepath: Path, conn: sqlite3.Connection, **kwargs) -> None:
    """
    Generate rules and write to file.

    Args:
        filepath: Output file path (.rules file)
        conn: SQLite database connection
        **kwargs: Additional arguments for export_rules()
    """
    rules_content = export_rules(conn, **kwargs)

    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        f.write(rules_content)

    print(f"Rules exported to {filepath}")
    print(f"Total size: {len(rules_content):,} bytes")


def cmd_rules(args) -> int:
    """Handle 'rules' subcommand."""
    try:
        conn = sqlite3.connect(DB_PATH)

        # Prepare filter parameters
        lifecycle_states = None
        if args.state:
            lifecycle_states = [s.strip() for s in args.state.split(",")]

        # Generate rules
        output_path = Path(args.output) if args.output else Path("apt-intel.rules")

        export_to_file(
            output_path,
            conn,
            min_score=args.min_score,
            lifecycle_states=lifecycle_states,
            actor=args.actor,
            include_domains=not args.exclude_domains,
            include_subnets=not args.exclude_subnets,
            limit=args.limit
        )

        conn.close()
        return 0
    except Exception as e:
        print(f"Error exporting rules: {e}", file=sys.stderr)
        return 1


def cmd_stats(args) -> int:
    """Handle 'stats' subcommand."""
    try:
        conn = sqlite3.connect(DB_PATH)
        stats = get_export_stats(conn, min_score=args.min_score)
        conn.close()

        # Display statistics
        print(f"Export Statistics (min_score={args.min_score})")
        print(f"Generated: {stats['timestamp']}")
        print()

        print("IP Rules:")
        print(f"  Total: {stats['ip_stats']['total']}")
        print("  By Score Tier:")
        for tier, count in stats['ip_stats']['by_score_tier'].items():
            print(f"    {tier}: {count}")

        if stats['ip_stats']['by_actor']:
            print("  By Actor (Top 10):")
            for actor, count in sorted(stats['ip_stats']['by_actor'].items(),
                                      key=lambda x: x[1], reverse=True)[:10]:
                print(f"    {actor}: {count}")

        print()
        print(f"Domain Rules: {stats['domain_count']}")
        print(f"Subnet Rules: {stats['subnet_count']}")

        return 0
    except Exception as e:
        print(f"Error retrieving statistics: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="APTWatch Suricata/Snort IDS rule export utility"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Rules export command
    rules_parser = subparsers.add_parser(
        "rules",
        help="Export IDS detection rules"
    )
    rules_parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum composite score threshold (0.0-1.0, default: 0.0)"
    )
    rules_parser.add_argument(
        "--state",
        type=str,
        help="Comma-separated lifecycle states to include (e.g., 'active,confirmed')"
    )
    rules_parser.add_argument(
        "--actor",
        type=str,
        help="Filter by specific threat actor"
    )
    rules_parser.add_argument(
        "--output",
        type=str,
        default="apt-intel.rules",
        help="Output rules file path (default: apt-intel.rules)"
    )
    rules_parser.add_argument(
        "--exclude-domains",
        action="store_true",
        help="Exclude domain detection rules"
    )
    rules_parser.add_argument(
        "--exclude-subnets",
        action="store_true",
        help="Exclude subnet detection rules"
    )
    rules_parser.add_argument(
        "--limit",
        type=int,
        default=5000,
        help="Maximum number of IP rules to generate (default: 5000)"
    )
    rules_parser.set_defaults(func=cmd_rules)

    # Statistics command
    stats_parser = subparsers.add_parser(
        "stats",
        help="Display export statistics"
    )
    stats_parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum composite score threshold (0.0-1.0, default: 0.0)"
    )
    stats_parser.set_defaults(func=cmd_stats)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
