#!/usr/bin/env python3
"""
Lifecycle and decay logic module for APTWatch threat intelligence platform.

Manages IOC lifecycle states (active, stale, expired, archived) and applies
decay multipliers based on age. Tracks state transitions in lifecycle_history.
"""

import os
import sqlite3
import sys
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path
DB_PATH = Path(os.environ.get("APT_INTEL_DB", Path(__file__).parent.parent / "database" / "apt_intel.db"))


def calculate_decay_multiplier(last_seen_date_str: Optional[str]) -> float:
    """
    Calculate decay multiplier based on days since last observation.

    Args:
        last_seen_date_str: ISO format date string or None

    Returns:
        float: Decay multiplier (0.0 to 1.0)
    """
    if not last_seen_date_str or last_seen_date_str.strip() == '':
        return 0.15

    try:
        last_seen = datetime.fromisoformat(last_seen_date_str.replace('Z', '+00:00'))
        now = datetime.utcnow()
        days_since = (now - last_seen).days

        if days_since < 7:
            return 1.0
        elif days_since < 14:
            return 0.95
        elif days_since < 30:
            return 0.85
        elif days_since < 60:
            return 0.65
        elif days_since < 90:
            return 0.35
        else:
            return 0.15
    except (ValueError, AttributeError) as e:
        logger.warning(f"Failed to parse date '{last_seen_date_str}': {e}")
        return 0.15


def determine_lifecycle_state(last_seen_date_str: Optional[str]) -> str:
    """
    Determine lifecycle state based on last observation date.

    Args:
        last_seen_date_str: ISO format date string or None

    Returns:
        str: Lifecycle state (active, stale, or expired)
    """
    if not last_seen_date_str or last_seen_date_str.strip() == '':
        return 'expired'

    try:
        last_seen = datetime.fromisoformat(last_seen_date_str.replace('Z', '+00:00'))
        now = datetime.utcnow()
        days_since = (now - last_seen).days

        if days_since < 7:
            return 'active'
        elif days_since < 90:
            return 'stale'
        else:
            return 'expired'
    except (ValueError, AttributeError) as e:
        logger.warning(f"Failed to parse date '{last_seen_date_str}': {e}")
        return 'expired'


def assess_single_ioc(ioc_id: int, conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Assess lifecycle state and decay for a single IOC.

    Calculates new state and decay multiplier, records transitions in
    lifecycle_history if state changed, and updates the IOC record.

    Args:
        ioc_id: IOC identifier
        conn: Database connection

    Returns:
        dict: Assessment result with old_state, new_state, decay_multiplier, transitioned
    """
    cursor = conn.cursor()

    # Fetch current IOC
    cursor.execute(
        "SELECT id, ip, last_seen, composite_score, lifecycle_state, decay_multiplier "
        "FROM ipv4_iocs WHERE id = ?",
        (ioc_id,)
    )
    row = cursor.fetchone()

    if not row:
        logger.warning(f"IOC {ioc_id} not found")
        return {'error': 'IOC not found'}

    ioc_id, ioc_value, last_seen, composite_score, old_state, old_decay = row

    # Calculate new state and decay
    new_state = determine_lifecycle_state(last_seen)
    new_decay = calculate_decay_multiplier(last_seen)

    # Record transition if state changed
    transitioned = False
    if new_state != old_state:
        transitioned = True
        new_score = composite_score * new_decay
        old_score = composite_score * old_decay

        cursor.execute(
            "INSERT INTO lifecycle_history "
            "(ioc_id, ioc_type, ioc_value, old_state, new_state, old_score, new_score, reason, transition_date) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ioc_id, 'ipv4', ioc_value, old_state, new_state, old_score, new_score,
             f'Automatic assessment: {last_seen}', datetime.utcnow().isoformat())
        )
        logger.debug(f"IOC {ioc_value} transitioned: {old_state} -> {new_state}")

    # Update IOC record
    cursor.execute(
        "UPDATE ipv4_iocs SET lifecycle_state = ?, decay_multiplier = ?, lifecycle_assessed_at = ? "
        "WHERE id = ?",
        (new_state, new_decay, datetime.utcnow().isoformat(), ioc_id)
    )

    return {
        'ioc_id': ioc_id,
        'ioc_value': ioc_value,
        'old_state': old_state,
        'new_state': new_state,
        'decay_multiplier': new_decay,
        'transitioned': transitioned
    }


def batch_assess_all(conn: sqlite3.Connection, limit: Optional[int] = None) -> Dict[str, Any]:
    """
    Assess lifecycle state for all IOCs in batch.

    Commits in batches of 500 and prints progress every 1000 IOCs.

    Args:
        conn: Database connection
        limit: Maximum number of IOCs to assess (None for all)

    Returns:
        dict: Statistics with counts of active, stale, expired, and transitions
    """
    cursor = conn.cursor()

    # Get total count
    cursor.execute("SELECT COUNT(*) FROM ipv4_iocs")
    total = cursor.fetchone()[0]

    if limit:
        total = min(total, limit)

    logger.info(f"Starting lifecycle assessment for {total} IOCs")

    stats = {
        'active': 0,
        'stale': 0,
        'expired': 0,
        'transitions': 0,
        'total': total
    }

    # Fetch all IOC IDs
    query = "SELECT id FROM ipv4_iocs"
    if limit:
        query += f" LIMIT {limit}"

    cursor.execute(query)
    ioc_ids = [row[0] for row in cursor.fetchall()]

    batch_size = 500
    for i, ioc_id in enumerate(ioc_ids):
        result = assess_single_ioc(ioc_id, conn)

        if 'error' not in result:
            new_state = result['new_state']
            stats[new_state] += 1
            if result['transitioned']:
                stats['transitions'] += 1

        # Progress logging
        if (i + 1) % 1000 == 0:
            logger.info(f"Assessed {i + 1}/{total} IOCs")

        # Batch commit
        if (i + 1) % batch_size == 0:
            conn.commit()
            logger.debug(f"Committed batch at {i + 1}")

    # Final commit
    conn.commit()
    logger.info(f"Lifecycle assessment complete: {stats}")

    return stats


def reactivate_ioc(ioc_id: int, conn: sqlite3.Connection, reason: str = 'validation_found') -> bool:
    """
    Reactivate an IOC and reset decay multiplier.

    Args:
        ioc_id: IOC identifier
        conn: Database connection
        reason: Reason for reactivation

    Returns:
        bool: True if successful, False otherwise
    """
    cursor = conn.cursor()

    # Fetch current state
    cursor.execute(
        "SELECT ip, lifecycle_state, composite_score, decay_multiplier FROM ipv4_iocs WHERE id = ?",
        (ioc_id,)
    )
    row = cursor.fetchone()

    if not row:
        logger.warning(f"IOC {ioc_id} not found for reactivation")
        return False

    ioc_value, old_state, composite_score, old_decay = row
    old_score = composite_score * old_decay

    # Update to active state
    cursor.execute(
        "UPDATE ipv4_iocs SET lifecycle_state = ?, decay_multiplier = ?, lifecycle_assessed_at = ? "
        "WHERE id = ?",
        ('active', 1.0, datetime.utcnow().isoformat(), ioc_id)
    )

    # Record in history
    new_score = composite_score * 1.0
    cursor.execute(
        "INSERT INTO lifecycle_history "
        "(ioc_id, ioc_type, ioc_value, old_state, new_state, old_score, new_score, reason, transition_date) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ioc_id, 'ipv4', ioc_value, old_state, 'active', old_score, new_score,
         reason, datetime.utcnow().isoformat())
    )

    conn.commit()
    logger.info(f"Reactivated IOC {ioc_value}: {old_state} -> active ({reason})")

    return True


def get_lifecycle_stats(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Get comprehensive lifecycle statistics.

    Returns counts by lifecycle state, average decay multiplier per state,
    and transition counts for various time windows.

    Args:
        conn: Database connection

    Returns:
        dict: Lifecycle statistics
    """
    cursor = conn.cursor()
    now = datetime.utcnow()

    # Count by state
    cursor.execute(
        "SELECT lifecycle_state, COUNT(*) FROM ipv4_iocs GROUP BY lifecycle_state"
    )
    state_counts = {row[0]: row[1] for row in cursor.fetchall()}

    # Average decay per state
    cursor.execute(
        "SELECT lifecycle_state, AVG(decay_multiplier) FROM ipv4_iocs "
        "GROUP BY lifecycle_state"
    )
    avg_decay = {row[0]: row[1] for row in cursor.fetchall()}

    # Transitions in time windows
    transitions_24h = transitions_7d = transitions_30d = 0

    for hours in [24, 168, 720]:  # 24h, 7d, 30d
        cutoff = (now - timedelta(hours=hours)).isoformat()
        cursor.execute(
            "SELECT COUNT(*) FROM lifecycle_history WHERE transition_date > ?",
            (cutoff,)
        )
        count = cursor.fetchone()[0]

        if hours == 24:
            transitions_24h = count
        elif hours == 168:
            transitions_7d = count
        elif hours == 720:
            transitions_30d = count

    return {
        'state_counts': state_counts,
        'avg_decay_by_state': avg_decay,
        'transitions_24h': transitions_24h,
        'transitions_7d': transitions_7d,
        'transitions_30d': transitions_30d,
        'total_iocs': sum(state_counts.values())
    }


def get_effective_score(ip: str, conn: sqlite3.Connection) -> Optional[float]:
    """
    Get effective threat score for an IP (composite_score * decay_multiplier).

    Args:
        ip: IP address
        conn: Database connection

    Returns:
        float: Effective score, or None if IP not found
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT composite_score, decay_multiplier FROM ipv4_iocs WHERE ip = ?",
        (ip,)
    )
    row = cursor.fetchone()

    if not row:
        return None

    composite_score, decay_multiplier = row
    return composite_score * decay_multiplier


def show_ioc_lifecycle(ip: str, conn: sqlite3.Connection) -> None:
    """
    Display current lifecycle state and decay for an IP.

    Args:
        ip: IP address
        conn: Database connection
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, ip, first_seen, last_seen, composite_score, "
        "lifecycle_state, decay_multiplier, lifecycle_assessed_at "
        "FROM ipv4_iocs WHERE ip = ?",
        (ip,)
    )
    row = cursor.fetchone()

    if not row:
        print(f"IP {ip} not found")
        return

    (ioc_id, ioc_value, first_seen, last_seen, composite_score,
     lifecycle_state, decay_multiplier, assessed_at) = row

    effective_score = composite_score * decay_multiplier

    print(f"\n{'='*60}")
    print(f"IOC Lifecycle: {ioc_value}")
    print(f"{'='*60}")
    print(f"First Seen:        {first_seen}")
    print(f"Last Seen:         {last_seen}")
    print(f"Lifecycle State:   {lifecycle_state}")
    print(f"Decay Multiplier:  {decay_multiplier:.2f}")
    print(f"Composite Score:   {composite_score:.2f}")
    print(f"Effective Score:   {effective_score:.2f}")
    print(f"Assessed At:       {assessed_at}")
    print(f"{'='*60}\n")


def show_ioc_history(ip: str, conn: sqlite3.Connection) -> None:
    """
    Display transition history for an IP.

    Args:
        ip: IP address
        conn: Database connection
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, old_state, new_state, old_score, new_score, reason, transition_date "
        "FROM lifecycle_history WHERE ioc_value = ? ORDER BY transition_date DESC",
        (ip,)
    )
    rows = cursor.fetchall()

    if not rows:
        print(f"No transition history for {ip}")
        return

    print(f"\n{'='*80}")
    print(f"Transition History: {ip}")
    print(f"{'='*80}")

    for row in rows:
        trans_id, old_state, new_state, old_score, new_score, reason, trans_date = row
        print(f"\nID: {trans_id}")
        print(f"  Date:     {trans_date}")
        print(f"  State:    {old_state} -> {new_state}")
        print(f"  Score:    {old_score:.2f} -> {new_score:.2f}")
        print(f"  Reason:   {reason}")

    print(f"\n{'='*80}\n")


def cli():
    """Command-line interface."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python lifecycle.py assess [limit]    - Run lifecycle assessment")
        print("  python lifecycle.py show <ip>         - Show lifecycle for an IP")
        print("  python lifecycle.py stats             - Lifecycle statistics")
        print("  python lifecycle.py history <ip>      - Transition history for IP")
        sys.exit(1)

    command = sys.argv[1]

    try:
        conn = sqlite3.connect(DB_PATH)

        if command == 'assess':
            limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
            stats = batch_assess_all(conn, limit)
            print(f"\nAssessment complete:")
            print(f"  Active:  {stats['active']}")
            print(f"  Stale:   {stats['stale']}")
            print(f"  Expired: {stats['expired']}")
            print(f"  Transitions: {stats['transitions']}")

        elif command == 'show':
            if len(sys.argv) < 3:
                print("Usage: python lifecycle.py show <ip>")
                sys.exit(1)
            ip = sys.argv[2]
            show_ioc_lifecycle(ip, conn)

        elif command == 'stats':
            stats = get_lifecycle_stats(conn)
            print(f"\n{'='*60}")
            print("Lifecycle Statistics")
            print(f"{'='*60}")
            print(f"Total IOCs: {stats['total_iocs']}")
            print(f"\nState Counts:")
            for state, count in stats['state_counts'].items():
                avg_decay = stats['avg_decay_by_state'].get(state, 0.0)
                print(f"  {state:10s}: {count:6d} (avg decay: {avg_decay:.2f})")
            print(f"\nTransitions:")
            print(f"  Last 24h: {stats['transitions_24h']}")
            print(f"  Last 7d:  {stats['transitions_7d']}")
            print(f"  Last 30d: {stats['transitions_30d']}")
            print(f"{'='*60}\n")

        elif command == 'history':
            if len(sys.argv) < 3:
                print("Usage: python lifecycle.py history <ip>")
                sys.exit(1)
            ip = sys.argv[2]
            show_ioc_history(ip, conn)

        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

        conn.close()

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
