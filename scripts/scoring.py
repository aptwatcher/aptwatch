#!/usr/bin/env python3
"""
Weighted IOC Scoring Engine for APTWatch Threat Intelligence Platform

Implements comprehensive composite and infrastructure risk scoring for IPv4 indicators
of compromise (IOCs) using multi-source validation data, ASN enrichment, and provider
risk profiling. Scores are normalized to 0.0–1.0 range with configurable multipliers
for bulletproof hosting, cloud providers, and abuse-tolerant ASNs.

Core Functions:
  calculate_composite_score(ip, conn)     → float 0.0–1.0 (weighted source validation)
  calculate_infrastructure_risk(ip, conn) → float 0.0–1.0 (4-component risk model)
  get_provider_risk_level(ip, conn)       → str (provider type from enrichment)
  get_source_confidence(source, raw_data) → float 0.0–1.0 (API-specific confidence)
  batch_score_all(conn, limit=5000)       → int (count updated, committed in batches)

Database: SQLite (WAL mode), reads from ipv4_iocs, source_validations, scoring_sources,
asn_info, enrichment_results, subnets, cert_patterns; writes to ipv4_iocs scoring fields.

CLI Usage:
  python scoring.py recalc [limit]     # Recalculate all scores
  python scoring.py show <ip>          # Show score breakdown for an IP
  python scoring.py top [N]            # Top N highest-scored IOCs
  python scoring.py stats              # Scoring statistics

Author: APTWatch Threat Intel Platform
Date: 2025
License: Proprietary
"""

import os
import sqlite3
import json
import sys
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any

# ============================================================================
# Configuration & Constants
# ============================================================================

DB_PATH = Path(os.environ.get("APT_INTEL_DB", Path(__file__).parent.parent / "database" / "apt_intel.db"))
LOG_DIR = Path(__file__).parent.parent / "database" / "logs"
LOG_PATH = LOG_DIR / "scoring.log"

# Ensure log directory exists
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging with rotation (5 MB max, keep 3 backups)
_log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
_file_handler = RotatingFileHandler(LOG_PATH, maxBytes=5*1024*1024, backupCount=3)
_file_handler.setFormatter(_log_formatter)
_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(_log_formatter)

logging.basicConfig(
    level=logging.INFO,
    handlers=[_file_handler, _stream_handler]
)
logger = logging.getLogger(__name__)

# Provider risk multipliers
PROVIDER_MULTIPLIERS = {
    'bulletproof_hosting': 1.5,    # High-risk: increases score
    'abuse_tolerant': 1.2,         # Elevated risk
    'cloud_provider': 0.3,         # FP-prone: decreases risk
    'datacenter': 0.8,             # Neutral
    'isp': 0.9,                    # Mostly benign
    'residential': 0.5,            # Low risk
    'unknown': 1.0,                # No adjustment
}

# Recency scoring thresholds (days)
RECENCY_THRESHOLDS = {
    0: 1.0,      # Seen today: highest risk
    7: 0.9,      # Within 1 week
    30: 0.7,     # Within 1 month
    60: 0.4,     # Within 2 months
    90: 0.1,     # 3+ months: lowest risk
}

# Batch commit size
BATCH_SIZE = 500


# ============================================================================
# Database Connection & Schema Validation
# ============================================================================

def get_connection() -> sqlite3.Connection:
    """
    Create and return a database connection with WAL mode enabled.

    Returns:
        sqlite3.Connection: Connected database handle

    Raises:
        sqlite3.DatabaseError: If database cannot be accessed
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except sqlite3.DatabaseError as e:
        logger.error(f"Database connection failed: {e}")
        raise


def validate_schema(conn: sqlite3.Connection) -> bool:
    """
    Verify required tables exist in database.

    Args:
        conn: Database connection

    Returns:
        bool: True if all required tables exist
    """
    required_tables = [
        'ipv4_iocs',
        'source_validations',
        'scoring_sources',
        'asn_info',
        'enrichment_results',
        'subnets',
        'cert_patterns'
    ]

    cur = conn.cursor()
    for table in required_tables:
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,)
        )
        if not cur.fetchone():
            logger.error(f"Required table '{table}' not found in database")
            return False

    logger.info("Schema validation passed")
    return True


# ============================================================================
# Core Scoring Functions
# ============================================================================

def calculate_composite_score(ip: str, conn: sqlite3.Connection) -> float:
    """
    Calculate weighted composite score from all source validations.

    Algorithm:
      1. Fetch all source_validations for this IP with reliability weights
      2. Sum weighted contributions: score += weight * confidence
      3. Normalize to [0.0, 1.0] by dividing by theoretical max
      4. Apply provider risk multiplier (BPH: 1.5x, cloud: 0.3x cap, etc.)
      5. Clamp final result to [0.0, 1.0]

    Args:
        ip: IPv4 address to score
        conn: Database connection

    Returns:
        float: Composite score in range [0.0, 1.0]
    """
    cur = conn.cursor()

    # Fetch source validations with reliability weights
    cur.execute("""
        SELECT
            sv.source,
            sv.confidence_score,
            ss.reliability_weight
        FROM source_validations sv
        LEFT JOIN scoring_sources ss ON sv.source = ss.source
        WHERE sv.ioc_value = ? AND sv.ioc_type = 'ipv4'
    """, (ip,))

    validations = cur.fetchall()

    if not validations:
        logger.debug(f"No validations found for {ip}")
        return 0.0

    # Calculate weighted score
    total_weight = 0.0
    weighted_sum = 0.0

    for row in validations:
        source = row[0] if row[0] else 'unknown'
        confidence = row[1] if row[1] is not None else 0.0
        weight = row[2] if row[2] is not None else 0.5  # Default weight

        weighted_sum += weight * confidence
        total_weight += weight

    # Normalize to 0.0–1.0
    if total_weight > 0:
        normalized_score = weighted_sum / total_weight
    else:
        normalized_score = 0.0

    # Apply provider risk multiplier
    multiplier = _get_provider_multiplier(ip, conn)
    final_score = normalized_score * multiplier

    # Clamp to valid range
    final_score = max(0.0, min(1.0, final_score))

    logger.debug(f"Composite score for {ip}: {final_score:.3f} "
                f"(normalized={normalized_score:.3f}, multiplier={multiplier:.2f})")

    return final_score


def calculate_infrastructure_risk(ip: str, conn: sqlite3.Connection) -> float:
    """
    Calculate multi-component infrastructure risk score.

    Components:
      - validation_component (40%): composite_score * 0.4
      - provider_component (30%): ASN fp_risk_score inverted (1 - fp for cloud,
        fp for BPH) * 0.3
      - abuse_frequency (20%): validation_count / max_validation_counts * 0.2
      - recency_component (10%): decay based on days since last_seen * 0.1

    Args:
        ip: IPv4 address to score
        conn: Database connection

    Returns:
        float: Infrastructure risk score in range [0.0, 1.0]
    """
    cur = conn.cursor()

    # Fetch IOC data
    cur.execute("""
        SELECT validation_count, last_seen FROM ipv4_iocs WHERE ip = ?
    """, (ip,))
    ioc_row = cur.fetchone()

    if not ioc_row:
        logger.debug(f"IP {ip} not found in ipv4_iocs")
        return 0.0

    validation_count = ioc_row[0] if ioc_row[0] is not None else 0
    last_seen_str = ioc_row[1]

    # Component 1: Validation component (40%)
    composite = calculate_composite_score(ip, conn)
    validation_component = composite * 0.4

    # Component 2: Provider component (30%)
    provider_component = _calculate_provider_component(ip, conn) * 0.3

    # Component 3: Abuse frequency (20%)
    # Normalize by max validation count across all IPs
    cur.execute("SELECT MAX(validation_count) FROM ipv4_iocs")
    max_val_count = cur.fetchone()[0]
    max_val_count = max(max_val_count or 1, 1)  # Avoid division by zero

    abuse_frequency = min(validation_count / max_val_count, 1.0) * 0.2

    # Component 4: Recency component (10%)
    recency_component = _calculate_recency_component(last_seen_str) * 0.1

    # Sum all components
    total_risk = validation_component + provider_component + abuse_frequency + recency_component

    # Clamp to valid range
    total_risk = max(0.0, min(1.0, total_risk))

    logger.debug(f"Infrastructure risk for {ip}: {total_risk:.3f} "
                f"(validation={validation_component:.3f}, provider={provider_component:.3f}, "
                f"abuse={abuse_frequency:.3f}, recency={recency_component:.3f})")

    return total_risk


def get_provider_risk_level(ip: str, conn: sqlite3.Connection) -> str:
    """
    Determine provider risk classification for an IP.

    Lookup chain:
      1. Query enrichment_results for this IP to find ASN
      2. Query asn_info for that ASN's provider_type
      3. Return provider_type or 'unknown' if not found

    Args:
        ip: IPv4 address
        conn: Database connection

    Returns:
        str: Provider type (bulletproof_hosting, abuse_tolerant, cloud_provider,
             datacenter, isp, residential, or unknown)
    """
    cur = conn.cursor()

    # Find ASN from enrichment results
    cur.execute("""
        SELECT asn FROM enrichment_results
        WHERE indicator = ? AND indicator_type = 'ipv4'
        LIMIT 1
    """, (ip,))

    enrich_row = cur.fetchone()
    if not enrich_row or not enrich_row[0]:
        logger.debug(f"No enrichment data found for {ip}")
        return 'unknown'

    asn = enrich_row[0]

    # Look up ASN provider type
    cur.execute("""
        SELECT provider_type FROM asn_info WHERE asn = ?
    """, (asn,))

    asn_row = cur.fetchone()
    if asn_row and asn_row[0]:
        return asn_row[0]

    logger.debug(f"No provider type found for ASN {asn}")
    return 'unknown'


def get_source_confidence(source: str, raw_data: Optional[str]) -> float:
    """
    Derive confidence score from API-specific response data.

    Source-specific scoring:
      - shodan: has_ports or has_vulns → 0.8, has_tags → 0.6, not_indexed → 0.0
      - abuseipdb: abuse_confidence / 100
      - virustotal: malicious / (malicious + harmless + suspicious + undetected)
      - otx: min(pulse_count / 10, 1.0)
      - dshield: min(attacks / 100, 1.0)
      - threatfox: found → 0.9, not found → 0.0
      - firehol: found → 0.7
      - stevenblack: found → 0.5
      - censys: has_services → 0.6

    Args:
        source: API/source name
        raw_data: JSON response string from API call

    Returns:
        float: Confidence score in range [0.0, 1.0]
    """
    if not raw_data:
        return 0.0

    try:
        data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON for source {source}")
        return 0.0

    source_lower = source.lower()

    # Shodan confidence
    if source_lower == 'shodan':
        if data.get('has_ports') or data.get('has_vulns'):
            return 0.8
        if data.get('has_tags'):
            return 0.6
        if data.get('status') == 'not_indexed':
            return 0.0
        return 0.4  # Default for uncategorized

    # AbuseIPDB confidence
    elif source_lower == 'abuseipdb':
        abuse_confidence = data.get('abuseConfidenceScore', 0)
        return min(abuse_confidence / 100.0, 1.0)

    # VirusTotal confidence (multi-engine consensus)
    elif source_lower == 'virustotal':
        malicious = data.get('malicious', 0)
        harmless = data.get('harmless', 0)
        suspicious = data.get('suspicious', 0)
        undetected = data.get('undetected', 0)

        total = malicious + harmless + suspicious + undetected
        if total == 0:
            return 0.0

        # Confidence based on malicious ratio
        return min(malicious / total, 1.0)

    # AlienVault OTX confidence
    elif source_lower == 'otx':
        pulse_count = data.get('pulse_count', 0)
        return min(pulse_count / 10.0, 1.0)

    # DShield confidence
    elif source_lower == 'dshield':
        attacks = data.get('attacks', 0)
        return min(attacks / 100.0, 1.0)

    # ThreatFox confidence
    elif source_lower == 'threatfox':
        found = data.get('found', False)
        return 0.9 if found else 0.0

    # FireHOL blocklist confidence
    elif source_lower == 'firehol':
        found = data.get('found', False)
        return 0.7 if found else 0.0

    # Steven Black hosts confidence
    elif source_lower == 'stevenblack':
        found = data.get('found', False)
        return 0.5 if found else 0.0

    # Censys confidence
    elif source_lower == 'censys':
        has_services = data.get('has_services', False)
        return 0.6 if has_services else 0.2

    # C2 Tracker confidence (local, cached feed)
    elif source_lower == 'c2tracker':
        listed = data.get('listed', False)
        if not listed:
            return 0.0
        # Higher confidence if matched a specific framework (Cobalt Strike, Sliver, etc.)
        frameworks = data.get('c2_frameworks', [])
        if any(f in ('cobalt_strike', 'brute_ratel') for f in frameworks):
            return 0.85  # High-confidence APT-linked C2
        if frameworks:
            return 0.7
        return 0.6  # Generic C2 match

    # TweetFeed confidence (local, cached feed)
    elif source_lower == 'tweetfeed':
        listed = data.get('listed', False)
        if not listed:
            return 0.0
        tags = data.get('tags', '').lower()
        # Higher confidence for APT-tagged entries
        if any(apt in tags for apt in ('kimsuky', 'turla', 'apt28', 'apt29',
                'sandworm', 'gamaredon', 'cozy', 'fancy')):
            return 0.8
        if any(t in tags for t in ('c2', 'rat', 'ransomware', 'stealer')):
            return 0.6
        return 0.5  # Generic malware tag

    # IPsum meta-blacklist confidence
    elif source_lower == 'ipsum':
        listed = data.get('listed', False)
        if not listed:
            return 0.0
        count = data.get('blacklist_count', 0)
        # Score scales with number of blacklists (capped at 1.0)
        # 1-2 lists: low confidence (FP risk), 3-5: moderate, 6+: high
        if count >= 8:
            return 0.9
        elif count >= 5:
            return 0.7
        elif count >= 3:
            return 0.5
        return 0.3  # 1-2 lists — FP-prone

    # Emerging Threats confidence (local, cached feed)
    elif source_lower == 'emerging_threats':
        listed = data.get('listed', False)
        return 0.65 if listed else 0.0

    # Unknown source: return default
    logger.debug(f"Unknown source: {source}")
    return 0.5


def batch_score_all(conn: sqlite3.Connection, limit: int = 5000) -> int:
    """
    Recalculate scores for all IPv4 IOCs in batch.

    Algorithm:
      1. Iterate over ipv4_iocs (optionally limited)
      2. Calculate composite_score and infrastructure_risk_score for each
      3. Determine provider_risk_level from enrichment
      4. Update ipv4_iocs with all scoring fields and timestamp
      5. Commit in batches of 500 to avoid memory bloat
      6. Log progress periodically

    Args:
        conn: Database connection
        limit: Maximum number of IOCs to score (0 = all)

    Returns:
        int: Number of IOCs updated
    """
    cur = conn.cursor()

    # Count total IOCs
    cur.execute("SELECT COUNT(*) FROM ipv4_iocs")
    total_count = cur.fetchone()[0]

    if limit > 0:
        total_count = min(total_count, limit)

    logger.info(f"Starting batch scoring for {total_count} IOCs...")

    # Fetch IPs to score
    query = "SELECT id, ip FROM ipv4_iocs"
    if limit > 0:
        query += f" LIMIT {limit}"

    cur.execute(query)
    ips = cur.fetchall()

    updated_count = 0
    timestamp = datetime.now().isoformat()

    for idx, row in enumerate(ips, start=1):
        ioc_id, ip = row

        try:
            # Calculate scores
            composite = calculate_composite_score(ip, conn)
            infrastructure = calculate_infrastructure_risk(ip, conn)
            provider_level = get_provider_risk_level(ip, conn)

            # Update database
            cur.execute("""
                UPDATE ipv4_iocs
                SET composite_score = ?,
                    infrastructure_risk_score = ?,
                    provider_risk_level = ?,
                    score_timestamp = ?
                WHERE id = ?
            """, (composite, infrastructure, provider_level, timestamp, ioc_id))

            updated_count += 1

            # Commit in batches
            if updated_count % BATCH_SIZE == 0:
                conn.commit()
                logger.info(f"Progress: {idx}/{total_count} IOCs scored "
                           f"({100*idx/total_count:.1f}%)")

        except Exception as e:
            logger.error(f"Error scoring {ip}: {e}")
            conn.rollback()
            continue

    # Final commit
    conn.commit()
    logger.info(f"Batch scoring complete: {updated_count} IOCs updated")

    return updated_count


# ============================================================================
# Helper Functions
# ============================================================================

def _get_provider_multiplier(ip: str, conn: sqlite3.Connection) -> float:
    """
    Get provider-specific risk multiplier for an IP.

    Args:
        ip: IPv4 address
        conn: Database connection

    Returns:
        float: Multiplier factor (typically 0.3–1.5)
    """
    provider = get_provider_risk_level(ip, conn)
    return PROVIDER_MULTIPLIERS.get(provider, 1.0)


def _calculate_provider_component(ip: str, conn: sqlite3.Connection) -> float:
    """
    Calculate provider component of infrastructure risk.

    Inverts fp_risk_score: for cloud providers (low FP risk), decreases score;
    for bulletproof hosting (high FP risk), increases score.

    Args:
        ip: IPv4 address
        conn: Database connection

    Returns:
        float: Provider risk component [0.0, 1.0]
    """
    cur = conn.cursor()
    provider = get_provider_risk_level(ip, conn)

    # Find ASN
    cur.execute("""
        SELECT asn FROM enrichment_results
        WHERE indicator = ? AND indicator_type = 'ipv4'
        LIMIT 1
    """, (ip,))

    enrich_row = cur.fetchone()
    if not enrich_row:
        return 0.5  # Default mid-range

    asn = enrich_row[0]

    # Get fp_risk_score
    cur.execute("SELECT fp_risk_score FROM asn_info WHERE asn = ?", (asn,))
    asn_row = cur.fetchone()

    if not asn_row:
        return 0.5

    fp_risk = asn_row[0] if asn_row[0] is not None else 0.5

    # Invert logic: for cloud (low FP), use 1 - fp_risk; for BPH (high FP), use fp_risk
    if provider == 'cloud_provider':
        return 1.0 - fp_risk  # Inverted: lower score
    else:
        return fp_risk  # Direct: higher score for risky providers


def _calculate_recency_component(last_seen_str: Optional[str]) -> float:
    """
    Calculate recency component based on days since last_seen.

    Thresholds:
      - 0 days (today): 1.0
      - 7 days: 0.9
      - 30 days: 0.7
      - 60 days: 0.4
      - 90+ days: 0.1

    Args:
        last_seen_str: ISO datetime string or None

    Returns:
        float: Recency factor [0.1, 1.0]
    """
    if not last_seen_str:
        return 0.1  # Very old if no last_seen date

    try:
        last_seen = datetime.fromisoformat(last_seen_str.replace('Z', '+00:00'))
        now = datetime.now(last_seen.tzinfo) if last_seen.tzinfo else datetime.now()

        days_ago = (now - last_seen).days
    except (ValueError, TypeError):
        logger.warning(f"Invalid last_seen date: {last_seen_str}")
        return 0.5

    # Find appropriate threshold
    for threshold, score in sorted(RECENCY_THRESHOLDS.items()):
        if days_ago <= threshold:
            return score

    # Older than 90 days
    return RECENCY_THRESHOLDS[90]


def _format_score_display(score: float) -> str:
    """
    Format score as percentage string with color indicators.

    Args:
        score: Score in range [0.0, 1.0]

    Returns:
        str: Formatted score (e.g., "85% (HIGH)")
    """
    if score is None:
        return "N/A (not scored)"
    percentage = score * 100

    if score >= 0.8:
        level = "CRITICAL"
    elif score >= 0.6:
        level = "HIGH"
    elif score >= 0.4:
        level = "MEDIUM"
    elif score >= 0.2:
        level = "LOW"
    else:
        level = "MINIMAL"

    return f"{percentage:.1f}% ({level})"


# ============================================================================
# CLI Commands
# ============================================================================

def cmd_recalc(limit: int = 0):
    """Recalculate all IOC scores."""
    conn = get_connection()
    try:
        if not validate_schema(conn):
            sys.exit(1)

        updated = batch_score_all(conn, limit=limit)
        print(f"\nScored {updated} IOCs")

    finally:
        conn.close()


def cmd_show(ip: str):
    """Show detailed score breakdown for an IP."""
    conn = get_connection()
    try:
        if not validate_schema(conn):
            sys.exit(1)

        cur = conn.cursor()

        # Fetch IOC data
        cur.execute("""
            SELECT ip, validation_count, last_seen, composite_score,
                   infrastructure_risk_score, provider_risk_level, score_timestamp
            FROM ipv4_iocs WHERE ip = ?
        """, (ip,))

        ioc = cur.fetchone()
        if not ioc:
            print(f"IP not found: {ip}")
            return

        # Print header
        print(f"\n{'='*70}")
        print(f"SCORE BREAKDOWN: {ip}")
        print(f"{'='*70}")

        print(f"\nComposite Score:        {_format_score_display(ioc[3])}")
        print(f"Infrastructure Risk:    {_format_score_display(ioc[4])}")
        print(f"Provider Risk Level:    {ioc[5]}")
        print(f"Validation Count:       {ioc[1]}")
        print(f"Last Seen:              {ioc[2]}")
        print(f"Score Calculated:       {ioc[6]}")

        # Fetch source validations
        cur.execute("""
            SELECT sv.source, sv.confidence_score, ss.reliability_weight
            FROM source_validations sv
            LEFT JOIN scoring_sources ss ON sv.source = ss.source
            WHERE sv.ioc_value = ? AND sv.ioc_type = 'ipv4'
            ORDER BY sv.confidence_score DESC
        """, (ip,))

        validations = cur.fetchall()
        if validations:
            print(f"\n{'Source':<20} {'Confidence':<15} {'Weight':<10}")
            print(f"{'-'*45}")
            for source, conf, weight in validations:
                conf_display = f"{conf*100:.1f}%" if conf else "N/A"
                weight_display = f"{weight:.2f}" if weight else "0.50"
                print(f"{source:<20} {conf_display:<15} {weight_display:<10}")

        print(f"\n{'='*70}\n")

    finally:
        conn.close()


def cmd_top(n: int = 20):
    """Show top N highest-scored IOCs."""
    conn = get_connection()
    try:
        if not validate_schema(conn):
            sys.exit(1)

        cur = conn.cursor()

        cur.execute("""
            SELECT ip, composite_score, infrastructure_risk_score,
                   provider_risk_level, validation_count
            FROM ipv4_iocs
            WHERE composite_score IS NOT NULL
            ORDER BY composite_score DESC
            LIMIT ?
        """, (n,))

        results = cur.fetchall()

        if not results:
            print("No scored IOCs found")
            return

        print(f"\n{'='*90}")
        print(f"TOP {n} HIGHEST-SCORED IOCs")
        print(f"{'='*90}\n")

        print(f"{'IP':<18} {'Composite':<15} {'Infra Risk':<15} {'Provider':<20} {'Validations':<10}")
        print(f"{'-'*90}")

        for ip, comp, infra, provider, val_count in results:
            comp_display = f"{comp*100:.1f}%" if comp is not None else "N/A"
            infra_display = f"{infra*100:.1f}%" if infra is not None else "N/A"
            print(f"{ip:<18} {comp_display:<15} {infra_display:<15} {provider:<20} {val_count:<10}")

        print(f"\n{'='*90}\n")

    finally:
        conn.close()


def cmd_stats():
    """Print scoring statistics."""
    conn = get_connection()
    try:
        if not validate_schema(conn):
            sys.exit(1)

        cur = conn.cursor()

        # Count IOCs by score level
        score_ranges = [
            (0.8, 1.0, "CRITICAL (80–100%)"),
            (0.6, 0.8, "HIGH (60–80%)"),
            (0.4, 0.6, "MEDIUM (40–60%)"),
            (0.2, 0.4, "LOW (20–40%)"),
            (0.0, 0.2, "MINIMAL (0–20%)"),
        ]

        print(f"\n{'='*70}")
        print(f"SCORING STATISTICS")
        print(f"{'='*70}\n")

        # Overall stats
        cur.execute("SELECT COUNT(*) FROM ipv4_iocs")
        total_iocs = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ipv4_iocs WHERE composite_score IS NOT NULL")
        scored_iocs = cur.fetchone()[0]

        print(f"Total IOCs:             {total_iocs:,}")
        print(f"Scored IOCs:            {scored_iocs:,}")
        print(f"Unscored IOCs:          {total_iocs - scored_iocs:,}")

        if scored_iocs > 0:
            # Score distribution
            print(f"\nScore Distribution:")
            for low, high, label in score_ranges:
                cur.execute("""
                    SELECT COUNT(*) FROM ipv4_iocs
                    WHERE composite_score >= ? AND composite_score < ?
                """, (low, high))
                count = cur.fetchone()[0]
                pct = 100 * count / scored_iocs
                print(f"  {label:<25} {count:>6} ({pct:>5.1f}%)")

            # Provider distribution
            cur.execute("""
                SELECT provider_risk_level, COUNT(*) as count
                FROM ipv4_iocs
                WHERE composite_score IS NOT NULL
                GROUP BY provider_risk_level
                ORDER BY count DESC
            """)

            print(f"\nProvider Distribution:")
            for provider, count in cur.fetchall():
                pct = 100 * count / scored_iocs
                print(f"  {provider or 'unknown':<25} {count:>6} ({pct:>5.1f}%)")

            # Source count
            cur.execute("SELECT COUNT(DISTINCT source) FROM source_validations")
            source_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM source_validations")
            total_validations = cur.fetchone()[0]

            print(f"\nValidation Sources:")
            print(f"  Unique sources:         {source_count}")
            print(f"  Total validations:      {total_validations:,}")
            if scored_iocs > 0:
                print(f"  Avg validations/IOC:    {total_validations/scored_iocs:.1f}")

        # Last update
        cur.execute("SELECT MAX(score_timestamp) FROM ipv4_iocs WHERE score_timestamp IS NOT NULL")
        last_update = cur.fetchone()[0]
        print(f"\nLast Scoring Run:       {last_update or 'Never'}")

        print(f"\n{'='*70}\n")

    finally:
        conn.close()


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Parse CLI arguments and execute command."""
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nUsage:")
        print("  python scoring.py recalc [limit]     # Recalculate all scores")
        print("  python scoring.py show <ip>          # Show score breakdown for an IP")
        print("  python scoring.py top [N]            # Top N highest-scored IOCs")
        print("  python scoring.py stats              # Scoring statistics")
        sys.exit(0)

    command = sys.argv[1].lower()

    try:
        if command == 'recalc':
            limit = int(sys.argv[2]) if len(sys.argv) > 2 else 0
            cmd_recalc(limit)

        elif command == 'show':
            if len(sys.argv) < 3:
                print("Usage: python scoring.py show <ip>")
                sys.exit(1)
            cmd_show(sys.argv[2])

        elif command == 'top':
            n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
            cmd_top(n)

        elif command == 'stats':
            cmd_stats()

        else:
            print(f"Unknown command: {command}")
            print("\nAvailable commands: recalc, show, top, stats")
            sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
