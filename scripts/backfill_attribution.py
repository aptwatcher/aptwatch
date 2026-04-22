#!/usr/bin/env python3
"""Step 2.A — Backfill actor_attribution_actor + _score on flat IOC tables.

After the Step 2.A migration adds the attribution columns to the flat IOC
tables (domains, urls, emails, cves, cidr_iocs, ipv6_iocs, cert_patterns)
and confirms them on ipv4_iocs, this script propagates the existing
curator attribution from campaign_iocs into the flat tables.

For every (ioc_type, ioc_value) pair in campaign_iocs whose parent campaign
has a campaign_name, UPDATE the corresponding flat row to:
    actor_attribution_actor = campaigns.campaign_name
    actor_attribution_score = 1.0  (curator-confirmed)

Curator corpus is considered ground truth. If a flat row is already attributed
to something else with score < 1.0, the curator value wins (overwritten).
If a flat row is already attributed with score = 1.0 to a DIFFERENT actor, the
conflict is logged and the row is left alone.

Rows in campaign_iocs whose ioc_type has no matching flat table (e.g.
`filename`, `subnet`, `sha256`) are counted but skipped.

Idempotent: running twice is a no-op for rows already at the target state.

Usage:
    python3 backfill_attribution.py --db /opt/apt-intel/database/apt_intel.db [--dry-run]
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from typing import Iterable

# Map campaign_iocs.ioc_type to (flat_table, ioc_column).
# Missing from this map = type is skipped (not yet a flat table or
# stored only in campaign_iocs as enrichment metadata).
IOC_TYPE_TABLE_MAP: dict[str, tuple[str, str]] = {
    "ipv4":   ("ipv4_iocs",  "ip"),
    "ipv6":   ("ipv6_iocs",  "ip"),
    "domain": ("domains",    "domain"),
    "url":    ("urls",       "url"),
    "email":  ("emails",     "email"),
    "cve":    ("cves",       "cve_id"),
    "cidr":   ("cidr_iocs",  "cidr"),
    # hash / sha256 / md5 / sha1 live in distinct tables or in
    # campaign-only metadata; skipped for this backfill.
    # subnet is aggregate metadata, not a row in a flat table.
    # filename / mutex / registry_key are host-level, no flat table.
}

# Rows in these tables are assumed to be curator-confirmed.
CURATOR_SCORE = 1.0


def backfill(db_path: str, dry_run: bool = False) -> int:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Validate schema: every target table must have the attribution columns.
    for ioc_type, (table, _col) in IOC_TYPE_TABLE_MAP.items():
        cols = {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}
        if "actor_attribution_actor" not in cols or "actor_attribution_score" not in cols:
            print(
                f"[error] {table} missing attribution columns — run the Step 2.A "
                "migration first.",
                file=sys.stderr,
            )
            return 2

    # Pull every campaign-attributed IOC paired with its campaign name.
    rows = cur.execute(
        """
        SELECT ci.ioc_type, ci.ioc_value, c.campaign_name
        FROM campaign_iocs ci
        JOIN campaigns c ON c.id = ci.campaign_id
        WHERE c.campaign_name IS NOT NULL
          AND c.campaign_name <> ''
        """
    ).fetchall()

    totals = {
        "curator_rows": len(rows),
        "updated": 0,
        "already_correct": 0,
        "conflict_kept_existing": 0,
        "flat_row_absent": 0,
        "skipped_unmapped_type": 0,
    }

    for r in rows:
        ioc_type = r["ioc_type"]
        ioc_value = r["ioc_value"]
        actor = r["campaign_name"]

        mapping = IOC_TYPE_TABLE_MAP.get(ioc_type)
        if mapping is None:
            totals["skipped_unmapped_type"] += 1
            continue
        table, col = mapping

        existing = cur.execute(
            f"SELECT actor_attribution_actor AS actor, actor_attribution_score AS score "
            f"FROM {table} WHERE {col} = ?",
            (ioc_value,),
        ).fetchone()

        if existing is None:
            totals["flat_row_absent"] += 1
            continue

        if (
            existing["actor"] == actor
            and existing["score"] is not None
            and abs(existing["score"] - CURATOR_SCORE) < 1e-9
        ):
            totals["already_correct"] += 1
            continue

        if (
            existing["actor"] is not None
            and existing["actor"] != actor
            and existing["score"] is not None
            and existing["score"] >= CURATOR_SCORE
        ):
            # Pre-existing curator-grade attribution to a different actor —
            # leave it alone. Operator must resolve.
            print(
                f"[conflict] {table}/{ioc_value}: existing={existing['actor']} "
                f"(score={existing['score']}) vs curator={actor} — skipped",
                file=sys.stderr,
            )
            totals["conflict_kept_existing"] += 1
            continue

        if dry_run:
            totals["updated"] += 1
            continue

        cur.execute(
            f"UPDATE {table} "
            f"SET actor_attribution_actor = ?, actor_attribution_score = ? "
            f"WHERE {col} = ?",
            (actor, CURATOR_SCORE, ioc_value),
        )
        totals["updated"] += 1

    if not dry_run:
        conn.commit()
    conn.close()

    mode = "DRY-RUN" if dry_run else "APPLIED"
    print(f"[{mode}] backfill summary:")
    for k, v in totals.items():
        print(f"  {k:28s} {v}")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db", required=True, help="Path to apt_intel.db")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Report the counts but don't write UPDATEs.",
    )
    args = p.parse_args(list(argv) if argv is not None else None)
    return backfill(args.db, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
