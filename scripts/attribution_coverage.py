#!/usr/bin/env python3
"""Step 2.D -- DB-native attribution coverage.

Computes per-actor coverage across all flat IOC tables, bucketed by score tier:
    curator          (score == 1.0)        -- ground truth
    high_supposed    (0.70 <= s <  1.00)   -- vetted per-group feeds
    medium_supposed  (0.30 <= s <  0.70)   -- aggregated / noisy feeds
    weak             (0.00 <  s <  0.30)   -- best-effort
    unattributed     (actor IS NULL)

One table per IOC table (ipv4_iocs, ipv6_iocs, domains, urls, emails, cves,
cidr_iocs, cert_patterns). Plus a per-campaign summary from campaign_iocs.

Replaces the deleted v1 collector_coverage_diff.py (source of truth: DB, not
YAML files that get deleted post-import).

Usage:
    python3 scripts/attribution_coverage.py --db /opt/apt-intel/database/apt_intel.db
    python3 scripts/attribution_coverage.py --db ... --format json > coverage.json
    python3 scripts/attribution_coverage.py --db ... --format md > reports/coverage.md
    python3 scripts/attribution_coverage.py --db ... --actor Gamaredon
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime
from typing import Any

# (flat_table, ioc_column, label)
FLAT_TABLES = [
    ("ipv4_iocs",     "ip",     "IPv4"),
    ("ipv6_iocs",     "ip",     "IPv6"),
    ("domains",       "domain", "Domain"),
    ("urls",          "url",    "URL"),
    ("emails",        "email",  "Email"),
    ("cves",          "cve_id", "CVE"),
    ("cidr_iocs",     "cidr",   "CIDR"),
    ("cert_patterns", "pattern","Cert Pattern"),
]


def bucket(score: float | None) -> str:
    if score is None or score == 0.0:
        return "unattributed"
    if abs(score - 1.0) < 1e-9:
        return "curator"
    if score >= 0.70:
        return "high_supposed"
    if score >= 0.30:
        return "medium_supposed"
    return "weak"


def actor_rollup(conn: sqlite3.Connection, actor_filter: str | None = None) -> dict[str, Any]:
    """Per (actor, ioc_table) bucketed counts."""
    data: dict[str, dict[str, dict[str, int]]] = {}  # actor -> table -> bucket -> count

    for table, _col, _label in FLAT_TABLES:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if "actor_attribution_actor" not in cols:
            # cert_patterns may be missing on older DBs.
            continue
        where = ""
        params: tuple = ()
        if actor_filter:
            where = "WHERE actor_attribution_actor = ?"
            params = (actor_filter,)
        rows = conn.execute(
            f"SELECT actor_attribution_actor AS actor, actor_attribution_score AS score, "
            f"COUNT(*) AS n FROM {table} {where} "
            f"GROUP BY actor_attribution_actor, actor_attribution_score",
            params,
        ).fetchall()
        for row in rows:
            actor = row[0] or "(unattributed)"
            b = bucket(row[1])
            data.setdefault(actor, {}).setdefault(table, {}).setdefault(b, 0)
            data[actor][table][b] += row[2]

    return data


def campaign_rollup(conn: sqlite3.Connection) -> list[dict]:
    """Per-campaign IOC counts from campaign_iocs (curator-grade linkage)."""
    rows = conn.execute(
        """SELECT c.id, c.campaign_name, ci.ioc_type, COUNT(*) AS n,
                  AVG(ci.confidence_score) AS avg_score
           FROM campaigns c
           LEFT JOIN campaign_iocs ci ON ci.campaign_id = c.id
           GROUP BY c.id, c.campaign_name, ci.ioc_type
           ORDER BY c.campaign_name, ci.ioc_type"""
    ).fetchall()
    return [dict(id=r[0], campaign=r[1], ioc_type=r[2], count=r[3], avg_score=r[4]) for r in rows]


def to_json(actor_data: dict, campaign_data: list) -> str:
    return json.dumps(
        {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "actors": actor_data,
            "campaigns": campaign_data,
        },
        indent=2,
    )


def to_markdown(actor_data: dict, campaign_data: list) -> str:
    out = []
    out.append(f"# Attribution coverage\n")
    out.append(f"Generated: {datetime.utcnow().isoformat()}Z\n")
    out.append("Buckets: `curator`=1.0, `high_supposed`=[0.70,1.0), "
               "`medium_supposed`=[0.30,0.70), `weak`=(0,0.30), `unattributed`=NULL.\n")

    out.append("## Per-actor coverage (flat tables)\n")
    for actor in sorted(actor_data.keys()):
        out.append(f"### {actor}\n")
        out.append("| Table | curator | high_supposed | medium_supposed | weak | unattributed | total |")
        out.append("|-------|--------:|--------------:|----------------:|-----:|-------------:|------:|")
        for table, _col, label in FLAT_TABLES:
            tb = actor_data[actor].get(table, {})
            cur = tb.get("curator", 0)
            hi = tb.get("high_supposed", 0)
            med = tb.get("medium_supposed", 0)
            wk = tb.get("weak", 0)
            un = tb.get("unattributed", 0)
            total = cur + hi + med + wk + un
            if total == 0:
                continue
            out.append(f"| {label} | {cur} | {hi} | {med} | {wk} | {un} | {total} |")
        out.append("")

    out.append("## Per-campaign coverage (campaign_iocs)\n")
    out.append("| Campaign | ioc_type | count | avg_score |")
    out.append("|----------|----------|------:|----------:|")
    for c in campaign_data:
        if c["count"] == 0:
            continue
        score_str = f"{c['avg_score']:.2f}" if c["avg_score"] is not None else "-"
        out.append(f"| {c['campaign']} | {c['ioc_type'] or '-'} | {c['count']} | {score_str} |")
    out.append("")
    return "\n".join(out)


def to_text(actor_data: dict, campaign_data: list) -> str:
    out = []
    out.append("=" * 70)
    out.append("Attribution coverage  -- " + datetime.utcnow().isoformat() + "Z")
    out.append("=" * 70)
    for actor in sorted(actor_data.keys()):
        out.append("")
        out.append(f"[{actor}]")
        for table, _col, label in FLAT_TABLES:
            tb = actor_data[actor].get(table, {})
            cur = tb.get("curator", 0)
            hi = tb.get("high_supposed", 0)
            med = tb.get("medium_supposed", 0)
            wk = tb.get("weak", 0)
            un = tb.get("unattributed", 0)
            total = cur + hi + med + wk + un
            if total == 0:
                continue
            out.append(f"  {label:13s}  curator={cur:>5d}  high={hi:>5d}  "
                       f"med={med:>5d}  weak={wk:>5d}  unatt={un:>5d}  total={total}")
    out.append("")
    out.append("-" * 70)
    out.append("campaign_iocs breakdown:")
    out.append("-" * 70)
    for c in campaign_data:
        if c["count"] == 0:
            continue
        score_str = f"{c['avg_score']:.2f}" if c["avg_score"] is not None else "-"
        out.append(f"  {c['campaign']:30s}  {c['ioc_type'] or '-':<8s}  "
                   f"n={c['count']:>5d}  avg_score={score_str}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db", required=True)
    p.add_argument("--format", choices=["text", "md", "json"], default="text")
    p.add_argument("--actor", help="Restrict the per-actor rollup to one actor")
    args = p.parse_args(argv)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        actor_data = actor_rollup(conn, actor_filter=args.actor)
        campaign_data = campaign_rollup(conn)
    finally:
        conn.close()

    if args.format == "json":
        print(to_json(actor_data, campaign_data))
    elif args.format == "md":
        print(to_markdown(actor_data, campaign_data))
    else:
        print(to_text(actor_data, campaign_data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
