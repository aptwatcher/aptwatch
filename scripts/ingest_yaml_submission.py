#!/usr/bin/env python3
"""Step 2.B — Canonical curator YAML loader (DB-native).

Replaces community/import_approved.py's flat-file-only path. Reads a curator
YAML submission and writes in a SINGLE SQLite transaction to:
    - campaigns                (resolve or create by campaign_name)
    - attribution_sources      (1 row per import — source_org + url + date)
    - campaign_iocs            (INSERT OR IGNORE via ux_campaign_iocs_unique)
    - ipv4_iocs / ipv6_iocs / domains / urls / emails / cves / cidr_iocs
      (INSERT OR IGNORE, then UPDATE actor_attribution_*)

Score model:
    - Curator YAMLs (no `confidence_score:` field) -> 1.0 (ground truth).
    - Auto-YAMLs from the collector / rss_monitor carry an explicit
      `confidence_score:` (0.30-0.99) -> that value is used verbatim.
    - Score semantics (Step 2.A migration):
        0.70-0.99 vetted per-group feeds (Mandiant, MSTIC, CISA).
        0.50-0.69 aggregated feeds (OTX, AlienVault).
        0.30-0.49 noisy / community sources.

Handles:
    - Defanged IOCs: `[.]` -> `.`, `hxxp://` -> `http://`
    - `compromised_domains:` list -> domains.domain_type='compromised_legitimate'
      (regular `domains:` -> domain_type='malicious', the default)
    - `apt_groups`: first entry = campaign_name, rest = aliases
    - Sentinel `Unattributed` (from rss_monitor) -> flat-table only,
      no campaign_iocs link, actor_attribution_actor stays NULL.
    - Privacy-by-design: deletes the YAML post-import (same as v1)
    - Idempotent re-runs via ux_campaign_iocs_unique

Usage:
    python3 scripts/ingest_yaml_submission.py submission.yaml
    python3 scripts/ingest_yaml_submission.py --all
    python3 scripts/ingest_yaml_submission.py --dry-run submission.yaml
    python3 scripts/ingest_yaml_submission.py --db /path/to/apt_intel.db --keep-yaml submission.yaml

Exit codes:
    0 = success (or nothing to do)
    1 = validation error / file not found
    2 = DB schema mismatch
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import datetime, date
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required -- pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# Project layout (matches apt-intel/repo/ layout on both dev + prod)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "database" / "apt_intel.db"
SUBMISSIONS_DIR = PROJECT_ROOT / "repo" / "community" / "submissions"
LOG_PATH = PROJECT_ROOT / "repo" / "community" / "import_log.txt"

CURATOR_SCORE = 1.0
MIN_AUTO_SCORE = 0.30
MAX_AUTO_SCORE = 0.99

# Step 2.G — Flat-to-campaign-iocs safety net.
# Any upsert_flat() call that lands at curator-grade (>= 1.0) MUST also
# guarantee a campaign_iocs row exists, even when called outside the
# normal import_submission() flow (e.g. backfill / rebuild scripts that
# reuse upsert_flat directly). We look up the campaign by canonical
# actor name (campaigns.campaign_name = actor) and INSERT OR IGNORE.
# Idempotent against the ux_campaign_iocs_unique index.
CAMPAIGN_LINK_THRESHOLD = 1.0

# RSS monitor sentinel: IOCs are captured but no campaign linkage is written.
# The flat tables still get source_file + first_seen, but actor_attribution_actor
# stays NULL. Phase-2 NLP actor resolution will replace this sentinel.
RSS_UNATTRIBUTED = "Unattributed"

# YAML key -> (flat_table, ioc_column, campaign_iocs.ioc_type)
IOC_MAP: dict[str, tuple[str, str, str]] = {
    "ipv4":    ("ipv4_iocs",  "ip",     "ipv4"),
    "ipv6":    ("ipv6_iocs",  "ip",     "ipv6"),
    "domains": ("domains",    "domain", "domain"),
    "urls":    ("urls",       "url",    "url"),
    "emails":  ("emails",     "email",  "email"),
    "cves":    ("cves",       "cve_id", "cve"),
    "cidrs":   ("cidr_iocs",  "cidr",   "cidr"),
}


def log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def defang(value: str) -> str:
    return value.strip().replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")


def load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def today_iso() -> str:
    return date.today().isoformat()


def verify_schema(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    for yaml_key, (table, _col, _t) in IOC_MAP.items():
        cols = {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}
        if "actor_attribution_actor" not in cols:
            raise RuntimeError(
                f"{table} missing actor_attribution_actor -- run Step 2.A migration first"
            )
    domain_cols = {r[1] for r in cur.execute("PRAGMA table_info(domains)").fetchall()}
    if "domain_type" not in domain_cols:
        raise RuntimeError("domains.domain_type missing -- run Step 8 migration first")
    idx = cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name='ux_campaign_iocs_unique'"
    ).fetchone()
    if not idx:
        raise RuntimeError("ux_campaign_iocs_unique missing -- run Step 1 migration first")


def resolve_campaign(cur: sqlite3.Cursor, apt_groups: list[str], description: str | None) -> int:
    if not apt_groups:
        raise ValueError("YAML apt_groups[] is empty -- cannot resolve campaign")
    canonical = apt_groups[0].strip()
    aliases = [a.strip() for a in apt_groups[1:] if a and a.strip()]
    row = cur.execute(
        "SELECT id, aliases FROM campaigns WHERE campaign_name = ?", (canonical,)
    ).fetchone()
    if row:
        campaign_id = row[0]
        existing_aliases = set(a.strip() for a in (row[1] or "").split(",") if a.strip())
        merged = sorted(existing_aliases | set(aliases))
        if merged != sorted(existing_aliases):
            cur.execute(
                "UPDATE campaigns SET aliases = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (", ".join(merged), campaign_id),
            )
        return campaign_id
    cur.execute(
        """INSERT INTO campaigns (campaign_name, aliases, description, confidence)
           VALUES (?, ?, ?, 'high')""",
        (canonical, ", ".join(aliases) if aliases else None, description),
    )
    return cur.lastrowid


def record_attribution_source(
    cur: sqlite3.Cursor, campaign_id: int, source_org: str | None,
    source_name: str | None, url: str | None, yaml_filename: str,
) -> int | None:
    if not (source_org or source_name or url):
        return None
    cur.execute(
        """INSERT INTO attribution_sources
               (campaign_id, source_org, report_title, publish_date, url,
                source_type, key_findings)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (campaign_id, source_org or "unknown", source_name, today_iso(), url,
         "curator_yaml", f"Imported from {yaml_filename}"),
    )
    return cur.lastrowid


# Step 2.G hook: keep flat-table writes and campaign_iocs in sync for
# curator-grade attribution. Tolerant of missing campaigns (logs and skips).
def _ensure_campaign_link(
    cur: sqlite3.Cursor, table: str, value: str, actor: str, score: float,
) -> bool:
    """When score >= CAMPAIGN_LINK_THRESHOLD, ensure a campaign_iocs row
    exists for (campaign(actor), ioc_type(table), value). Returns True if
    a new row was inserted, False otherwise (already present, or skipped)."""
    if score < CAMPAIGN_LINK_THRESHOLD or not actor:
        return False
    if actor == RSS_UNATTRIBUTED:
        return False
    table_to_iocs_type = {
        "ipv4_iocs": "ipv4", "ipv6_iocs": "ipv6", "domains": "domain",
        "urls": "url", "emails": "email", "cves": "cve", "cidr_iocs": "cidr",
    }
    ioc_type = table_to_iocs_type.get(table)
    if ioc_type is None:
        return False
    row = cur.execute(
        "SELECT id FROM campaigns WHERE campaign_name = ?", (actor,),
    ).fetchone()
    if row is None:
        log(f"  [step2g] no campaign for actor={actor!r}; cannot link {table}/{value}")
        return False
    campaign_id = row[0]
    cur.execute(
        "INSERT OR IGNORE INTO campaign_iocs "
        "(campaign_id, ioc_type, ioc_value, notes, confidence_score, confidence_basis) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (campaign_id, ioc_type, value, "step2g: flat->campaign sync",
         score, "flat_table_curator_sync"),
    )
    return cur.rowcount > 0


def upsert_flat(
    cur: sqlite3.Cursor, table: str, col: str, value: str, actor: str,
    score: float, source_file: str, domain_type: str | None = None,
) -> str:
    """INSERT OR IGNORE + UPDATE on a flat IOC table.

    Monotonic: higher-score incoming upgrades lower-score existing. Curator-grade
    (1.0) never yields to auto. Different actor at same grade -> conflict (logged).

    Returns: 'inserted', 'updated_attr', 'already_correct', 'conflict_kept',
    or 'lower_score_skipped'.
    """
    existing = cur.execute(
        f"SELECT actor_attribution_actor, actor_attribution_score FROM {table} WHERE {col} = ?",
        (value,),
    ).fetchone()

    if existing is None:
        if table == "domains" and domain_type is not None:
            cur.execute(
                f"INSERT INTO {table} ({col}, source_file, first_seen, domain_type, "
                f"actor_attribution_actor, actor_attribution_score) VALUES (?, ?, ?, ?, ?, ?)",
                (value, source_file, today_iso(), domain_type, actor, score),
            )
        elif table == "ipv4_iocs":
            cur.execute(
                f"INSERT INTO {table} (ip, source_file, first_seen, last_seen, "
                f"actor_attribution_actor, actor_attribution_score) VALUES (?, ?, ?, ?, ?, ?)",
                (value, source_file, today_iso(), today_iso(), actor, score),
            )
        else:
            cur.execute(
                f"INSERT INTO {table} ({col}, source_file, first_seen, "
                f"actor_attribution_actor, actor_attribution_score) VALUES (?, ?, ?, ?, ?)",
                (value, source_file, today_iso(), actor, score),
            )
        # Step 2.G — sync flat curator inserts into campaign_iocs.
        _ensure_campaign_link(cur, table, value, actor, score)
        return "inserted"

    existing_actor, existing_score = existing
    existing_score = existing_score or 0.0

    if existing_actor == actor and abs(existing_score - score) < 1e-9:
        if table == "domains" and domain_type == "compromised_legitimate":
            cur.execute(
                f"UPDATE {table} SET domain_type = ? WHERE {col} = ? AND domain_type = 'malicious'",
                (domain_type, value),
            )
        # Step 2.G — even on no-op, ensure curator link exists.
        _ensure_campaign_link(cur, table, value, actor, score)
        return "already_correct"

    if existing_actor and existing_actor != actor and existing_score > score:
        log(f"  [conflict] {table}/{value}: existing={existing_actor} "
            f"(score={existing_score}) vs incoming={actor} (score={score}) -- skipped")
        return "conflict_kept"

    if existing_actor and existing_actor != actor and abs(existing_score - score) < 1e-9:
        log(f"  [conflict] {table}/{value}: existing={existing_actor} "
            f"and incoming={actor} both at score={score} -- skipped")
        return "conflict_kept"

    if existing_score > score:
        return "lower_score_skipped"

    cur.execute(
        f"UPDATE {table} SET actor_attribution_actor = ?, actor_attribution_score = ? "
        f"WHERE {col} = ?",
        (actor, score, value),
    )
    if table == "domains" and domain_type == "compromised_legitimate":
        cur.execute(
            f"UPDATE {table} SET domain_type = ? WHERE {col} = ? AND domain_type = 'malicious'",
            (domain_type, value),
        )
    # Step 2.G — after a successful UPDATE at curator grade, link campaign.
    _ensure_campaign_link(cur, table, value, actor, score)
    return "updated_attr"


def _insert_flat_only(cur: sqlite3.Cursor, table: str, col: str, value: str, source_file: str) -> bool:
    """Insert a row into a flat table without touching attribution columns.

    Used for RSS Unattributed YAMLs -- IOCs are captured but actor stays NULL.
    Returns True if inserted, False if already present.
    """
    existing = cur.execute(f"SELECT 1 FROM {table} WHERE {col} = ?", (value,)).fetchone()
    if existing is not None:
        return False
    if table == "ipv4_iocs":
        cur.execute(
            "INSERT INTO ipv4_iocs (ip, source_file, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?)",
            (value, source_file, today_iso(), today_iso()),
        )
    else:
        cur.execute(
            f"INSERT INTO {table} ({col}, source_file, first_seen) VALUES (?, ?, ?)",
            (value, source_file, today_iso()),
        )
    return True


def import_submission(
    conn: sqlite3.Connection, yaml_path: Path,
    dry_run: bool = False, keep_yaml: bool = False,
) -> dict:
    data = load_yaml(yaml_path)
    if not data:
        raise ValueError(f"empty YAML: {yaml_path.name}")

    apt_groups = data.get("apt_groups") or []
    if not isinstance(apt_groups, list) or not apt_groups:
        raise ValueError(f"{yaml_path.name}: apt_groups[] missing or empty")

    description = (data.get("description") or "").strip() or None
    source = data.get("source") or None
    source_name = data.get("source_name") or None
    author = data.get("author") or "unknown"

    yaml_score = data.get("confidence_score")
    if yaml_score is None:
        score = CURATOR_SCORE
    else:
        try:
            score = float(yaml_score)
        except (TypeError, ValueError):
            raise ValueError(f"{yaml_path.name}: confidence_score must be numeric")
        if not (MIN_AUTO_SCORE <= score <= MAX_AUTO_SCORE):
            raise ValueError(
                f"{yaml_path.name}: confidence_score={score} outside "
                f"[{MIN_AUTO_SCORE}, {MAX_AUTO_SCORE}] (1.0 reserved for curator)"
            )

    cur = conn.cursor()
    canonical = apt_groups[0].strip()
    unattributed = canonical == RSS_UNATTRIBUTED

    if unattributed:
        campaign_id = None
        attribution_source_id = None
    else:
        campaign_id = resolve_campaign(cur, apt_groups, description)
        attribution_source_id = record_attribution_source(
            cur, campaign_id, author, source_name, source, yaml_path.name
        )

    source_file_tag = f"{'rss' if unattributed else 'curator'}:{yaml_path.name}"
    is_curator = abs(score - CURATOR_SCORE) < 1e-9
    basis = "curator_yaml_submission" if is_curator else "auto_yaml_submission"
    note_prefix = "Curator import" if is_curator else "Auto import"

    stats = {
        "campaign_id": campaign_id, "campaign": canonical, "score": score,
        "inserted": 0, "updated_attr": 0, "already_correct": 0,
        "conflict_kept": 0, "lower_score_skipped": 0,
        "campaign_iocs_inserted": 0, "campaign_iocs_already": 0,
        "flat_only": 0,
    }

    # 1) Regular IOC lists
    for yaml_key, (table, col, ci_type) in IOC_MAP.items():
        items = data.get(yaml_key) or []
        if not isinstance(items, list):
            continue
        for raw in items:
            if not isinstance(raw, str):
                continue
            value = defang(raw)
            if not value:
                continue

            if unattributed:
                if _insert_flat_only(cur, table, col, value, source_file_tag):
                    stats["flat_only"] += 1
                continue

            result = upsert_flat(cur, table, col, value, canonical, score, source_file_tag)
            stats[result] = stats.get(result, 0) + 1

            before = conn.total_changes
            cur.execute(
                """INSERT OR IGNORE INTO campaign_iocs
                       (campaign_id, ioc_type, ioc_value, notes,
                        attribution_source_id, confidence_score, confidence_basis)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (campaign_id, ci_type, value, f"{note_prefix}: {yaml_path.name}",
                 attribution_source_id, score, basis),
            )
            if conn.total_changes > before:
                stats["campaign_iocs_inserted"] += 1
            else:
                stats["campaign_iocs_already"] += 1

    # 2) Compromised-legitimate domains (Step 8 semantics)
    compromised = data.get("compromised_domains") or []
    if isinstance(compromised, list) and not unattributed:
        for raw in compromised:
            if not isinstance(raw, str):
                continue
            value = defang(raw)
            if not value:
                continue
            result = upsert_flat(
                cur, "domains", "domain", value, canonical, score,
                source_file_tag, domain_type="compromised_legitimate",
            )
            stats[f"compromised_{result}"] = stats.get(f"compromised_{result}", 0) + 1
            before = conn.total_changes
            cur.execute(
                """INSERT OR IGNORE INTO campaign_iocs
                       (campaign_id, ioc_type, ioc_value, notes,
                        attribution_source_id, confidence_score, confidence_basis)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (campaign_id, "domain", value,
                 f"{note_prefix} (compromised): {yaml_path.name}",
                 attribution_source_id, score, basis),
            )
            if conn.total_changes > before:
                stats["campaign_iocs_inserted"] += 1
            else:
                stats["campaign_iocs_already"] += 1

    if dry_run:
        conn.rollback()
        log(f"DRY-RUN {yaml_path.name} -> campaign={canonical} ({campaign_id}) "
            f"score={score} stats={stats}")
    else:
        conn.commit()
        log(f"IMPORTED {yaml_path.name} -> campaign={canonical} ({campaign_id}) "
            f"score={score} flat_new={stats['inserted']} flat_only={stats['flat_only']} "
            f"attr_updated={stats['updated_attr']} ci_new={stats['campaign_iocs_inserted']}")
        if not keep_yaml:
            try:
                yaml_path.unlink()
                log(f"  Source YAML deleted: {yaml_path.name}")
            except OSError as e:
                log(f"  WARNING: could not delete {yaml_path.name}: {e}")

    return stats


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target", nargs="?", help="YAML file (or --all)")
    p.add_argument("--all", action="store_true", help="Process every *.yaml in submissions/")
    p.add_argument("--db", default=str(DEFAULT_DB), help="Path to apt_intel.db")
    p.add_argument("--dry-run", action="store_true", help="Do not write to DB or delete YAML")
    p.add_argument("--keep-yaml", action="store_true", help="Do not delete the YAML after import")
    args = p.parse_args(argv)

    if not args.target and not args.all:
        p.print_help()
        return 1

    conn = sqlite3.connect(args.db)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        verify_schema(conn)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.all:
        candidates = sorted(SUBMISSIONS_DIR.glob("*.yaml")) + sorted(SUBMISSIONS_DIR.glob("*.yml"))
        candidates = [f for f in candidates if not f.name.startswith("_TEMPLATE")]
        if not candidates:
            log("No submissions to process.")
            return 0
        ok = True
        for path in candidates:
            try:
                import_submission(conn, path, dry_run=args.dry_run, keep_yaml=args.keep_yaml)
            except Exception as e:
                log(f"ERROR on {path.name}: {e}")
                ok = False
        return 0 if ok else 1

    path = Path(args.target)
    if not path.exists():
        path = SUBMISSIONS_DIR / args.target
    if not path.exists():
        print(f"File not found: {args.target}", file=sys.stderr)
        return 1
    try:
        import_submission(conn, path, dry_run=args.dry_run, keep_yaml=args.keep_yaml)
    except Exception as e:
        log(f"ERROR on {path.name}: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
