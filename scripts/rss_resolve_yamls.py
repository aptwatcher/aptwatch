#!/usr/bin/env python3
"""Phase-2 RSS YAML post-processor.

Scans community/submissions/*.yaml looking for auto-YAMLs whose
`apt_groups:` is `[Unattributed]` (the rss_monitor.py sentinel). For each
match, calls `rss_keyword_resolver.resolve_yaml_fields()` on the YAML's
title + description + source_name + matched_keywords. If the resolver
returns a unique actor, the YAML is rewritten in place:
    - apt_groups: [<resolved-actor>]
    - confidence_score: 0.60
    - notes/comment: "actor resolved by Phase-2 keyword matcher
      (hit_counts={...})"

Dry-run is the default; pass --apply to rewrite YAMLs.

Chaining: wired into sync_to_github.sh BEFORE ingest_yaml_submission.py
so the loader sees the resolved attribution and writes campaign_iocs
links instead of flat-only Unattributed rows.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required -- pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# Allow running as standalone or from scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rss_keyword_resolver import (
    KEYWORD_RESOLVED_SCORE,
    UNATTRIBUTED_SENTINEL,
    resolve_yaml_fields,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUBMISSIONS_DIR = PROJECT_ROOT / "repo" / "community" / "submissions"


def is_unattributed(data: dict) -> bool:
    groups = data.get("apt_groups")
    if not isinstance(groups, list) or len(groups) == 0:
        return False
    return groups[0].strip() == UNATTRIBUTED_SENTINEL


def resolve_one(path: Path, apply: bool) -> str:
    """Return a status string: 'not_unattributed', 'no_match',
    'multi_match', 'resolved', or 'error:...'."""
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as e:
        return f"error:{e}"

    if not is_unattributed(data):
        return "not_unattributed"

    title = data.get("title") or data.get("description") or ""
    description = data.get("description") or ""
    source_name = data.get("source_name") or ""
    matched_keywords = data.get("matched_keywords") or []

    actor, hits = resolve_yaml_fields(
        title=title,
        description=description,
        source_name=source_name,
        matched_keywords=matched_keywords,
    )

    if actor is None:
        return "no_match" if not hits else "multi_match"

    data["apt_groups"] = [actor]
    data["confidence_score"] = KEYWORD_RESOLVED_SCORE
    existing_notes = data.get("notes") or ""
    note = (
        f"actor resolved by Phase-2 keyword matcher "
        f"(hits={hits})"
    )
    data["notes"] = (existing_notes + "\n" + note).strip() if existing_notes else note

    if apply:
        path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))

    return f"resolved:{actor}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target", nargs="?")
    p.add_argument("--all", action="store_true")
    p.add_argument("--apply", action="store_true",
                   help="Rewrite YAMLs in place (default is dry-run)")
    p.add_argument("--dir", default=str(DEFAULT_SUBMISSIONS_DIR))
    args = p.parse_args(argv)

    submissions = Path(args.dir)
    if not submissions.exists():
        print(f"No submissions directory at {submissions} -- nothing to do.")
        return 0

    if args.all:
        targets = sorted(submissions.glob("*.yaml")) + sorted(submissions.glob("*.yml"))
        targets = [t for t in targets if not t.name.startswith("_TEMPLATE")]
    elif args.target:
        targets = [Path(args.target)]
    else:
        p.print_help()
        return 1

    if not targets:
        print("No submissions to process.")
        return 0

    stats = {"not_unattributed": 0, "no_match": 0, "multi_match": 0,
             "resolved": 0, "error": 0}
    for t in targets:
        status = resolve_one(t, apply=args.apply)
        if status.startswith("error"):
            stats["error"] += 1
            print(f"  [error] {t.name}: {status}")
        elif status.startswith("resolved:"):
            stats["resolved"] += 1
            actor = status.split(":", 1)[1]
            mode = "APPLIED" if args.apply else "DRY-RUN"
            print(f"  [{mode}] {t.name} -> {actor}")
        else:
            stats[status] = stats.get(status, 0) + 1

    print()
    print(f"Stats: {stats}")
    if not args.apply and stats["resolved"] > 0:
        print("(dry-run -- pass --apply to rewrite YAMLs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
