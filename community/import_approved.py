#!/usr/bin/env python3
"""
Import approved community IOC submissions into the database.
MAINTAINER-ONLY — run manually after reviewing a PR.

Usage:
    python community/import_approved.py submission-file.yaml
    python community/import_approved.py --all        # Import all pending submissions
    python community/import_approved.py --dry-run submission-file.yaml

What it does:
    1. Validates the YAML (same checks as validate_submission.py)
    2. Appends new IOCs to the iocs/ text files
    3. Runs incremental import into the database
    4. Deletes the submission file (clean up + prevent duplicates)
    5. Logs the import to community/import_log.txt
"""

import sys
from pathlib import Path
from datetime import datetime

# Reuse validation logic
sys.path.insert(0, str(Path(__file__).parent))
from validate_submission import load_yaml, load_existing_iocs, validate_file

PROJECT_ROOT = Path(__file__).parent.parent
IOCS_DIR = PROJECT_ROOT / "iocs"
SUBMISSIONS_DIR = Path(__file__).parent / "submissions"

LOG_PATH = Path(__file__).parent / "import_log.txt"

# Map YAML field names to IOC filenames
FILE_MAP = {
    "ipv4": "ipv4.txt",
    "domains": "domains.txt",
    "urls": "urls.txt",
    "ipv6": "ipv6.txt",
    "emails": "emails.txt",
    "cidrs": "cidr.txt",
    "cves": "cves.txt",
}


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (ts, msg)
    print(line)
    try:
        with open(str(LOG_PATH), "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def import_submission(filepath, dry_run=False):
    """Import a single submission file."""
    existing = load_existing_iocs()
    errors, warnings, stats = validate_file(filepath, existing)

    if errors:
        is_security = any(e.startswith("SECURITY:") for e in errors)
        prefix = "SECURITY BLOCKED" if is_security else "REJECTED"
        log("%s %s — %d errors:" % (prefix, filepath.name, len(errors)))
        for e in errors:
            log("  ✗ %s" % e)
        if is_security:
            log("  ⚠ This file was blocked for security reasons and will NOT be imported.")
            # Delete dangerous files immediately
            if not dry_run:
                try:
                    filepath.unlink()
                    log("  Dangerous file deleted: %s" % filepath.name)
                except OSError:
                    log("  WARNING: failed to delete dangerous file %s" % filepath.name)
        return False

    data = load_yaml(str(filepath))
    if not data:
        log("REJECTED %s — empty file" % filepath.name)
        return False

    author = data.get("author", "unknown")
    source = data.get("source", "unknown")
    added_total = 0

    for ioc_type, filename in FILE_MAP.items():
        items = data.get(ioc_type, [])
        if not items or not isinstance(items, list):
            continue

        new_items = []
        for item in items:
            if not item or not isinstance(item, str):
                continue
            clean = item.strip().replace("[.]", ".").replace("hxxp", "http")
            if clean.lower() not in existing.get(ioc_type, set()):
                new_items.append(clean)

        if not new_items:
            continue

        ioc_file = IOCS_DIR / filename
        if dry_run:
            log("  DRY-RUN: would add %d %s to %s" % (len(new_items), ioc_type, filename))
        else:
            with open(str(ioc_file), "a") as f:
                for item in new_items:
                    f.write(item + "\n")
            log("  Added %d %s to %s" % (len(new_items), ioc_type, filename))

        added_total += len(new_items)

    if added_total == 0:
        log("SKIPPED %s — all IOCs already exist" % filepath.name)
        return True

    if not dry_run:
        # Delete the submission file to keep submissions/ clean and prevent duplicates
        try:
            filepath.unlink()
            log("IMPORTED %s — %d new IOCs (author: %s, source: %s)" % (
                filepath.name, added_total, author, source))
            log("  Submission file deleted")
        except OSError as e:
            log("WARNING: imported but failed to delete %s: %s" % (filepath.name, e))
        log("  Run: python apt.py import iocs")
    else:
        log("DRY-RUN %s — %d new IOCs would be added" % (filepath.name, added_total))

    return True


def main():
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]

    if not args:
        print(__doc__)
        return

    if args[0] == "--all":
        files = sorted(
            list(SUBMISSIONS_DIR.glob("*.yaml")) + list(SUBMISSIONS_DIR.glob("*.yml"))
        )
        files = [f for f in files if f.name != "TEMPLATE.yaml"]

        # Security: warn about unexpected files in submissions/
        for f in SUBMISSIONS_DIR.iterdir():
            if f.is_file() and f.name != '.gitkeep' and f.suffix.lower() not in ('.yaml', '.yml'):
                log("SECURITY WARNING: unexpected non-YAML file in submissions/: %s — deleting" % f.name)
                try:
                    f.unlink()
                except OSError:
                    pass

        if not files:
            print("No pending submissions.")
            return
        for f in files:
            import_submission(f, dry_run)
    else:
        filepath = Path(args[0])
        if not filepath.exists():
            filepath = SUBMISSIONS_DIR / args[0]
        if not filepath.exists():
            print("File not found: %s" % args[0])
            return
        import_submission(filepath, dry_run)

    if not dry_run:
        print("\nNext step: python apt.py import iocs")
        print("Then:      python apt.py export")


if __name__ == "__main__":
    main()
