#!/usr/bin/env python3
"""
Validates community IOC submissions (YAML files).
Used by GitHub Actions on PRs — never writes to the database.

Checks:
  - Valid YAML structure
  - Required fields present (author, source)
  - IP/domain/URL format validation
  - CVE format validation
  - Duplicate detection against existing IOC files
  - Reject private/reserved IPs
  - Reject known-safe domains (google.com, etc.)

Exit codes:
  0 = all submissions valid
  1 = validation errors found
"""

import sys
import re
import ipaddress
from pathlib import Path

try:
    import yaml
except ImportError:
    # Fallback: basic YAML parsing for CI without pyyaml
    yaml = None

PROJECT_ROOT = Path(__file__).parent.parent
IOCS_DIR = PROJECT_ROOT / "iocs"
SUBMISSIONS_DIR = Path(__file__).parent / "submissions"

# Domains that should never appear as IOCs
SAFE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "cloudflare.com", "facebook.com", "twitter.com", "linkedin.com",
    "youtube.com", "wikipedia.org", "mozilla.org", "ubuntu.com",
    "debian.org", "python.org", "stackoverflow.com",
}

REQUIRED_FIELDS = ["author", "source"]
IOC_FIELDS = ["ipv4", "domains", "urls", "ipv6", "emails", "cidrs", "cves"]


def load_yaml(path):
    """Load YAML file, with fallback parser if pyyaml not installed."""
    if yaml:
        with open(path) as f:
            return yaml.safe_load(f)

    # Minimal fallback parser for simple flat YAML
    data = {}
    current_key = None
    current_list = []

    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.endswith(":") and not stripped.startswith("-"):
                if current_key and current_list:
                    data[current_key] = current_list
                    current_list = []
                current_key = stripped[:-1].strip()
            elif stripped.startswith("- "):
                val = stripped[2:].strip().strip("'\"")
                if val and not val.startswith("#"):
                    current_list.append(val)
            elif ":" in stripped and not stripped.startswith("-"):
                key, val = stripped.split(":", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if val and not val.startswith("#"):
                    data[key] = val

        if current_key and current_list:
            data[current_key] = current_list

    return data


def load_existing_iocs():
    """Load existing IOCs from iocs/ directory for duplicate checking."""
    existing = {"ipv4": set(), "domains": set(), "urls": set(),
                "ipv6": set(), "emails": set(), "cidrs": set(), "cves": set()}

    file_map = {
        "ipv4": "ipv4.txt", "domains": "domains.txt", "urls": "urls.txt",
        "ipv6": "ipv6.txt", "emails": "emails.txt", "cidrs": "cidr.txt",
        "cves": "cves.txt",
    }

    for ioc_type, filename in file_map.items():
        filepath = IOCS_DIR / filename
        if filepath.exists():
            with open(filepath) as f:
                for line in f:
                    val = line.strip()
                    if val and not val.startswith("#"):
                        existing[ioc_type].add(val.lower())

    return existing


def validate_ipv4(ip):
    """Validate an IPv4 address — reject private/reserved."""
    errors = []
    # Clean defanged notation
    clean = ip.replace("[.]", ".").replace("[", "").replace("]", "")
    try:
        addr = ipaddress.ip_address(clean)
        if addr.is_private:
            errors.append("Private IP: %s" % ip)
        if addr.is_reserved:
            errors.append("Reserved IP: %s" % ip)
        if addr.is_loopback:
            errors.append("Loopback IP: %s" % ip)
    except ValueError:
        errors.append("Invalid IPv4: %s" % ip)
    return clean, errors


def validate_ipv6(ip):
    """Validate an IPv6 address."""
    errors = []
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            errors.append("Private IPv6: %s" % ip)
        if addr.is_loopback:
            errors.append("Loopback IPv6: %s" % ip)
    except ValueError:
        errors.append("Invalid IPv6: %s" % ip)
    return ip, errors


def validate_domain(domain):
    """Validate a domain name."""
    errors = []
    clean = domain.lower().strip().replace("[.]", ".")
    if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$', clean):
        errors.append("Invalid domain: %s" % domain)
    if clean in SAFE_DOMAINS or any(clean.endswith("." + s) for s in SAFE_DOMAINS):
        errors.append("Safe domain rejected: %s" % domain)
    return clean, errors


def validate_url(url):
    """Validate a URL."""
    errors = []
    clean = url.replace("[.]", ".").replace("hxxp", "http")
    if not re.match(r'^https?://', clean):
        errors.append("Invalid URL (must start with http/https): %s" % url)
    return clean, errors


def validate_cve(cve):
    """Validate CVE format."""
    errors = []
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve.upper()):
        errors.append("Invalid CVE format: %s (expected CVE-YYYY-NNNNN)" % cve)
    return cve.upper(), errors


def validate_cidr(cidr):
    """Validate CIDR notation."""
    errors = []
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.is_private:
            errors.append("Private CIDR: %s" % cidr)
    except ValueError:
        errors.append("Invalid CIDR: %s" % cidr)
    return cidr, errors


def validate_file(filepath, existing):
    """Validate a single submission file. Returns (errors, warnings, stats)."""
    errors = []
    warnings = []
    stats = {"new": 0, "duplicate": 0, "rejected": 0}

    try:
        data = load_yaml(str(filepath))
    except Exception as e:
        return ["Failed to parse YAML: %s" % e], warnings, stats

    if not data:
        return ["Empty or invalid YAML file"], warnings, stats

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in data or not data[field]:
            errors.append("Missing required field: %s" % field)

    # Validate each IOC type
    validators = {
        "ipv4": validate_ipv4, "ipv6": validate_ipv6,
        "domains": validate_domain, "urls": validate_url,
        "cves": validate_cve, "cidrs": validate_cidr,
    }

    for ioc_type in IOC_FIELDS:
        items = data.get(ioc_type, [])
        if not items or not isinstance(items, list):
            continue

        for item in items:
            if not item or not isinstance(item, str):
                continue

            validator = validators.get(ioc_type)
            if not validator:
                continue

            clean, item_errors = validator(item)

            if item_errors:
                errors.extend(item_errors)
                stats["rejected"] += 1
            elif clean.lower() in existing.get(ioc_type, set()):
                warnings.append("Duplicate %s: %s (already in database)" % (ioc_type, item))
                stats["duplicate"] += 1
            else:
                stats["new"] += 1

    return errors, warnings, stats


def main():
    """Validate all YAML files in community/submissions/."""
    files = list(SUBMISSIONS_DIR.glob("*.yaml")) + list(SUBMISSIONS_DIR.glob("*.yml"))

    if not files:
        print("No submission files found in community/submissions/")
        return 0

    existing = load_existing_iocs()
    total_errors = 0
    total_new = 0

    for filepath in sorted(files):
        if filepath.name == "TEMPLATE.yaml":
            continue

        print("\n=== %s ===" % filepath.name)
        errors, warnings, stats = validate_file(filepath, existing)

        if errors:
            print("  ERRORS:")
            for e in errors:
                print("    ✗ %s" % e)
            total_errors += len(errors)

        if warnings:
            print("  WARNINGS:")
            for w in warnings:
                print("    ⚠ %s" % w)

        print("  Stats: %d new, %d duplicate, %d rejected" % (
            stats["new"], stats["duplicate"], stats["rejected"]))
        total_new += stats["new"]

    print("\n" + "=" * 50)
    if total_errors:
        print("FAILED: %d error(s) found across %d file(s)" % (total_errors, len(files)))
        return 1
    else:
        print("PASSED: %d file(s) validated, %d new IOCs ready for review" % (len(files), total_new))
        return 0


if __name__ == "__main__":
    sys.exit(main())
