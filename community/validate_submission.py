#!/usr/bin/env python3
"""
Validates community IOC submissions (YAML files).
Used by GitHub Actions on PRs — never writes to the database.

Checks:
  - SECURITY: file size, extension, null bytes, YAML injection tags,
    shell metacharacters, path traversal, unknown fields
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

# =============================================================
# SECURITY LIMITS
# =============================================================
MAX_FILE_SIZE = 100 * 1024          # 100 KB per submission
MAX_IOCS_PER_TYPE = 500             # Max IOCs per type per submission
MAX_IOCS_TOTAL = 2000               # Max total IOCs per submission
MAX_VALUE_LENGTH = 500              # Max characters per IOC value
ALLOWED_EXTENSIONS = {'.yaml', '.yml'}
ALLOWED_FIELDS = {'author', 'source', 'source_name', 'apt_groups', 'description',
                  'ipv4', 'ipv6', 'domains', 'urls', 'emails', 'cidrs', 'cves'}

# Characters that should NEVER appear in IOC values (shell injection vectors)
DANGEROUS_CHARS = re.compile(r'[;|&`!{}()\x00-\x08\x0e-\x1f]')
# Path traversal
PATH_TRAVERSAL = re.compile(r'\.\.[/\\]')
# Forbidden YAML tags
YAML_INJECTION = re.compile(
    r'!!(?:python|ruby|perl|java|exec|import|apply|merge)',
    re.IGNORECASE
)
# Embedded code patterns
CODE_PATTERNS = re.compile(
    r'<script|<\?php|^#!.*/(?:bash|sh|python|perl|ruby)|'
    r'import\s+os\b|subprocess\.|eval\s*\(|exec\s*\(',
    re.IGNORECASE | re.MULTILINE
)

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


def check_value_safety(value, ioc_type):
    """Check a single IOC value for shell injection and path traversal."""
    errors = []
    if not isinstance(value, str):
        errors.append("SECURITY: %s value is not a string: %r" % (ioc_type, value))
        return errors
    if len(value) > MAX_VALUE_LENGTH:
        errors.append("SECURITY: %s value too long (%d chars, max %d): %s..." % (
            ioc_type, len(value), MAX_VALUE_LENGTH, value[:50]))
    if DANGEROUS_CHARS.search(value):
        errors.append("SECURITY: %s contains dangerous characters: %s" % (ioc_type, value))
    if PATH_TRAVERSAL.search(value):
        errors.append("SECURITY: %s contains path traversal: %s" % (ioc_type, value))
    return errors


def validate_file(filepath, existing):
    """Validate a single submission file. Returns (errors, warnings, stats)."""
    errors = []
    warnings = []
    stats = {"new": 0, "duplicate": 0, "rejected": 0}

    # ── Security pre-checks ──────────────────────────────────
    filepath = Path(filepath)

    # File extension check
    if filepath.suffix.lower() not in ALLOWED_EXTENSIONS:
        return ["SECURITY: invalid file extension '%s' (only .yaml/.yml allowed)" % filepath.suffix], warnings, stats

    # Filename check — alphanumeric, hyphens, dots only
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*\.ya?ml$', filepath.name):
        return ["SECURITY: suspicious filename '%s'" % filepath.name], warnings, stats

    # File size check
    try:
        file_size = filepath.stat().st_size
        if file_size > MAX_FILE_SIZE:
            return ["SECURITY: file too large (%d bytes, max %d)" % (file_size, MAX_FILE_SIZE)], warnings, stats
        if file_size == 0:
            return ["Empty file"], warnings, stats
    except OSError as e:
        return ["Cannot read file: %s" % e], warnings, stats

    # Raw content checks (before YAML parsing)
    try:
        raw = filepath.read_bytes()
        # Null bytes
        if b'\x00' in raw:
            return ["SECURITY: file contains null bytes"], warnings, stats
        raw_str = raw.decode('utf-8', errors='replace')
        # YAML deserialization tags
        if YAML_INJECTION.search(raw_str):
            return ["SECURITY: file contains forbidden YAML tags (!!python etc.)"], warnings, stats
        # Embedded code
        if CODE_PATTERNS.search(raw_str):
            return ["SECURITY: file contains suspicious code patterns"], warnings, stats
    except Exception as e:
        return ["SECURITY: cannot read file content: %s" % e], warnings, stats

    # ── YAML parsing ─────────────────────────────────────────
    try:
        data = load_yaml(str(filepath))
    except Exception as e:
        return ["Failed to parse YAML: %s" % e], warnings, stats

    if not data:
        return ["Empty or invalid YAML file"], warnings, stats

    if not isinstance(data, dict):
        return ["SECURITY: YAML root must be a mapping, got %s" % type(data).__name__], warnings, stats

    # Check for unexpected top-level keys
    unknown_keys = set(data.keys()) - ALLOWED_FIELDS
    if unknown_keys:
        errors.append("SECURITY: unknown fields: %s" % ', '.join(sorted(unknown_keys)))

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in data or not data[field]:
            errors.append("Missing required field: %s" % field)

    # ── Validate each IOC type ───────────────────────────────
    validators = {
        "ipv4": validate_ipv4, "ipv6": validate_ipv6,
        "domains": validate_domain, "urls": validate_url,
        "cves": validate_cve, "cidrs": validate_cidr,
    }

    total_iocs = 0

    for ioc_type in IOC_FIELDS:
        items = data.get(ioc_type, [])
        if not items or not isinstance(items, list):
            continue

        if len(items) > MAX_IOCS_PER_TYPE:
            errors.append("SECURITY: too many %s (%d, max %d per type)" % (ioc_type, len(items), MAX_IOCS_PER_TYPE))
            continue

        for item in items:
            if not item or not isinstance(item, str):
                continue

            total_iocs += 1
            if total_iocs > MAX_IOCS_TOTAL:
                errors.append("SECURITY: too many total IOCs (max %d)" % MAX_IOCS_TOTAL)
                return errors, warnings, stats

            # Safety check on raw value
            safety_errors = check_value_safety(item, ioc_type)
            if safety_errors:
                errors.extend(safety_errors)
                stats["rejected"] += 1
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

    # Security: reject any non-YAML files in submissions directory
    all_files = list(SUBMISSIONS_DIR.iterdir())
    for f in all_files:
        if f.is_file() and f.name != '.gitkeep' and f.suffix.lower() not in ALLOWED_EXTENSIONS:
            print("  SECURITY WARNING: unexpected file in submissions/: %s" % f.name)

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
