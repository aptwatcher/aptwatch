#!/usr/bin/env python3
"""
Generate blocklists in multiple formats from APT intelligence database.

Outputs:
  blocklists/apt-ips-high.netset      - High confidence IPs (5+ OSINT sources) — firehol format
  blocklists/apt-ips-medium.netset    - Medium confidence (3-4 sources) — firehol format
  blocklists/apt-ips-all.netset       - All validated IPs — firehol format
  blocklists/apt-subnets.netset       - High-density subnets (>15% IOC) — firehol CIDR format
  blocklists/apt-domains.hosts        - Malicious domains — StevenBlack hosts format
  blocklists/apt-domains-plain.txt    - Domains plain list (for DNS sinkhole)
  blocklists/apt-combined.hosts       - IPs + domains — StevenBlack hosts format

Usage:
  python3 scripts/generate_blocklists.py [--min-sources N] [--subnet-threshold PCT]
"""

import sqlite3
import os
import sys
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'apt_intel.db')
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'blocklists')

# Parse args
min_high = 5
min_medium = 3
subnet_threshold = 15.0  # % IOC density for subnet-level blocking

for i, arg in enumerate(sys.argv[1:], 1):
    if arg == '--min-sources' and i < len(sys.argv) - 1:
        min_high = int(sys.argv[i + 1])
    elif arg == '--subnet-threshold' and i < len(sys.argv) - 1:
        subnet_threshold = float(sys.argv[i + 1])

os.makedirs(OUT_DIR, exist_ok=True)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def firehol_header(name, description, category, entries):
    return f"""#
# {name}
# {description}
#
# Category: {category}
# Maintainer: APT Intelligence Database
# Generated: {now}
# Entries: {entries}
#
# This file is auto-generated from the APT intelligence database.
# DO NOT EDIT MANUALLY — re-run generate_blocklists.py instead.
#
# Redistribution: TLP:AMBER — do not share publicly
#
"""

def stevenblack_header(name, description, entries):
    return f"""# Title: {name}
# Description: {description}
# Last modified: {now}
# Entries: {entries}
# Homepage: APT Intelligence Database
# License: TLP:AMBER — do not share publicly
#
# This file is auto-generated. Re-run generate_blocklists.py to update.
#
"""

# === 1. HIGH CONFIDENCE IPs (5+ OSINT sources) ===
high_ips = [r[0] for r in c.execute(
    "SELECT DISTINCT ip FROM ipv4_iocs WHERE validation_count >= ? ORDER BY ip", (min_high,)
).fetchall()]

with open(os.path.join(OUT_DIR, 'apt-ips-high.netset'), 'w') as f:
    f.write(firehol_header(
        'apt-ips-high',
        f'High confidence APT IPs ({min_high}+ OSINT sources)',
        'apt/threat-intelligence',
        len(high_ips)
    ))
    for ip in high_ips:
        f.write(ip + '\n')
print(f"  apt-ips-high.netset: {len(high_ips):,} IPs")

# === 2. MEDIUM CONFIDENCE IPs (3+ sources) ===
med_ips = [r[0] for r in c.execute(
    "SELECT DISTINCT ip FROM ipv4_iocs WHERE validation_count >= ? ORDER BY ip", (min_medium,)
).fetchall()]

with open(os.path.join(OUT_DIR, 'apt-ips-medium.netset'), 'w') as f:
    f.write(firehol_header(
        'apt-ips-medium',
        f'Medium+ confidence APT IPs ({min_medium}+ OSINT sources)',
        'apt/threat-intelligence',
        len(med_ips)
    ))
    for ip in med_ips:
        f.write(ip + '\n')
print(f"  apt-ips-medium.netset: {len(med_ips):,} IPs")

# === 3. ALL VALIDATED IPs ===
all_ips = [r[0] for r in c.execute(
    "SELECT DISTINCT ip FROM ipv4_iocs WHERE validation_count >= 1 ORDER BY ip"
).fetchall()]

with open(os.path.join(OUT_DIR, 'apt-ips-all.netset'), 'w') as f:
    f.write(firehol_header(
        'apt-ips-all',
        'All validated APT IPs (1+ OSINT sources)',
        'apt/threat-intelligence',
        len(all_ips)
    ))
    for ip in all_ips:
        f.write(ip + '\n')
print(f"  apt-ips-all.netset: {len(all_ips):,} IPs")

# === 4. HIGH-DENSITY SUBNETS (CIDR blocks) ===
subnets = c.execute("""
    SELECT cidr, ioc_count, ROUND(ioc_count * 100.0 / 256, 1) as pct, asn_org
    FROM subnets 
    WHERE (ioc_count * 100.0 / 256) >= ?
    ORDER BY ioc_count DESC
""", (subnet_threshold,)).fetchall()

with open(os.path.join(OUT_DIR, 'apt-subnets.netset'), 'w') as f:
    f.write(firehol_header(
        'apt-subnets',
        f'High-density APT subnets (>{subnet_threshold}% IOC density)',
        'apt/threat-intelligence',
        len(subnets)
    ))
    for cidr, iocs, pct, org in subnets:
        f.write(f"{cidr}  # {iocs} IOCs ({pct}%) — {(org or 'unknown')[:50]}\n")
print(f"  apt-subnets.netset: {len(subnets)} CIDRs")

# === 5. MALICIOUS DOMAINS — StevenBlack hosts format ===
# Only include domains from threat reports, not the full 1.5M domain list
threat_domains = [r[0] for r in c.execute(
    "SELECT DISTINCT domain FROM domains WHERE source_file LIKE '%blacksanta%' OR source_file LIKE '%threat%' ORDER BY domain"
).fetchall()]

# Also include known malicious from metadata
import json
try:
    bs_data = c.execute("SELECT value FROM metadata WHERE key='blacksanta_validin'").fetchone()
    if bs_data:
        bs = json.loads(bs_data[0])
        for d in bs.get('domains', []):
            if d not in threat_domains:
                threat_domains.append(d)
except: pass

with open(os.path.join(OUT_DIR, 'apt-domains.hosts'), 'w') as f:
    f.write(stevenblack_header(
        'APT Malicious Domains',
        'Domains from APT threat intelligence reports',
        len(threat_domains)
    ))
    for domain in sorted(set(threat_domains)):
        f.write(f"0.0.0.0 {domain}\n")
print(f"  apt-domains.hosts: {len(threat_domains)} domains")

# === 6. PLAIN DOMAIN LIST (for DNS sinkhole / pihole) ===
with open(os.path.join(OUT_DIR, 'apt-domains-plain.txt'), 'w') as f:
    for domain in sorted(set(threat_domains)):
        f.write(domain + '\n')
print(f"  apt-domains-plain.txt: {len(threat_domains)} domains")

# === 7. COMBINED hosts file (IPs + domains) ===
with open(os.path.join(OUT_DIR, 'apt-combined.hosts'), 'w') as f:
    f.write(stevenblack_header(
        'APT Combined Blocklist',
        f'All validated APT IPs + malicious domains',
        len(all_ips) + len(threat_domains)
    ))
    f.write("# === MALICIOUS IPs ===\n")
    for ip in all_ips:
        f.write(f"0.0.0.0 {ip}\n")
    f.write(f"\n# === MALICIOUS DOMAINS ===\n")
    for domain in sorted(set(threat_domains)):
        f.write(f"0.0.0.0 {domain}\n")
print(f"  apt-combined.hosts: {len(all_ips) + len(threat_domains)} entries")

# === Summary ===
print(f"\n=== BLOCKLIST GENERATION COMPLETE ===")
print(f"  Output directory: blocklists/")
print(f"  High confidence IPs:  {len(high_ips):,}")
print(f"  Medium+ IPs:          {len(med_ips):,}")
print(f"  All validated IPs:    {len(all_ips):,}")
print(f"  Subnet blocks:        {len(subnets)}")
print(f"  Threat domains:       {len(threat_domains)}")
print(f"\n  Usage:")
print(f"    Firewall (strict):  apt-ips-high.netset + apt-subnets.netset")
print(f"    Firewall (broad):   apt-ips-all.netset + apt-subnets.netset")
print(f"    DNS sinkhole:       apt-domains-plain.txt")
print(f"    Hosts file:         apt-combined.hosts")
print(f"    firehol ipset:      ipset create apt-high hash:ip; while read ip; do ipset add apt-high $ip; done < apt-ips-high.netset")

conn.close()
