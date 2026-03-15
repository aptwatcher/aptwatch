#!/usr/bin/env python3
"""
Recon & Enrichment Tool for APT Intelligence Database
Discovers new candidates by enriching existing IOCs via free online APIs.

Features:
  - RDAP/WHOIS lookups for IP and domain registration data
  - ASN expansion: find sibling IPs in same ASN ranges
  - Subnet neighbor discovery from known-bad /24s
  - Staging server detection (proxy + C2 pattern analysis)
  - Confidence scoring for new candidates

Free APIs used (no keys required):
  - RDAP (ARIN/RIPE/APNIC): IP and domain registration
  - ipinfo.io: Geolocation + ASN (limited free tier)
  - bgp.he.net: ASN details (scraping)
  - ip-api.com: Geolocation batch (free, 45/min)

Usage:
    python database/recon.py enrich-top [N]       # Enrich top N critical IPs
    python database/recon.py enrich-ip <IP>       # Enrich single IP
    python database/recon.py enrich-subnet <CIDR> # Enrich all IPs in a subnet
    python database/recon.py expand-asn <ASN>     # Find new IPs in ASN
    python database/recon.py detect-staging       # Detect staging/proxy servers
    python database/recon.py find-candidates      # Run full candidate discovery
    python database/recon.py report               # Show recon summary
"""

import sqlite3
import json
import re
import sys
import time
import ipaddress
import socket
from pathlib import Path
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import quote

BASE_DIR = Path(__file__).parent.parent
DB_PATH = Path(__file__).parent.parent / 'database' / 'apt_intel.db'

# Rate limiting
RATE_LIMIT = 1.0  # seconds between API calls
_last_request = 0

def rate_limit():
    global _last_request
    elapsed = time.time() - _last_request
    if elapsed < RATE_LIMIT:
        time.sleep(RATE_LIMIT - elapsed)
    _last_request = time.time()


def get_conn():
    if not DB_PATH.exists():
        print(f"ERROR: {DB_PATH} not found. Run rebuild_db.py first.")
        sys.exit(1)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def api_get(url, timeout=15):
    """Make a GET request with rate limiting and error handling."""
    rate_limit()
    try:
        req = Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; APT-Intel-Recon/1.0)',
            'Accept': 'application/json'
        })
        resp = urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode('utf-8', errors='ignore'))
    except (URLError, HTTPError, json.JSONDecodeError, Exception) as e:
        return {'error': str(e)}


# =============================================================
# ENRICHMENT FUNCTIONS
# =============================================================

def enrich_ip_rdap(ip):
    """Query RDAP for IP registration data."""
    data = api_get(f'https://rdap.org/ip/{ip}')
    if 'error' in data:
        return data

    result = {
        'source': 'rdap',
        'country': data.get('country', ''),
        'name': data.get('name', ''),
    }

    # Extract entity info (registrant, abuse contact)
    for entity in data.get('entities', []):
        roles = entity.get('roles', [])
        vcard = entity.get('vcardArray', [None, []])[1] if 'vcardArray' in entity else []
        name = ''
        email = ''
        for item in vcard:
            if isinstance(item, list):
                if item[0] == 'fn':
                    name = item[3] if len(item) > 3 else ''
                if item[0] == 'email':
                    email = item[3] if len(item) > 3 else ''
        if 'registrant' in roles:
            result['registrant'] = name
        if 'abuse' in roles:
            result['abuse_contact'] = email

    # Extract CIDR blocks
    cidrs = data.get('cidr0_cidrs', [])
    if cidrs:
        result['network'] = f"{cidrs[0].get('v4prefix', '')}/{cidrs[0].get('length', '')}"

    # Events (registration, last changed)
    for event in data.get('events', []):
        action = event.get('eventAction', '')
        date = event.get('eventDate', '')
        if action == 'registration':
            result['created_date'] = date
        elif action == 'last changed':
            result['updated_date'] = date

    return result


def enrich_ip_ipinfo(ip):
    """Query ip-api.com for geolocation and ASN (free, 45/min)."""
    data = api_get(f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,isp,org,as,asname,reverse,hosting')
    if data.get('status') == 'fail':
        return {'error': data.get('message', 'unknown')}

    asn = None
    as_str = data.get('as', '')
    if as_str:
        match = re.match(r'AS(\d+)', as_str)
        if match:
            asn = int(match.group(1))

    return {
        'source': 'ip-api',
        'asn': asn,
        'asn_org': data.get('asname', ''),
        'country': data.get('countryCode', ''),
        'city': data.get('city', ''),
        'hosting_provider': data.get('isp', ''),
        'reverse_dns': data.get('reverse', ''),
        'is_hosting': data.get('hosting', False),
        'org': data.get('org', ''),
    }


def enrich_ip_batch(ips, conn):
    """Enrich a list of IPs and store results."""
    now = datetime.now().isoformat()
    enriched = 0

    for ip in ips:
        # Skip if already enriched recently
        existing = conn.execute(
            "SELECT id FROM enrichment_results WHERE indicator=? AND source='ip-api'",
            (ip,)
        ).fetchone()
        if existing:
            continue

        print(f"  Enriching {ip}...", end=' ', flush=True)

        # ip-api.com (free, fast)
        geo = enrich_ip_ipinfo(ip)
        if 'error' not in geo:
            conn.execute("""
                INSERT OR REPLACE INTO enrichment_results
                (indicator, indicator_type, source, raw_data, asn, asn_org,
                 country, city, reverse_dns, hosting_provider, queried_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (ip, 'ip', 'ip-api', json.dumps(geo), geo.get('asn'),
                  geo.get('asn_org'), geo.get('country'), geo.get('city'),
                  geo.get('reverse_dns'), geo.get('hosting_provider'), now))
            print(f"ASN:{geo.get('asn')} {geo.get('country')} {geo.get('hosting_provider', '')[:30]}")

            # Update asn_info table
            if geo.get('asn'):
                conn.execute("""
                    INSERT OR IGNORE INTO asn_info (asn, org_name, country)
                    VALUES (?,?,?)
                """, (geo['asn'], geo.get('asn_org', ''), geo.get('country', '')))

            enriched += 1
        else:
            print(f"FAILED: {geo['error'][:50]}")

        # RDAP (slower, more detail)
        rdap = enrich_ip_rdap(ip)
        if 'error' not in rdap:
            conn.execute("""
                INSERT OR REPLACE INTO enrichment_results
                (indicator, indicator_type, source, raw_data, country,
                 registrar, created_date, updated_date, abuse_contact, queried_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (ip, 'ip', 'rdap', json.dumps(rdap), rdap.get('country', ''),
                  rdap.get('name', ''), rdap.get('created_date', ''),
                  rdap.get('updated_date', ''), rdap.get('abuse_contact', ''), now))

        conn.commit()

    return enriched


def try_reverse_dns(ip):
    """Attempt reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


# =============================================================
# STAGING SERVER DETECTION
# =============================================================

def detect_staging_servers(conn):
    """
    Identify staging/coordination servers based on behavioral patterns:
    - Proxy services (squid, nginx, socks) + C2 frameworks
    - Multiple C2 frameworks on single IP (relay/coordinator)
    - SSH + proxy combo (command forwarding)
    - High-port admin panels + C2
    """
    now = datetime.now().isoformat()
    detected = 0

    # Pattern 1: Proxy + C2 (staging/relay nodes)
    print("  Checking proxy + C2 patterns...")
    rows = conn.execute("""
        SELECT DISTINCT ip, services, c2_indicators, risk_score, open_ports
        FROM scan_results
        WHERE (services LIKE '%squid%' OR services LIKE '%socks%'
               OR services LIKE '%proxy%' OR services LIKE '%nginx%')
          AND c2_indicators IS NOT NULL AND c2_indicators != ''
        ORDER BY risk_score DESC
    """).fetchall()

    for row in rows:
        ip = row['ip']
        services = row['services'] or ''
        c2 = row['c2_indicators'] or ''
        risk = row['risk_score'] or 0

        reasons = []
        role = 'staging'
        confidence = 0.5

        # Detect proxy type
        proxy_services = []
        for proxy in ['squid', 'socks', 'nginx', 'haproxy']:
            if proxy in services.lower():
                proxy_services.append(proxy)
                reasons.append(f'proxy_service:{proxy}')

        # Count C2 frameworks
        c2_list = [x.strip() for x in re.split(r'[,\[\]"{}]', c2) if x.strip() and x.strip() not in ('c2_frameworks', 'lateral_movement')]
        c2_frameworks = [x for x in c2_list if x in ('gh0st_rat', 'empire', 'metasploit', 'custom_c2', 'back_orifice', 'cobalt_strike')]

        if len(c2_frameworks) >= 2:
            reasons.append(f'multi_c2:{",".join(c2_frameworks)}')
            confidence += 0.15
            role = 'c2_relay'

        if 'ssh' in services.lower():
            reasons.append('ssh_tunnel_capable')
            confidence += 0.1

        if 'vpn' in services.lower():
            reasons.append('vpn_tunnel')
            confidence += 0.05

        if risk >= 500:
            confidence += 0.1
        if risk >= 200:
            confidence += 0.05

        confidence = min(confidence, 0.95)

        # Find potential downstream targets (same subnet)
        subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
        downstream = conn.execute("""
            SELECT DISTINCT ip FROM scan_results
            WHERE ip LIKE ? AND ip != ? AND c2_indicators IS NOT NULL
        """, ('.'.join(ip.split('.')[:3]) + '%', ip)).fetchall()
        downstream_ips = [r['ip'] for r in downstream]

        conn.execute("""
            INSERT OR REPLACE INTO staging_servers
            (ip, role, confidence, detection_reasons, downstream_ips,
             proxy_services, c2_frameworks, first_seen, last_seen, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (ip, role, confidence, json.dumps(reasons),
              json.dumps(downstream_ips) if downstream_ips else None,
              ','.join(proxy_services), ','.join(c2_frameworks),
              now, now, now))
        detected += 1

    # Pattern 2: Multi-C2 without proxy (coordination nodes)
    print("  Checking multi-C2 coordination nodes...")
    rows = conn.execute("""
        SELECT DISTINCT ip, services, c2_indicators, risk_score
        FROM scan_results
        WHERE c2_indicators LIKE '%,%'
          AND c2_indicators NOT LIKE '%[%'
          AND ip NOT IN (SELECT ip FROM staging_servers)
        ORDER BY risk_score DESC
    """).fetchall()

    for row in rows:
        ip = row['ip']
        c2 = row['c2_indicators'] or ''
        c2_list = [x.strip() for x in c2.split(',') if x.strip()]
        c2_frameworks = [x for x in c2_list if x in ('gh0st_rat', 'empire', 'metasploit', 'custom_c2', 'back_orifice', 'cobalt_strike')]

        if len(c2_frameworks) >= 3:
            confidence = 0.7
            role = 'c2_relay'
        elif len(c2_frameworks) >= 2:
            confidence = 0.5
            role = 'c2_relay'
        else:
            continue

        reasons = [f'multi_c2:{",".join(c2_frameworks)}']
        services = row['services'] or ''
        if 'database' in services.lower() or 'mysql' in services.lower():
            reasons.append('database_access')
            confidence += 0.1

        confidence = min(confidence, 0.95)

        conn.execute("""
            INSERT OR REPLACE INTO staging_servers
            (ip, role, confidence, detection_reasons, c2_frameworks,
             first_seen, last_seen, updated_at)
            VALUES (?,?,?,?,?,?,?,?)
        """, (ip, role, confidence, json.dumps(reasons),
              ','.join(c2_frameworks), now, now, now))
        detected += 1

    conn.commit()
    return detected


# =============================================================
# CANDIDATE DISCOVERY
# =============================================================

def find_candidates_from_asn(conn):
    """
    Find new candidate IPs by analyzing ASN clustering.
    If multiple known IOCs share an ASN, other IPs in that ASN are candidates.
    """
    now = datetime.now().isoformat()
    found = 0

    # Get ASNs with enrichment data
    rows = conn.execute("""
        SELECT asn, asn_org, country, COUNT(*) as ioc_count
        FROM enrichment_results
        WHERE asn IS NOT NULL AND indicator_type='ip'
        GROUP BY asn
        HAVING ioc_count >= 3
        ORDER BY ioc_count DESC
    """).fetchall()

    for row in rows:
        asn = row['asn']
        org = row['asn_org'] or ''
        country = row['country'] or ''
        ioc_count = row['ioc_count']

        # Calculate confidence based on IOC density
        confidence = min(0.3 + (ioc_count * 0.05), 0.85)

        # Store as ASN-level candidate
        conn.execute("""
            INSERT OR REPLACE INTO recon_candidates
            (indicator, indicator_type, discovery_method, confidence,
             asn, asn_org, country, classification, notes, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (f'AS{asn}', 'asn', 'asn_clustering',
              confidence, asn, org, country, 'CANDIDATE',
              f'{ioc_count} known IOCs in this ASN', now))
        found += 1

    conn.commit()
    return found


def find_candidates_from_subnets(conn):
    """
    Find new candidate subnets by analyzing /24 neighborhood patterns.
    Adjacent subnets to high-tier ones are likely candidates.
    """
    now = datetime.now().isoformat()
    found = 0

    # Get TIER_A and TIER_S subnets
    hot_subnets = conn.execute("""
        SELECT cidr, ioc_count, tier FROM subnets
        WHERE tier IN ('TIER_S', 'TIER_A', 'TIER_B')
        ORDER BY ioc_count DESC
    """).fetchall()

    known_subnets = set()
    for s in conn.execute("SELECT cidr FROM subnets").fetchall():
        known_subnets.add(s['cidr'])

    for row in hot_subnets:
        cidr = row['cidr']
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            base_int = int(network.network_address)
        except ValueError:
            continue

        # Check adjacent /24s (±1, ±2)
        for offset in [-2, -1, 1, 2]:
            neighbor_int = base_int + (offset * 256)
            try:
                neighbor_ip = ipaddress.IPv4Address(neighbor_int)
                neighbor_cidr = f"{neighbor_ip}/24"
            except (ValueError, ipaddress.AddressValueError):
                continue

            if neighbor_cidr in known_subnets:
                continue

            confidence = 0.4 if abs(offset) == 1 else 0.25
            if row['tier'] == 'TIER_S':
                confidence += 0.2
            elif row['tier'] == 'TIER_A':
                confidence += 0.1

            conn.execute("""
                INSERT OR REPLACE INTO recon_candidates
                (indicator, indicator_type, discovery_method, related_to,
                 confidence, classification, notes, updated_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (neighbor_cidr, 'subnet', 'subnet_adjacency', cidr,
                  confidence, 'CANDIDATE',
                  f'Adjacent to {row["tier"]} subnet {cidr} ({row["ioc_count"]} IOCs)', now))
            found += 1

    conn.commit()
    return found


def find_candidates_from_staging(conn):
    """
    Analyze staging servers to find upstream C2 candidates.
    Look at IPs that appear across multiple subnet clusters as potential coordinators.
    """
    now = datetime.now().isoformat()
    found = 0

    # Find IPs that appear in scans across multiple /24 subnets (multi-subnet actors)
    rows = conn.execute("""
        SELECT ip, COUNT(DISTINCT source_file) as source_count,
               MAX(risk_score) as max_risk,
               GROUP_CONCAT(DISTINCT c2_indicators) as all_c2
        FROM scan_results
        WHERE c2_indicators IS NOT NULL AND c2_indicators != ''
        GROUP BY ip
        HAVING source_count >= 2
        ORDER BY max_risk DESC
    """).fetchall()

    for row in rows:
        ip = row['ip']
        # Check if it's already a known staging server
        existing = conn.execute("SELECT id FROM staging_servers WHERE ip=?", (ip,)).fetchone()
        if not existing:
            confidence = min(0.4 + (row['source_count'] * 0.1), 0.8)
            conn.execute("""
                INSERT OR REPLACE INTO recon_candidates
                (indicator, indicator_type, discovery_method, confidence,
                 risk_score, classification, notes, updated_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (ip, 'ip', 'multi_source_correlation', confidence,
                  row['max_risk'], 'CANDIDATE',
                  f"Appears in {row['source_count']} sources, C2: {row['all_c2'][:100]}", now))
            found += 1

    conn.commit()
    return found


# =============================================================
# COMMANDS
# =============================================================

def cmd_enrich_top(n=20):
    """Enrich top N critical IPs."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT DISTINCT ip FROM scan_results
        WHERE classification IN ('CRITICAL', 'HIGH')
          AND ip NOT IN (SELECT indicator FROM enrichment_results WHERE source='ip-api')
        ORDER BY risk_score DESC
        LIMIT ?
    """, (n,)).fetchall()

    ips = [r['ip'] for r in rows]
    print(f"Enriching {len(ips)} IPs...")
    enriched = enrich_ip_batch(ips, conn)
    conn.close()
    print(f"\nDone. Enriched {enriched} IPs.")


def cmd_enrich_ip(ip):
    """Enrich a single IP."""
    conn = get_conn()
    enriched = enrich_ip_batch([ip], conn)
    conn.close()
    print(f"Done. Enriched {enriched} IP(s).")


def cmd_enrich_subnet(cidr):
    """Enrich all known IOC IPs in a subnet."""
    conn = get_conn()
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        print(f"Invalid CIDR: {cidr}")
        return

    rows = conn.execute("""
        SELECT DISTINCT ip FROM ipv4_iocs
    """).fetchall()

    ips = [r['ip'] for r in rows if ipaddress.IPv4Address(r['ip']) in network]
    print(f"Found {len(ips)} IOC IPs in {cidr}")
    enriched = enrich_ip_batch(ips[:50], conn)  # cap at 50 per run
    conn.close()
    print(f"Done. Enriched {enriched} IPs.")


def cmd_detect_staging():
    """Run staging server detection."""
    conn = get_conn()
    print("Running staging server detection...")
    detected = detect_staging_servers(conn)
    conn.close()
    print(f"\nDetected {detected} staging/relay servers.")


def cmd_find_candidates():
    """Run full candidate discovery pipeline."""
    conn = get_conn()
    print("=" * 60)
    print("CANDIDATE DISCOVERY PIPELINE")
    print("=" * 60)

    print("\n[1/4] Detecting staging servers...")
    staging = detect_staging_servers(conn)
    print(f"  Found {staging} staging/relay servers")

    print("\n[2/4] Discovering ASN-based candidates...")
    asn_candidates = find_candidates_from_asn(conn)
    print(f"  Found {asn_candidates} ASN candidates")

    print("\n[3/4] Discovering subnet-adjacent candidates...")
    subnet_candidates = find_candidates_from_subnets(conn)
    print(f"  Found {subnet_candidates} subnet candidates")

    print("\n[4/4] Finding multi-source correlation candidates...")
    staging_candidates = find_candidates_from_staging(conn)
    print(f"  Found {staging_candidates} correlation candidates")

    # Summary
    total_candidates = conn.execute("SELECT COUNT(*) FROM recon_candidates").fetchone()[0]
    total_staging = conn.execute("SELECT COUNT(*) FROM staging_servers").fetchone()[0]

    print(f"\n{'=' * 60}")
    print(f"RESULTS:")
    print(f"  Staging servers:  {total_staging}")
    print(f"  Recon candidates: {total_candidates}")
    print(f"{'=' * 60}")

    conn.close()


def cmd_report():
    """Show recon summary report."""
    conn = get_conn()

    print("=" * 60)
    print("RECON & ENRICHMENT REPORT")
    print("=" * 60)

    # Enrichment stats
    enrich_count = conn.execute("SELECT COUNT(*) FROM enrichment_results").fetchone()[0]
    print(f"\nEnrichment results: {enrich_count}")

    if enrich_count > 0:
        print("\n  Top ASNs by IOC count:")
        rows = conn.execute("""
            SELECT asn, asn_org, country, COUNT(*) as cnt
            FROM enrichment_results
            WHERE asn IS NOT NULL
            GROUP BY asn ORDER BY cnt DESC LIMIT 10
        """).fetchall()
        for r in rows:
            print(f"    AS{r['asn']:>6}  {r['country'] or '??'}  {r['cnt']:>4} IOCs  {(r['asn_org'] or '')[:40]}")

        print("\n  Top countries:")
        rows = conn.execute("""
            SELECT country, COUNT(*) as cnt
            FROM enrichment_results WHERE country IS NOT NULL AND country != ''
            GROUP BY country ORDER BY cnt DESC LIMIT 10
        """).fetchall()
        for r in rows:
            print(f"    {r['country']:>4}: {r['cnt']:>4} IPs")

        print("\n  Top hosting providers:")
        rows = conn.execute("""
            SELECT hosting_provider, COUNT(*) as cnt
            FROM enrichment_results WHERE hosting_provider IS NOT NULL AND hosting_provider != ''
            GROUP BY hosting_provider ORDER BY cnt DESC LIMIT 10
        """).fetchall()
        for r in rows:
            print(f"    {r['cnt']:>4}  {(r['hosting_provider'] or '')[:50]}")

    # Staging servers
    staging_count = conn.execute("SELECT COUNT(*) FROM staging_servers").fetchone()[0]
    print(f"\nStaging servers: {staging_count}")
    if staging_count > 0:
        print("\n  By role:")
        rows = conn.execute("""
            SELECT role, COUNT(*) as cnt, AVG(confidence) as avg_conf
            FROM staging_servers GROUP BY role ORDER BY cnt DESC
        """).fetchall()
        for r in rows:
            print(f"    {r['role']:>12}: {r['cnt']:>4}  (avg confidence: {r['avg_conf']:.2f})")

        print("\n  Top staging servers (confidence > 0.6):")
        rows = conn.execute("""
            SELECT ip, role, confidence, c2_frameworks, proxy_services
            FROM staging_servers WHERE confidence > 0.6
            ORDER BY confidence DESC LIMIT 15
        """).fetchall()
        for r in rows:
            print(f"    {r['ip']:>18}  {r['role']:>10}  conf:{r['confidence']:.2f}  "
                  f"c2:{r['c2_frameworks'] or '-'}  proxy:{r['proxy_services'] or '-'}")

    # Recon candidates
    cand_count = conn.execute("SELECT COUNT(*) FROM recon_candidates").fetchone()[0]
    print(f"\nRecon candidates: {cand_count}")
    if cand_count > 0:
        print("\n  By type:")
        rows = conn.execute("""
            SELECT indicator_type, COUNT(*) as cnt
            FROM recon_candidates GROUP BY indicator_type ORDER BY cnt DESC
        """).fetchall()
        for r in rows:
            print(f"    {r['indicator_type']:>8}: {r['cnt']:>4}")

        print("\n  By discovery method:")
        rows = conn.execute("""
            SELECT discovery_method, COUNT(*) as cnt, AVG(confidence) as avg_conf
            FROM recon_candidates GROUP BY discovery_method ORDER BY cnt DESC
        """).fetchall()
        for r in rows:
            print(f"    {(r['discovery_method'] or 'unknown'):>25}: {r['cnt']:>4}  (avg conf: {r['avg_conf']:.2f})")

        print("\n  Top candidates (highest confidence):")
        rows = conn.execute("""
            SELECT indicator, indicator_type, discovery_method, confidence, notes
            FROM recon_candidates ORDER BY confidence DESC LIMIT 15
        """).fetchall()
        for r in rows:
            print(f"    {r['indicator']:>22}  {r['indicator_type']:>7}  conf:{r['confidence']:.2f}  "
                  f"{r['discovery_method']}  {(r['notes'] or '')[:40]}")

    conn.close()


USAGE = """
Usage: python database/recon.py <command> [args]

Commands:
  enrich-top [N]         Enrich top N critical IPs (default: 20)
  enrich-ip <IP>         Enrich a single IP address
  enrich-subnet <CIDR>   Enrich all IOC IPs in a /24 subnet
  detect-staging         Detect staging/proxy/relay servers
  find-candidates        Run full candidate discovery pipeline
  report                 Show recon summary report

Pipeline (recommended order):
  1. python database/recon.py enrich-top 50
  2. python database/recon.py detect-staging
  3. python database/recon.py find-candidates
  4. python database/recon.py report
"""

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'enrich-top':
        n = int(sys.argv[2]) if len(sys.argv) >= 3 else 20
        cmd_enrich_top(n)
    elif cmd == 'enrich-ip' and len(sys.argv) >= 3:
        cmd_enrich_ip(sys.argv[2])
    elif cmd == 'enrich-subnet' and len(sys.argv) >= 3:
        cmd_enrich_subnet(sys.argv[2])
    elif cmd == 'detect-staging':
        cmd_detect_staging()
    elif cmd == 'find-candidates':
        cmd_find_candidates()
    elif cmd == 'report':
        cmd_report()
    else:
        print(USAGE)
        sys.exit(1)
