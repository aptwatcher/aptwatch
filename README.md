<p align="center">
  <img src="aptwatch-logo.png" alt="APTWatch" width="160">
</p>

<h1 align="center">APT Watch</h1>

<p align="center">Open-source threat intelligence database tracking Russian APT infrastructure.<br>Aggregates IOCs from OSINT sources, validates them against 10+ APIs, and serves live blocklist feeds.</p>

<p align="center">
  <code>threat-intelligence</code> · <code>apt</code> · <code>ioc</code> · <code>osint</code> · <code>cybersecurity</code> · <code>blocklist</code> · <code>firehol</code> · <code>pihole</code>
</p>

<p align="center">
  <a href="https://aptwatch.org"><strong>Live Dashboard</strong></a> · <a href="https://aptwatch.org/feeds.html"><strong>Blocklist Feeds</strong></a> · <a href="https://api.aptwatch.org"><strong>API</strong></a>
</p>

---

## What is APT Watch?

APT Watch is a threat intelligence platform that collects, validates, and distributes indicators of compromise (IOCs) related to Russian state-sponsored cyber operations. It tracks infrastructure used by groups like APT28 (Fancy Bear), Sandworm, APT29 (Cozy Bear), Gamaredon, and Turla.

The project provides three things:

- **A database** of 5,700+ validated IPv4 IOCs, 6,900+ CIDR ranges, 1.5M+ domains, and 94 CVEs, cross-referenced with vulnerability scans and enrichment data
- **Blocklist feeds** in standard formats (FireHOL, StevenBlack, plain text) that update automatically every 6 hours and can be plugged into firewalls, DNS sinkholes, and SIEM tools — including unified feeds (`aptw-*`) that merge our data with FireHOL, StevenBlack, URLhaus, AbuseIPDB, and Phishing.Database for broader coverage
- **An interactive dashboard** at [aptwatch.org](https://aptwatch.org) for exploring the data directly in the browser

---

## Live dashboard — aptwatch.org

The dashboard at [aptwatch.org](https://aptwatch.org) is a fully client-side application. It loads an SQLite database directly in your browser using sql.js — no backend, no account, no tracking. Everything runs locally on your machine.

When you visit the site, it automatically fetches the web export database (~23 MB) and lets you explore:

- **Overview** — IOC counts, classification distribution, subnet tiers, top ASNs, validation coverage
- **IOC Explorer** — search and filter IPv4, IPv6, domains, CIDRs, CVEs, emails
- **Scan Results** — vulnerability scan data with risk scores, C2 indicators, and service fingerprints
- **Recon** — staging servers, recon candidates, enrichment data, ASN intelligence map
- **Validation** — OSINT validation status per source, quick IP lookup via Shodan InternetDB and VirusTotal
- **Attribution** — campaign mapping across 13 campaigns, inter-agency correlations (GRU/FSB/SVR), hosting providers, certificate patterns, takedown targets
- **Custom SQL** — run arbitrary queries with 17 pre-built templates
- **Export** — download any table or query result as CSV

You can also open `web/index.html` locally with any browser and load a database file manually — useful for offline analysis or working with the full database.

---

## Database versions

Two versions of the database are available, depending on your use case.

### Web export (~23 MB)

The web export is built for the browser dashboard. It contains all the intelligence data you need for analysis but excludes bulk tables that would make it too large to load in a browser.

**Included:** 5,774 IPv4 IOCs, 6,941 CIDRs, 6,832 scan results, 10,000+ vulnerability findings (Critical + High + top Medium by CVSS), 32,808 enrichment results, 1,117 staging servers, 415 recon candidates, 497 ASN records, 94 CVEs, 162 emails, campaign attribution and inter-agency correlation data.

**Excluded:** 1.5M domains, 254K URLs, 317K Low/None vulnerability findings, validation queue (operational data). Domain and URL counts are stored in metadata so the dashboard can display totals.

Download: [api.aptwatch.org/api/download/web](https://api.aptwatch.org/api/download/web)

### Full database (~400 MB)

The full database contains everything — all 1.5M domains, 254K URLs, every vulnerability finding at every severity level, and the operational validation queue. Use this if you need complete domain/URL coverage for DNS analysis, full vulnerability scan data, or want to run the validation pipeline locally.

Download: [api.aptwatch.org/api/download/full](https://api.aptwatch.org/api/download/full) (rate limited, served behind Cloudflare)

Both versions share the same schema (`database/schema_v2.sql`) and work with all CLI commands and the dashboard.

---

## Using the blocklists

The easiest way to use APT Watch is to subscribe to the blocklist feeds. No setup required.

### APT-specific blocklists (Russian APT infrastructure only)

| Feed | Format | Link |
|------|--------|------|
| High confidence IPs (5+ OSINT sources) | FireHOL .netset | [aptw-apt-ips-high.netset](https://aptwatch.org/blocklists/aptw-apt-ips-high.netset) |
| Medium confidence IPs (3+ sources) | FireHOL .netset | [aptw-apt-ips-medium.netset](https://aptwatch.org/blocklists/aptw-apt-ips-medium.netset) |
| All validated IPs | FireHOL .netset | [aptw-apt-ips-all.netset](https://aptwatch.org/blocklists/aptw-apt-ips-all.netset) |
| High-density subnets | FireHOL .netset | [aptw-apt-subnets.netset](https://aptwatch.org/blocklists/aptw-apt-subnets.netset) |
| Malicious domains | StevenBlack .hosts | [aptw-apt-domains.hosts](https://aptwatch.org/blocklists/aptw-apt-domains.hosts) |
| Plain domain list (Pi-hole/DNS) | Text | [aptw-apt-domains-plain.txt](https://aptwatch.org/blocklists/aptw-apt-domains-plain.txt) |
| Combined IPs + domains | StevenBlack .hosts | [aptw-apt-combined.hosts](https://aptwatch.org/blocklists/aptw-apt-combined.hosts) |

### Unified blocklists (APT Watch + external feeds — for Pi-hole, firewalls, etc.)

These merge our APT-specific intelligence with major external threat feeds for broader protection. All entries are deduplicated and RFC1918-filtered.

| Feed | Format | Sources | Link |
|------|--------|---------|------|
| All threat IPs | FireHOL .netset | APT Watch + FireHOL L1/L2 + AbuseIPDB | [aptw-full-ips.netset](https://aptwatch.org/blocklists/aptw-full-ips.netset) |
| All threat domains | StevenBlack .hosts | APT Watch + StevenBlack + URLhaus + Phishing.Database | [aptw-full-domains.hosts](https://aptwatch.org/blocklists/aptw-full-domains.hosts) |
| All threat domains (plain) | Text | Same as above | [aptw-full-domains-plain.txt](https://aptwatch.org/blocklists/aptw-full-domains-plain.txt) |
| Resolved IPs from domains | FireHOL .netset | DNS A records of malicious domains | [aptw-resolved-ips.netset](https://aptwatch.org/blocklists/aptw-resolved-ips.netset) |
| Reverse DNS hostnames | StevenBlack .hosts | PTR records of malicious IPs | [aptw-reverse-dns.hosts](https://aptwatch.org/blocklists/aptw-reverse-dns.hosts) |
| Cryptojacking mining pools | StevenBlack .hosts | 56K+ mining pool domains | [aptw-mining.hosts](https://aptwatch.org/blocklists/aptw-mining.hosts) |

### Firewall integration

```bash
# iptables/ipset — block high-confidence APT IPs
ipset create apt-high hash:ip
curl -s https://aptwatch.org/blocklists/aptw-apt-ips-high.netset | grep -v '^#' | while read ip; do
  ipset add apt-high "$ip"
done
iptables -I INPUT -m set --match-set apt-high src -j DROP
```

### Pi-hole / DNS sinkhole

Add these URLs as blocklists in Pi-hole or AdGuard Home:

```
# APT-only (Russian APT domains)
https://aptwatch.org/blocklists/aptw-apt-domains-plain.txt

# Full coverage (APT + StevenBlack + URLhaus + Phishing.Database)
https://aptwatch.org/blocklists/aptw-full-domains-plain.txt

# Cryptojacking / mining pools
https://aptwatch.org/blocklists/aptw-mining.hosts
```

### Scheduled updates

Blocklists update automatically every 6 hours. Set up a cron job to pull fresh data:

```bash
# crontab -e
0 */6 * * * curl -s -o /etc/blocklists/aptw-apt-ips-high.netset https://aptwatch.org/blocklists/aptw-apt-ips-high.netset
```

---

## Using the CLI

Clone the repo and use `apt.py` for local analysis. No API keys required for basic operations.

```bash
git clone https://github.com/aptwatcher/aptwatch.git
cd aptwatch
python3 apt.py                       # Interactive menu
```

### Core commands

```bash
python3 apt.py query stats           # Database statistics
python3 apt.py query ip 1.2.3.4      # Full IP profile
python3 apt.py query critical        # Top critical IPs
python3 apt.py rebuild               # Full DB rebuild from source files
python3 apt.py import vulnscan scan.csv    # Import vulnerability scan
python3 apt.py export                # Export web DB for dashboard
```

### OSINT validation

Validation checks IOCs against 10 OSINT sources. Shodan InternetDB requires no key. Other sources are optional — add your keys to `config.ini` (copy from `config.ini.example`).

```bash
python3 apt.py validate auto         # Scheduled run (respects daily limits)
python3 apt.py validate run shodan 100    # Run one source
python3 apt.py validate run all 100       # All sources, 100 IPs each
python3 apt.py validate check 1.2.3.4     # Check a single IP
python3 apt.py validate status            # Coverage stats
```

### Recon & enrichment

```bash
python3 apt.py recon enrich-top 100  # Enrich via ip-api.com + RDAP
python3 apt.py recon detect-staging  # Find staging/relay servers
python3 apt.py recon find-candidates # Discover new infrastructure
python3 apt.py recon report          # Summary report
```

### Validation sources

| Source | Key Required | Free Tier |
|--------|-------------|-----------|
| Shodan InternetDB | No | Unlimited |
| DShield/SANS ISC | No | ~5,000/day |
| abuse.ch ThreatFox | No | ~5,000/day |
| FireHOL blocklists | No | Offline |
| Steven Black hosts | No | Offline |
| AlienVault OTX | Yes | ~10,000/day |
| AbuseIPDB | Yes | 1,000/day |
| VirusTotal | Yes | 500/day |
| Censys | Yes | Limited |

All sources are optional. Missing keys are auto-skipped.

---

## API

The API at `api.aptwatch.org` serves blocklists, IOC lookups, and database downloads. All endpoints are read-only and rate-limited behind Cloudflare.

| Endpoint | Description |
|----------|-------------|
| `GET /api/blocklist/ips/high` | High confidence IPs (FireHOL .netset) |
| `GET /api/blocklist/ips/medium` | Medium confidence IPs |
| `GET /api/blocklist/ips` | All validated IPs |
| `GET /api/blocklist/subnets` | High-density /24 subnets |
| `GET /api/blocklist/domains` | Malicious domains (StevenBlack .hosts) |
| `GET /api/blocklist/combined` | IPs + domains combined |
| `GET /api/blocklist/unified/ips` | Unified IPs (APT + FireHOL + AbuseIPDB) |
| `GET /api/blocklist/unified/domains` | Unified domains (APT + StevenBlack + URLhaus) |
| `GET /api/blocklist/unified/mining` | Cryptojacking mining pool domains |
| `GET /api/blocklist/resolved` | IPs resolved from malicious domains |
| `GET /api/blocklist/reverse` | Reverse DNS hostnames of malicious IPs |
| `GET /api/feed/json` | Latest IOCs as JSON feed |
| `GET /api/ioc/<ip>` | Full profile for a single IP |
| `GET /api/search?q=<pattern>` | Search across IOCs |
| `GET /api/stats` | Database statistics |
| `GET /api/download/web` | Download web export (~23 MB) |
| `GET /api/download/full` | Download full database (~400 MB) |

---

## Contributing

Contributions are welcome — whether you're submitting IOCs from a threat report, improving the dashboard, or adding a new validation source.

### Submit IOCs

The easiest way to contribute is to submit IOCs from public threat reports via Pull Request.

1. Fork this repository
2. Copy `community/TEMPLATE.yaml` to `community/submissions/your-name-YYYY-MM-DD.yaml`
3. Fill in your IOCs and source URL
4. Open a Pull Request

A GitHub Action automatically validates format, rejects private IPs and known-safe domains, and flags duplicates. A maintainer reviews and imports approved IOCs into the live database.

Accepted types: IPv4, IPv6, domains, URLs, emails, CIDRs, CVEs. Defanged notation is fine (`1.2.3[.]4`, `hxxps://`).

### Improve the code

```bash
git clone https://github.com/YOUR_USER/aptwatch.git
cd aptwatch
cp config.ini.example config.ini
python3 apt.py query stats           # Verify setup
```

No external dependencies for core scripts (Python stdlib only). `pyyaml` is needed for community submission validation, `flask` + `gunicorn` for the server API.

Areas where help is most useful:

- **New OSINT sources** — add to `scripts/validate.py`
- **Dashboard features** — `web/index.html` (single-file, vanilla JS + sql.js)
- **Blocklist formats** — add to `scripts/generate_blocklists.py` or `scripts/generate_unified_blocklist.py`
- **External feed sources** — add new feeds to `generate_unified_blocklist.py`
- **DNS resolution** — improve `generate_resolved_blocklist.py` (e.g., add AAAA records, MX lookups)
- **Documentation** — guides, tutorials, integration examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

### Pull Request checklist

- Only modifies files in scope of the change
- Tested locally with `python3 apt.py` commands
- No API keys, server IPs, or secrets in the diff
- Works on Python 3.10+ (Windows and Linux)

---

## Project structure

```
aptwatch/
├── apt.py                              # CLI entry point
├── scripts/
│   ├── validate.py                     # OSINT validation (10 sources)
│   ├── import_data.py                  # Data importer
│   ├── query.py                        # Database queries
│   ├── recon.py                        # Enrichment & candidate discovery
│   ├── export.py                       # Web DB export
│   ├── generate_blocklists.py          # APT-specific blocklist generator (RFC1918-filtered)
│   ├── generate_unified_blocklist.py   # Unified blocklists (aptw-*) — merges with external feeds
│   ├── generate_resolved_blocklist.py  # DNS resolution blocklists (forward + reverse)
│   ├── suricata_generator.py           # Suricata IDS rule generator
│   ├── rss_monitor.py                  # RSS threat intelligence monitor
│   ├── aptwatch_ioc_collector.py       # Automated IOC collector (TrendMicro, OTX, blogs)
│   ├── sync_to_github.sh              # Server → GitHub sync (systemd timer)
│   ├── rebuild.py                      # Full database rebuild
│   └── db_health_check.py             # Database integrity checks
├── database/
│   └── schema_v2.sql                   # Schema definition
├── iocs/                               # IOC text files (auto-synced)
│   ├── ipv4.txt, domains.txt, ...      # Core IOC feeds
│   ├── mining_domains.txt              # 56K+ cryptojacking pool domains
│   └── suricata/                       # IDS rules (.rules files)
├── blocklists/                         # Generated blocklists (auto-synced)
│   ├── aptw-apt-ips-*.netset                # APT-specific IP blocklists
│   ├── aptw-apt-domains*.hosts              # APT-specific domain blocklists
│   ├── aptw-full-*.netset/.hosts        # Unified (APT + external feeds)
│   ├── aptw-resolved-*.netset/.map     # DNS-resolved blocklists
│   ├── aptw-reverse-dns.*              # Reverse DNS blocklists
│   └── aptw-mining.hosts               # Cryptojacking blocklist
├── web/                                # Dashboard (GitHub Pages)
├── community/                          # Community IOC submissions
├── .github/workflows/                  # CI/CD
├── config.ini.example                  # Configuration template
└── requirements.txt                    # Python dependencies
```

---

## Acknowledgments

APT Watch exists because of the OSINT community and the organizations that make threat intelligence freely accessible. This project wouldn't be possible without them.

### Validation & enrichment sources

| Source | Provider | What it gives us |
|--------|----------|-----------------|
| [Shodan InternetDB](https://internetdb.shodan.io/) | Shodan | Open ports, vulnerabilities, hostnames — free, no key, unlimited |
| [AlienVault OTX](https://otx.alienvault.com/) | AT&T Cybersecurity | Pulse-based threat intelligence, community IOCs |
| [AbuseIPDB](https://www.abuseipdb.com/) | Marathon Studios | Crowd-sourced IP abuse reports and confidence scores |
| [VirusTotal](https://www.virustotal.com/) | Google / Chronicle | Multi-engine malware and URL scanning |
| [Censys Search](https://search.censys.io/) | Censys | Internet-wide scanning, certificate and host data |
| [DShield / SANS ISC](https://isc.sans.edu/) | SANS Institute | Attack correlation, IP threat scoring |
| [abuse.ch ThreatFox](https://threatfox.abuse.ch/) | abuse.ch | IOC sharing platform, malware-related indicators |
| [FireHOL IP Lists](https://iplists.firehol.org/) | FireHOL / Costa Tsaousis | Curated, aggregated IP blocklists from 40+ sources |
| [Steven Black Hosts](https://github.com/StevenBlack/hosts) | Steven Black | Unified hosts file with extensions for malware and adware domains |
| [ip-api.com](https://ip-api.com/) | ip-api | Geolocation, ASN, and ISP data for enrichment |
| [RDAP](https://about.rdap.org/) | ARIN / RIPE / APNIC | IP and domain registration data |
| [URLhaus](https://urlhaus.abuse.ch/) | abuse.ch | Active malware distribution URLs and domains |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) | Mitchell Krog | Active phishing domains, community-maintained |
| [CoinBlockerLists](https://zerodot1.gitlab.io/CoinBlockerLists/) | ZeroDot1 | Browser-based cryptominer domains |
| [Netcraft](https://report.netcraft.com/) | Netcraft | Phishing/malware takedown reporting API |

### Threat intelligence & attribution

The attribution and campaign mapping in this project draws on public research from:

Mandiant/Google (APT28, APT29, APT44/Sandworm reports), Microsoft Threat Intelligence (Cadet Blizzard, Midnight Blizzard, Star Blizzard, EvilTokens/Storm-2372), ESET (Gamaredon-Turla collaboration research, Sep 2025), Recorded Future (GRU infrastructure tracking), Check Point Research (Storm-2372 / APT29 overlap), Volexity (device-code phishing campaigns), CISA / FBI / NSA joint advisories, and the broader OSINT community sharing indicators through OTX pulses, ThreatFox submissions, and open threat reports.

### The OSINT community

Special thanks to the analysts, researchers, and hobbyists who share IOCs, write threat reports, and maintain the free tools that make projects like this possible. If you've published APT research, built an OSINT tool, or contributed indicators to any of the platforms above — this project stands on your work.

---

## License

This project is released under the [Unlicense](LICENSE) — it's public domain. You can use, modify, and distribute it without restriction.

All IOCs are sourced from public OSINT feeds and threat reports. Offensive use of this data requires appropriate legal authorization.
