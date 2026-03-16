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
- **Blocklist feeds** in standard formats (FireHOL, StevenBlack, plain text) that update automatically every 6 hours and can be plugged into firewalls, DNS sinkholes, and SIEM tools
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

### Direct download

| Feed | Format | Link |
|------|--------|------|
| High confidence IPs (5+ OSINT sources) | FireHOL .netset | [apt-ips-high.netset](https://aptwatch.org/blocklists/apt-ips-high.netset) |
| Medium confidence IPs (3+ sources) | FireHOL .netset | [apt-ips-medium.netset](https://aptwatch.org/blocklists/apt-ips-medium.netset) |
| All validated IPs | FireHOL .netset | [apt-ips-all.netset](https://aptwatch.org/blocklists/apt-ips-all.netset) |
| High-density subnets | FireHOL .netset | [apt-subnets.netset](https://aptwatch.org/blocklists/apt-subnets.netset) |
| Malicious domains | StevenBlack .hosts | [apt-domains.hosts](https://aptwatch.org/blocklists/apt-domains.hosts) |
| Plain domain list (Pi-hole/DNS) | Text | [apt-domains-plain.txt](https://aptwatch.org/blocklists/apt-domains-plain.txt) |
| Combined IPs + domains | StevenBlack .hosts | [apt-combined.hosts](https://aptwatch.org/blocklists/apt-combined.hosts) |

### Firewall integration

```bash
# iptables/ipset — block high-confidence APT IPs
ipset create apt-high hash:ip
curl -s https://aptwatch.org/blocklists/apt-ips-high.netset | grep -v '^#' | while read ip; do
  ipset add apt-high "$ip"
done
iptables -I INPUT -m set --match-set apt-high src -j DROP
```

### Pi-hole / DNS sinkhole

Add this URL as a blocklist in Pi-hole or AdGuard Home:

```
https://aptwatch.org/blocklists/apt-domains-plain.txt
```

### Scheduled updates

Blocklists update automatically every 6 hours. Set up a cron job to pull fresh data:

```bash
# crontab -e
0 */6 * * * curl -s -o /etc/blocklists/apt-ips-high.netset https://aptwatch.org/blocklists/apt-ips-high.netset
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
- **Blocklist formats** — add to `scripts/generate_blocklists.py`
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
├── apt.py                     # CLI entry point
├── scripts/
│   ├── validate.py            # OSINT validation (10 sources)
│   ├── import_data.py         # Data importer
│   ├── query.py               # Database queries
│   ├── recon.py               # Enrichment & candidate discovery
│   ├── export.py              # Web DB export
│   ├── generate_blocklists.py # Blocklist generator
│   ├── rebuild.py             # Full database rebuild
│   └── db_manager.py          # DB utilities
├── database/
│   └── schema_v2.sql          # Schema definition
├── iocs/                      # IOC text files (auto-synced)
├── blocklists/                # Generated blocklists (auto-synced)
├── web/                       # Dashboard (GitHub Pages)
├── community/                 # Community IOC submissions
├── .github/workflows/         # CI/CD
├── config.ini.example         # Configuration template
└── requirements.txt           # Python dependencies
```

---

## License

This project is released under the [Unlicense](LICENSE) — it's public domain. You can use, modify, and distribute it without restriction.

All IOCs are sourced from public OSINT feeds and threat reports. Offensive use of this data requires appropriate legal authorization.
