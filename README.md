<p align="center">
  <img src="aptwatch-logo.png" alt="APTWatch" width="160">
</p>

<h1 align="center">APT Intel</h1>

<p align="center">Open-source threat intelligence database tracking Russian APT infrastructure.<br>Aggregates IOCs from OSINT sources, validates them against 10+ APIs, and serves live blocklist feeds.</p>

<p align="center"><strong>Schema:</strong> v2.0 | <strong>Status:</strong> Active</p>

---

## Architecture

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Cloudflare   │────▸│  Origin Server   │     │    GitHub     │
│  DDoS + WAF   │     │  Database + API  │◂───▸│  Code + IOCs  │
└──────────────┘     └─────────────────┘     │  Blocklists   │
                                              │  Dashboard    │
                                              └──────────────┘
```

The project is split across three targets.

| Component | What | Where |
|-----------|------|-------|
| Core database | `apt_intel.db` (400MB+), API server, validation cron | Private server (Debian) |
| DDoS protection | WAF, rate limiting, origin IP masking | Cloudflare (free tier) |
| Public repo | Scripts, IOC files, blocklists, dashboard, CI/CD | GitHub + Pages |

---

## Quick Start

### Local (analysis only)

```bash
git clone https://github.com/aptwatcher/aptwatch.git
cd aptwatch
cp config.ini.example config.ini     # Add your API keys
python3 apt.py                       # Interactive menu
python3 apt.py query stats           # Database statistics
```

### Server deployment

Server deployment scripts and documentation are maintained separately. Contact maintainers for access.

---

## API Endpoints

When deployed, the server exposes these feeds (all read-only):

| Endpoint | Format | Description |
|----------|--------|-------------|
| `/api/blocklist/ips/high` | firehol .netset | High confidence IPs (5+ OSINT sources) |
| `/api/blocklist/ips/medium` | firehol .netset | Medium confidence (3+ sources) |
| `/api/blocklist/ips` | firehol .netset | All validated IPs |
| `/api/blocklist/subnets` | firehol .netset | High-density /24 subnets |
| `/api/blocklist/domains` | StevenBlack .hosts | Malicious domains |
| `/api/blocklist/combined` | StevenBlack .hosts | IPs + domains combined |
| `/api/feed/json` | JSON | Latest IOCs with metadata |
| `/api/ioc/<ip>` | JSON | Full profile for single IP |
| `/api/search?q=<pattern>` | JSON | Search across IOCs |
| `/api/stats` | JSON | Database statistics |

Static blocklist files are also available under `/static/blocklists/` and via GitHub Pages.

---

## CLI

All operations go through `apt.py`:

```bash
python3 apt.py                       # Interactive menu
python3 apt.py --help                # All commands

# Core commands
python3 apt.py rebuild               # Full DB rebuild from source files
python3 apt.py import iocs           # Re-import IOC files
python3 apt.py import vulnscan scan.csv    # Import vulnerability scan
python3 apt.py query stats           # Full statistics
python3 apt.py query ip 1.2.3.4      # Full IP profile
python3 apt.py query critical        # Top critical IPs

# Recon & enrichment
python3 apt.py recon enrich-top 100  # Enrich via ip-api.com + RDAP
python3 apt.py recon detect-staging  # Find staging/relay servers
python3 apt.py recon find-candidates # Discover new candidates

# OSINT validation (10 sources)
python3 apt.py validate auto         # Scheduled run (respects daily limits)
python3 apt.py validate run all 100  # All sources, 100 IPs each
python3 apt.py validate check 1.2.3.4
python3 apt.py validate status       # Coverage stats

# Export & blocklists
python3 apt.py export                # Web DB for dashboard
python3 scripts/generate_blocklists.py
```

---

## Validation Sources

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

## Automation

### Server (systemd timers)
- Validation runs every 6 hours
- Blocklists regenerated after each validation
- Updated IOCs/blocklists auto-pushed to GitHub

### GitHub Actions
- `validate.yml` — Scheduled OSINT validation (every 6h)
- `blocklists.yml` — Regenerate blocklists on IOC changes
- `pages-deploy.yml` — Deploy dashboard to GitHub Pages
- `validate-pr.yml` — Validate community IOC submissions

### Local (Windows/Linux)
- `tasks/linux/validate_continuous.sh` — Continuous validation loop
- `tasks/linux/import_incremental.sh` — Watch for new scan files
- `tasks/run.bat` / `tasks/linux/run.sh` — Quick launcher

---

## Project Structure

```
aptwatch/
├── apt.py                              # CLI entry point
├── scripts/                            # Core Python modules
│   ├── validate.py                     # OSINT validation (10 sources)
│   ├── import_data.py                  # Data importer
│   ├── query.py                        # Database queries
│   ├── recon.py                        # Enrichment & discovery
│   ├── rebuild.py                      # Database rebuild
│   ├── export.py                       # Web DB export
│   ├── generate_blocklists.py          # Blocklist generator
│   └── db_manager.py                   # DB utilities
├── .github/workflows/                  # CI/CD
├── database/schema_v2.sql              # Schema definition
├── iocs/                               # IOC text files
├── blocklists/                         # Generated blocklists
├── community/                          # Community IOC submissions
├── web/                                # GitHub Pages dashboard
├── config.ini.example                  # Config template
└── requirements.txt                    # Python dependencies
```

---

## Community Contributions

Submit IOCs via Pull Request. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Contributors add a YAML file to `community/submissions/`. A GitHub Action validates format and checks for duplicates. Maintainers review and import approved IOCs.

---

## Legal

All IOCs are sourced from public OSINT feeds and reports. Offensive use requires appropriate authorization.
