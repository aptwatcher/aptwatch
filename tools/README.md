# APT Watch — OSINT lookup tools

Passive host-lookup helpers for collaborators. Query **Shodan** (free InternetDB
or keyed) and **Censys** (Platform v3) for a set of IPs / CIDRs and get a
normalized CSV (+ optional full JSON).

These are *passive*: Shodan and Censys report what they already scanned, so they
reveal hosts that drop ICMP or refuse direct probing (e.g. a Nessus scan that
reports every target "dead"). They're also handy for **historical** checks
(Censys `--at-time`) to see what a block was running weeks ago.

Two equivalent implementations — use whichever fits your platform:

| File | Runtime |
| --- | --- |
| `osint_lookup.py` | Python 3.8+ (stdlib only, cross-platform) |
| `osint_lookup.ps1` | PowerShell 7+ (Windows/macOS/Linux) |

## Keys — never committed

No keys live in this repo. Both tools read credentials at runtime, in this order:

1. **Environment variables** (take priority): `SHODAN_API_KEY`, `CENSYS_API_TOKEN`
2. **An INI config** `[api_keys]` section: `shodan_api_key`, `censys_api_token`
   - search order: `--config`/`-Config` → `$APTWATCH_CONFIG` → `./config.ini`

Copy `config.ini.example` (repo root) to a local `config.ini`, fill in your keys,
and **keep it out of git** (add `config.ini` to `.gitignore`). For STTR/private
operations the keys already live in `apt-intel/config.ini` (private mirror) —
point the tool at it with `--config ../apt-intel/config.ini`.

If your config stores keys base64-encoded, add `--key-encoding base64`
(Python) / `-KeyEncoding base64` (PowerShell). Default is `plain`.

## Providers

| Provider | Auth | Granularity | Notes |
| --- | --- | --- | --- |
| `internetdb` (default) | none | per-IP | Shodan InternetDB, free. ports/CPEs/hostnames/vulns/tags. |
| `shodan` | `shodan_api_key` | per-IP host, or `net:` search for CIDRs | CIDR search needs a Membership plan (credits). |
| `censys` | `censys_api_token` | per-IP (Platform v3) | Supports `--at-time` (RFC3339) historical + `--org-id`. Costs credits. |

`internetdb` and `censys` are per-IP, so CIDRs are expanded to hosts (capped by
`--max-hosts`, default 256). `shodan` sends CIDRs to the `net:` search endpoint.

## Usage

Python:
```bash
# Free, no key — what does Shodan see on these hosts?
python tools/osint_lookup.py 198.51.100.10 198.51.100.20 -p internetdb

# A block from a file, Censys, historical snapshot, write CSV+JSON
python tools/osint_lookup.py -f targets.txt -p censys \
    --at-time 2026-04-01T00:00:00Z --config ../apt-intel/config.ini \
    --out myblock_apr --json

# Shodan keyed CIDR search
python tools/osint_lookup.py 192.0.2.0/24 -p shodan --out myblock

# All providers at once
python tools/osint_lookup.py 8.8.8.8 -p all
```

PowerShell:
```powershell
.\tools\osint_lookup.ps1 -Target 198.51.100.10,198.51.100.20 -Provider internetdb

.\tools\osint_lookup.ps1 -File targets.txt -Provider censys `
    -AtTime 2026-04-01T00:00:00Z -Config ..\apt-intel\config.ini -Out myblock_apr -Json

.\tools\osint_lookup.ps1 -Target 192.0.2.0/24 -Provider shodan -Out myblock
```

`targets.txt` is one IP or CIDR per line; `#` comments and blank lines ignored.

## Output

Normalized CSV columns: `ip, provider, alive, ports, asn, asn_org, country,
hostnames, note`. With `--out PREFIX` it writes `PREFIX.csv`; add `--json` /
`-Json` for `PREFIX.json` (full raw responses, keyed by IP). Without `--out`,
the summary table prints to stdout.

## Caveats

- **Credits**: Shodan keyed + Censys consume API credits/quota; InternetDB is
  free. Keep CIDR-expanded per-IP runs sampled (use `--max-hosts`).
- **Rate limits**: `--delay` (seconds between calls) is intentionally polite;
  raise it if you hit `429`/`403`.
- **`alive=False` ≠ dead host.** It means the provider has no current data — a
  hardened/allowlisted/recently-rotated host looks identical to an empty IP.
  Corroborate with a second provider, Censys `--at-time` history, and live BGP
  before concluding. (See the swissnetwork02 / AS42624 write-up in `reports/`.)
- Attribution discipline (CLAUDE.md) still applies: a lookup result is evidence,
  not an attribution.
