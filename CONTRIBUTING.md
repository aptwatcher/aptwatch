# Contributing

Thanks for helping track APT infrastructure. This project accepts community IOC submissions via Pull Requests and welcomes code improvements.

## Submitting IOCs

1. Fork this repository
2. Copy `community/TEMPLATE.yaml` to `community/submissions/your-name-YYYY-MM-DD.yaml`
3. Fill in your IOCs (IPs, domains, URLs, CVEs, etc.)
4. Open a Pull Request

A GitHub Action will automatically validate your submission and comment on the PR with results.

### What happens next

1. **Automated validation** checks format, rejects private IPs and known-safe domains, flags duplicates
2. **Maintainer review** — a human reviews the IOCs and source before approving
3. **Import** — approved IOCs are added to the database and synced to the live feeds

### Rules

Your PR must **only** add files in `community/submissions/`. PRs that modify other files will be rejected automatically.

**Required fields:**
- `author` — your GitHub username
- `source` — URL or name of the threat report

**Accepted IOC types:** IPv4, IPv6, domains, URLs, emails, CIDRs, CVEs

**Auto-rejected:** private/reserved IPs, known-safe domains (google.com etc.), invalid formats.

### Quality guidelines

- Only submit IOCs from credible sources (threat reports, OSINT feeds, your own research)
- Include the source URL so maintainers can verify
- Defanged notation is accepted (`1.2.3[.]4`, `hxxps://`)
- Duplicates are flagged as warnings, not errors

### What NOT to submit

- IOCs from private/classified sources without authorization
- Legitimate infrastructure (CDNs, cloud providers) unless confirmed C2
- Test/sandbox IPs or domains
- Bulk dumps without context or source attribution

---

## Contributing Code

Code improvements, bug fixes, and new features are welcome.

### Setup

```bash
git clone https://github.com/YOUR_USER/apt-intel.git
cd apt-intel
cp config.ini.example config.ini     # Add API keys for testing
python3 apt.py query stats           # Verify setup
```

No external Python dependencies are required for core scripts (stdlib only). `pyyaml` is needed for community submission validation, `flask` + `gunicorn` for the server API.

### Areas for contribution

- New OSINT validation sources (add to `scripts/validate.py`)
- Dashboard improvements (`web/index.html`)
- Blocklist format support (add to `scripts/generate_blocklists.py`)
- Documentation and guides

### Architecture notes

The project is split across GitHub (code + static files) and a private server (database + API). See `docs/INFRASTRUCTURE.md` for the full architecture.

Key points for contributors:

- All scripts use relative paths from `BASE_DIR = Path(__file__).parent.parent`
- Database path: `database/apt_intel.db` (schema in `database/schema_v2.sql`)
- Config is read from `config.ini` (local) or environment variables (GitHub Actions / server)
- The database is never committed to Git — only IOC text files, blocklists, and the lightweight web export
- Scripts must work on both Windows and Linux (Debian 12)

### Pull Request checklist

- [ ] Only modifies files in the scope of the change
- [ ] Tested locally with `python3 apt.py` commands
- [ ] No API keys, server IPs, or secrets in the diff
- [ ] Works on both Python 3.10+ and Debian 12
