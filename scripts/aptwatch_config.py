#!/usr/bin/env python3
"""
APT Watch — Shared Configuration
====================================
Central configuration module for all APT Watch scripts.
Loads config.ini, determines mode (local/server/github) and
exposes paths, API keys and adapted behaviors.

Usage:
    from aptwatch_config import config
    print(config.mode)               # "local", "server", "github"
    print(config.otx_api_key)        # key or ""
    print(config.paths.submissions)  # Path to community/submissions
    print(config.can_write_db)       # True in server mode
    print(config.auto_git)           # True if git auto enabled
"""

import os
import configparser
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("aptwatch.config")

# ═══════════════════════════════════════════════════════════════
#  PATH RESOLUTION
# ═══════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(__file__).resolve().parent           # scripts/
# SERVER_DIR removed — scripts now at project_root/scripts/
PROJECT_ROOT = SCRIPT_DIR.parent                       # apt-intel/

# Search for config.ini: first at project root, then fallback
CONFIG_CANDIDATES = [
    PROJECT_ROOT / "config.ini",
    SCRIPT_DIR / "config.ini",
    Path.home() / ".aptwatch" / "config.ini",
]


class Paths:
    """Resolved paths according to execution mode."""

    def __init__(self, mode: str, project_root: Path):
        self.project_root = project_root
        self.mode = mode

        # Common paths
        self.repo = project_root / "repo"
        self.database_dir = project_root / "database"
        self.scripts = SCRIPT_DIR
        self.safelist = SCRIPT_DIR / "safelist.yaml"

        # Mode-dependent paths
        if mode == "server":
            self.db_file = self.database_dir / "apt_intel.db"
            self.submissions = self.repo / "community" / "submissions"
            self.iocs_dir = self.repo / "iocs"
            self.suricata_dir = self.repo / "iocs" / "suricata"
            self.sql_dir = self.database_dir
            self.output = project_root / "collector_output"
        else:
            # Local mode: output in a dedicated folder
            self.db_file = None  # no DB access in local mode
            self.submissions = self.repo / "community" / "submissions"
            self.iocs_dir = self.repo / "iocs"
            self.suricata_dir = self.repo / "iocs" / "suricata"
            self.sql_dir = self.database_dir
            self.output = project_root / "collector_output"

    def ensure_dirs(self):
        """Creates output folders if necessary."""
        for d in [self.submissions, self.iocs_dir, self.suricata_dir,
                  self.sql_dir, self.output]:
            if d:
                d.mkdir(parents=True, exist_ok=True)


class Config:
    """APT Watch configuration loaded from config.ini."""

    def __init__(self):
        self._parser = configparser.ConfigParser()
        self._config_path: Optional[Path] = None
        self.mode: str = "local"

        # API keys
        self.otx_api_key: str = ""
        self.abuseipdb_key: str = ""
        self.virustotal_key: str = ""
        self.censys_api_token: str = ""
        self.greynoise_key: str = ""

        # Validation settings
        self.validated_threshold: int = 3
        self.runs_per_day: int = 4

        # Server settings
        self.auto_git: bool = False
        self.auto_import_db: bool = False
        self.deploy_key_path: str = ""
        self.github_repo: str = ""
        self.github_branch: str = "main"

        # Load
        self._load()
        self.paths = Paths(self.mode, PROJECT_ROOT)

    def _load(self):
        """Loads config.ini from the first file found."""
        for candidate in CONFIG_CANDIDATES:
            if candidate.exists():
                self._config_path = candidate
                self._parser.read(str(candidate), encoding="utf-8")
                log.info(f"Config loaded: {candidate}")
                break

        if not self._config_path:
            log.warning("No config.ini found — local mode by default")

        # Mode
        self.mode = self._get("general", "mode", "local").lower().strip()
        if self.mode not in ("local", "server", "github"):
            log.warning(f"Unknown mode '{self.mode}' — fallback to local")
            self.mode = "local"

        # API keys: config.ini then env vars (env override)
        self.otx_api_key = self._get_key("api_keys", "otx_api_key", "OTX_API_KEY")
        self.abuseipdb_key = self._get_key("api_keys", "abuseipdb_key", "ABUSEIPDB_KEY")
        self.virustotal_key = self._get_key("api_keys", "virustotal_key", "VIRUSTOTAL_KEY")
        self.censys_api_token = self._get_key("api_keys", "censys_api_token", "CENSYS_API_TOKEN")
        self.greynoise_key = self._get_key("api_keys", "greynoise_key", "GREYNOISE_KEY")

        # Validation
        self.validated_threshold = self._get_int("validation", "validated_threshold", 3)
        self.runs_per_day = self._get_int("validation", "runs_per_day", 4)

        # Server
        self.deploy_key_path = self._get("server", "deploy_key_path", "")
        self.github_repo = self._get("server", "github_repo", "")
        self.github_branch = self._get("server", "github_branch", "main")

        # Behaviors derived from mode
        self.auto_git = (self.mode == "server")
        self.auto_import_db = (self.mode == "server")

    def _get(self, section: str, key: str, default: str = "") -> str:
        try:
            return self._parser.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def _get_int(self, section: str, key: str, default: int = 0) -> int:
        try:
            return self._parser.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return default

    def _get_key(self, section: str, ini_key: str, env_key: str) -> str:
        """Loads an API key: env var override > config.ini."""
        env_val = os.environ.get(env_key, "").strip()
        if env_val:
            return env_val
        return self._get(section, ini_key, "").strip()

    # ═══════════════════════════════════════════════════════
    #  CONVENIENCE PROPERTIES
    # ═══════════════════════════════════════════════════════

    @property
    def is_server(self) -> bool:
        return self.mode == "server"

    @property
    def is_local(self) -> bool:
        return self.mode == "local"

    @property
    def is_github(self) -> bool:
        return self.mode == "github"

    @property
    def can_write_db(self) -> bool:
        """True if the mode allows direct DB writes."""
        return self.is_server and self.paths.db_file and self.paths.db_file.exists()

    @property
    def can_validate(self) -> bool:
        """True if at least one validation API key is available."""
        return bool(self.otx_api_key or self.abuseipdb_key or
                    self.virustotal_key or self.greynoise_key)

    @property
    def has_otx(self) -> bool:
        return bool(self.otx_api_key)

    def summary(self) -> str:
        """Configuration summary for logs."""
        keys = []
        if self.otx_api_key: keys.append("OTX")
        if self.abuseipdb_key: keys.append("AbuseIPDB")
        if self.virustotal_key: keys.append("VirusTotal")
        if self.censys_api_token: keys.append("Censys")
        if self.greynoise_key: keys.append("GreyNoise")

        return (
            f"Mode: {self.mode} | "
            f"Config: {self._config_path or 'default'} | "
            f"API keys: {', '.join(keys) if keys else 'none'} | "
            f"DB write: {self.can_write_db} | "
            f"Auto-git: {self.auto_git}"
        )


# Singleton — directly importable
config = Config()
