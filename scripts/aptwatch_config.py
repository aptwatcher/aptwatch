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
    print(config.paths.submissions)  # Path to community/submissions
    print(config.has_otx)            # True if OTX key configured
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

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

# Search for config.ini
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
        self.scripts = SCRIPT_DIR
        self.safelist = SCRIPT_DIR / "safelist.yaml"

        # Mode-dependent paths
        if mode == "server":
            self.submissions = project_root / "community" / "submissions"
            self.iocs_dir = project_root / "iocs"
            self.suricata_dir = project_root / "iocs" / "suricata"
            self.output = project_root / "collector_output"
        else:
            # Local / GitHub mode
            self.submissions = project_root / "community" / "submissions"
            self.iocs_dir = project_root / "iocs"
            self.suricata_dir = project_root / "iocs" / "suricata"
            self.output = project_root / "collector_output"

    def ensure_dirs(self):
        """Creates output folders if necessary."""
        for d in [self.submissions, self.iocs_dir, self.suricata_dir, self.output]:
            if d:
                d.mkdir(parents=True, exist_ok=True)


class Config:
    """APT Watch configuration loaded from config.ini."""

    def __init__(self):
        self._parser = configparser.ConfigParser()
        self._config_path: Optional[Path] = None
        self.mode: str = "local"

        # API keys (loaded from config.ini or environment variables)
        self.otx_api_key: str = ""

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

        # Behaviors derived from mode
        self.auto_git = (self.mode == "server")

    def _get(self, section: str, key: str, default: str = "") -> str:
        try:
            return self._parser.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
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
    def has_otx(self) -> bool:
        return bool(self.otx_api_key)

    def summary(self) -> str:
        """Configuration summary for logs."""
        keys = []
        if self.otx_api_key: keys.append("OTX")
        return (
            f"Mode: {self.mode} | "
            f"Config: {self._config_path or 'default'} | "
            f"API keys: {', '.join(keys) if keys else 'none'}"
        )


# Singleton — directly importable
config = Config()
