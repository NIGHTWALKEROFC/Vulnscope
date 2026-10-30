import copy
import json
import os
from pathlib import Path

DEFAULTS = {
    "http": {
        "timeout": 15,
        "max_response_bytes": 2_000_000,
        "rate_limit_per_sec": 8.0,
        "retries": 2,
        "max_redirects": 5,
        "user_agent": "VulnScope/{version} (+authorized-security-assessment)",
        "verify_tls": True,
    },
    "scan": {
        "concurrency": 4,
        "max_pages": 40,
        "max_depth": 2,
        "max_params_tested": 25,
        "max_cves_per_product": 20,
        "plugin_timeout_scale": 1.0,
        "port_timeout": 2.0,
        "port_concurrency": 100,
        "max_hosts": 256,
        "require_ack": True,
    },
    "intel": {
        "nvd_api_key": "",
        "osv_cache_ttl_hours": 24,
        "offline": False,
        "stale_after_days": 14,
    },
    "limits": {
        "max_upload_mb": 200,
        "max_archive_uncompressed_mb": 800,
        "max_archive_files": 50000,
        "max_scan_file_kb": 1024,
    },
    "plugins": {"disabled": []},
    "lite": {
        "concurrency": 2,
        "max_pages": 10,
        "port_concurrency": 30,
        "rate_limit_per_sec": 3.0,
    },
}


def home_dir():
    env = os.environ.get("VULNSCOPE_HOME")
    base = Path(env) if env else Path.home() / ".vulnscope"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _merge(base, extra):
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


class Config:
    def __init__(self, data=None, home=None):
        self.home = Path(home) if home else home_dir()
        self.data = copy.deepcopy(DEFAULTS)
        if data:
            _merge(self.data, data)
        key = os.environ.get("NVD_API_KEY")
        if key:
            self.data["intel"]["nvd_api_key"] = key

    @property
    def path(self):
        return self.home / "config.json"

    @classmethod
    def load(cls, home=None):
        home_path = Path(home) if home else home_dir()
        home_path.mkdir(parents=True, exist_ok=True)
        cfg_path = home_path / "config.json"
        data = {}
        if cfg_path.is_file():
            with open(cfg_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        return cls(data, home_path)

    def save(self):
        self.home.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2)

    def get(self, section, key, default=None):
        return self.data.get(section, {}).get(key, default)

    def apply_lite(self):
        lite = self.data["lite"]
        self.data["scan"]["concurrency"] = lite["concurrency"]
        self.data["scan"]["max_pages"] = lite["max_pages"]
        self.data["scan"]["port_concurrency"] = lite["port_concurrency"]
        self.data["http"]["rate_limit_per_sec"] = lite["rate_limit_per_sec"]

    @property
    def db_path(self):
        return self.home / "vulnscope.db"

    @property
    def intel_path(self):
        return self.home / "intel.db"

    @property
    def reports_dir(self):
        path = self.home / "reports"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def uploads_dir(self):
        path = self.home / "uploads"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def logs_dir(self):
        path = self.home / "logs"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def tmp_dir(self):
        path = self.home / "tmp"
        path.mkdir(parents=True, exist_ok=True)
        return path
