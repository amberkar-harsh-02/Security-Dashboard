import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent

DEFAULT_INGEST_KEY = "dev-ingest-key"


def _bool(value):
    return str(value).lower() in ("1", "true", "yes", "on")


class Config:
    """Settings read from environment variables, with defaults for local development."""

    def __init__(self, **overrides):
        self.DB_PATH = os.environ.get("SIEM_DB_PATH", str(BACKEND_DIR / "data" / "siem.db"))
        self.HOST = os.environ.get("SIEM_HOST", "127.0.0.1")
        self.PORT = int(os.environ.get("SIEM_PORT", "5000"))
        self.DEBUG = _bool(os.environ.get("SIEM_DEBUG", "false"))
        self.CORS_ORIGINS = [
            origin.strip()
            for origin in os.environ.get(
                "SIEM_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
            ).split(",")
            if origin.strip()
        ]
        self.RETENTION_DAYS = int(os.environ.get("SIEM_RETENTION_DAYS", "7"))
        self.INGEST_API_KEY = os.environ.get("SIEM_INGEST_KEY", DEFAULT_INGEST_KEY)
        self.MAX_BATCH_SIZE = int(os.environ.get("SIEM_MAX_BATCH_SIZE", "1000"))
        self.MAX_CONTENT_LENGTH = 5 * 1024 * 1024

        # Analyst login. Without SIEM_SECRET_KEY a random key is generated and kept next to the database.
        self.SECRET_KEY = os.environ.get("SIEM_SECRET_KEY")
        self.ADMIN_USER = os.environ.get("SIEM_ADMIN_USER", "admin")
        self.ADMIN_PASSWORD = os.environ.get("SIEM_ADMIN_PASSWORD")
        self.SESSION_HOURS = float(os.environ.get("SIEM_SESSION_HOURS", "12"))
        self.COOKIE_SECURE = _bool(os.environ.get("SIEM_COOKIE_SECURE", "false"))
        # Behind a reverse proxy at a sub-path (e.g. Caddy at /siem), limit the cookie to that path.
        self.COOKIE_PATH = os.environ.get("SIEM_COOKIE_PATH", "/")
        # Trust X-Forwarded-For/-Proto from one proxy in front (Caddy). Only turn on behind a proxy.
        self.TRUST_PROXY = _bool(os.environ.get("SIEM_TRUST_PROXY", "false"))

        # Blocking: the file the server firewall sync follows (unset: record blocks without enforcing),
        # and extra never-block ranges (comma-separated CIDRs).
        self.BLOCKLIST_FILE = os.environ.get("SIEM_BLOCKLIST_FILE", "")
        self.BLOCK_ALLOWLIST = os.environ.get("SIEM_BLOCK_ALLOWLIST", "")

        # Performance page: seconds between samples of CPU, memory, disk and network.
        self.PERF_INTERVAL = float(os.environ.get("SIEM_PERF_INTERVAL", "2"))

        # Live updates: how often the stream checks for changes, and when it hands the client a reconnect.
        self.STREAM_POLL_SECONDS = float(os.environ.get("SIEM_STREAM_POLL_SECONDS", "2"))
        self.STREAM_MAX_SECONDS = float(os.environ.get("SIEM_STREAM_MAX_SECONDS", "300"))

        # Built dashboard served by Flask (run `npm run build` in frontend/).
        self.FRONTEND_DIST = os.environ.get("SIEM_FRONTEND_DIST", str(BACKEND_DIR.parent / "frontend" / "dist"))

        self.RULES_DIR = os.environ.get("SIEM_RULES_DIR", str(BACKEND_DIR / "rules"))
        self.INTEL_DIR = os.environ.get("SIEM_INTEL_DIR", str(BACKEND_DIR / "intel"))

        # Collectors. Set SIEM_SYSLOG_PORT=0 to turn the syslog listener off.
        self.SYSLOG_HOST = os.environ.get("SIEM_SYSLOG_HOST", "127.0.0.1")
        self.SYSLOG_PORT = int(os.environ.get("SIEM_SYSLOG_PORT", "5514"))
        self.HOST_AGENT_ENABLED = _bool(os.environ.get("SIEM_HOST_AGENT", "true"))
        self.HOST_AGENT_INTERVAL = float(os.environ.get("SIEM_HOST_AGENT_INTERVAL", "10"))

        # Demo data: attack scenarios on request, plus continuous background activity.
        self.SIMULATOR_ENABLED = _bool(os.environ.get("SIEM_SIMULATOR", "true"))
        self.NOISE_RATE = float(os.environ.get("SIEM_NOISE_RATE", "0.5"))  # events per second, 0 = off

        # Background jobs (retention, collectors, noise) are disabled in tests.
        self.START_BACKGROUND_JOBS = True

        for key, value in overrides.items():
            setattr(self, key, value)
