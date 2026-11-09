"""Environment-based configuration. No secrets live in the code or the repo."""
import os


def load_dotenv(path=".env"):
    """Tiny .env loader (no extra dependency). Real env vars win over the file."""
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def build_config(overrides=None):
    load_dotenv()
    cfg = {
        "PASSWORD_PEPPER": os.environ.get("PASSWORD_PEPPER", ""),
        "DATABASE": os.environ.get("DATABASE", "records.db"),
        "SESSION_TTL_SECONDS": int(os.environ.get("SESSION_TTL_SECONDS", "3600")),
        "MAX_LOGIN_FAILURES": int(os.environ.get("MAX_LOGIN_FAILURES", "5")),
        "LOCKOUT_SECONDS": int(os.environ.get("LOCKOUT_SECONDS", "900")),
        "FAILURE_WINDOW_SECONDS": int(os.environ.get("FAILURE_WINDOW_SECONDS", "900")),
        "MAX_CONTENT_LENGTH": 64 * 1024,  # hard cap on request body size
    }
    cfg.update(overrides or {})
    if len(cfg["PASSWORD_PEPPER"]) < 16:
        raise RuntimeError("PASSWORD_PEPPER must be set (>=16 chars). See .env.example.")
    return cfg
