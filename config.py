# app/config.py
# Safe configuration wrapper for MiniHack Router.
# This file DOES NOT change behavior unless you import and use it.
# To adopt gradually, see the integration notes below.

from __future__ import annotations
import os
from typing import Optional
import secrets

def _get_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in {"1","true","yes","on"}

class BaseConfig:
    # Keep defaults conservative. You can override via env vars.
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
    DEBUG = _get_bool("FLASK_DEBUG", False)
    TESTING = _get_bool("FLASK_TESTING", False)

    # Network / server
    SERVER_NAME = os.getenv("FLASK_SERVER_NAME")  # e.g. "example.com"
    PREFERRED_URL_SCHEME = os.getenv("FLASK_URL_SCHEME", "https")
    PORT = int(os.getenv("FLASK_RUN_PORT", "5000"))

    # Security headers (opt-in mild defaults)
    SESSION_COOKIE_SECURE = _get_bool("SESSION_COOKIE_SECURE", True)
    SESSION_COOKIE_HTTPONLY = _get_bool("SESSION_COOKIE_HTTPONLY", True)
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")

    # CORS (comma-separated origins). Empty => deny all cross-origin by default
    CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS","").split(",") if o.strip()]

    # Rate limiting (only if you enable Flask-Limiter in your app)
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "60/minute")  # example
    RATELIMIT_STORAGE_URL = os.getenv("RATELIMIT_STORAGE_URL", "memory://")

    # Database (use if you migrate to SQLAlchemy/another DB)
    DATABASE_URL = os.getenv("DATABASE_URL")  # e.g. sqlite:///instance/app.db

    # Suricata paths (only used by helper modules if you wire them)
    SURICATA_EVE_PATH = os.getenv("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
    SURICATA_FASTLOG_PATH = os.getenv("SURICATA_FASTLOG_PATH", "/var/log/suricata/fast.log")

class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # dev friendliness
    PREFERRED_URL_SCHEME = "http"

class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False
    # Enforce a real secret in prod
    if os.getenv("FLASK_ENV","production").lower() == "production":
        if BaseConfig.SECRET_KEY == "CHANGE_ME_IN_PROD":
            raise RuntimeError("FLASK_SECRET_KEY is required in production.")

# Optional easy switcher
def get_config(env: Optional[str] = None):
    env = (env or os.getenv("FLASK_ENV","production")).lower()
    if env in ("dev","development"):
        return DevelopmentConfig
    if env in ("test","testing"):
        return BaseConfig  # keep simple
    return ProductionConfig

