# server/config.py
# Load configuration from environment variables

import os
from pathlib import Path

from dotenv import load_dotenv

# Always load .env from project root (not depending on shell cwd)
_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env", override=True)


def _bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class Config:
    MONGODB_URI = os.getenv("MONGODB_URI", "")
    MONGODB_DB = os.getenv("MONGODB_DB", "Secure_Communication")

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret")
    JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY)
    JWT_ACCESS_EXPIRES_MINUTES = int(os.getenv("JWT_ACCESS_EXPIRES_MINUTES", "15"))
    JWT_REFRESH_EXPIRES_DAYS = int(os.getenv("JWT_REFRESH_EXPIRES_DAYS", "7"))

    CORS_ORIGINS = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
        if o.strip()
    ]
    CLIENT_URL = os.getenv("CLIENT_URL", "http://localhost:3000")
    SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000")

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "") or os.getenv("SMTP_USER", "")
    EMAIL_DEV_MODE = _bool(os.getenv("EMAIL_DEV_MODE"), True)

    RATE_LIMIT_AUTH = os.getenv("RATE_LIMIT_AUTH", "5 per minute")
    FLASK_DEBUG = _bool(os.getenv("FLASK_DEBUG"), True)
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))

    OTP_EXPIRE_SECONDS = 300
    OTP_RESEND_SECONDS = 60
    OTP_MAX_ATTEMPTS = 3
    PASSWORD_RESET_EXPIRE_MINUTES = 30
    MIN_PASSWORD_LENGTH = 8
