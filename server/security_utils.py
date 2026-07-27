# server/security_utils.py
# Password hashing, validation, JWT helpers, request auth

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from bson import ObjectId
from flask import g, jsonify, request

from server.config import Config
from server.db import get_db, utcnow


PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{"
    + str(Config.MIN_PASSWORD_LENGTH)
    + r",}$"
)
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def validate_password(password: str) -> str | None:
    if not password or len(password) < Config.MIN_PASSWORD_LENGTH:
        return f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters"
    if not PASSWORD_PATTERN.match(password):
        return (
            "Password must include uppercase, lowercase, and a number"
        )
    return None


def is_valid_email(email: str) -> bool:
    return bool(email and EMAIL_PATTERN.match(email))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(user: dict) -> str:
    now = utcnow()
    payload = {
        "sub": str(user["_id"]),
        "username": user["username"],
        "role": user.get("role", "user"),
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=Config.JWT_ACCESS_EXPIRES_MINUTES),
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")


def create_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "access":
            return None
        return payload
    except jwt.PyJWTError:
        return None


def get_bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return None


def current_user_from_token():
    token = get_bearer_token()
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload:
        return None
    db = get_db()
    try:
        user = db.users.find_one({"_id": ObjectId(payload["sub"])})
    except Exception:
        return None
    if not user or user.get("is_deleted"):
        return None
    return user


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user_from_token()
        if not user:
            return jsonify({"success": False, "message": "Authentication required"}), 401
        g.current_user = user
        return f(*args, **kwargs)

    return wrapper


def client_meta():
    return {
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "user_agent": request.headers.get("User-Agent", ""),
    }


def conversation_id(user_a: str, user_b: str) -> str:
    return "|".join(sorted([user_a.lower(), user_b.lower()]))
