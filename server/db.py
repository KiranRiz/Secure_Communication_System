# server/db.py
# MongoDB Atlas connection and index setup

from datetime import datetime, timezone

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import ConnectionFailure

from server.config import Config

_client = None
_db = None


def get_db():
    """Return the MongoDB database handle (lazy singleton)."""
    global _client, _db
    if _db is not None:
        return _db

    if not Config.MONGODB_URI:
        raise RuntimeError("MONGODB_URI is not set in environment")

    _client = MongoClient(
        Config.MONGODB_URI,
        serverSelectionTimeoutMS=10000,
    )
    _client.admin.command("ping")
    _db = _client[Config.MONGODB_DB]
    ensure_indexes(_db)
    return _db


def ensure_indexes(db):
    """Create indexes for auth, OTP, sessions, messages, and logs."""
    db.users.create_index("username", unique=True)
    db.users.create_index("email", unique=True, sparse=True)

    db.otps.create_index("email")
    db.otps.create_index("expires_at", expireAfterSeconds=0)

    db.sessions.create_index("token_hash", unique=True)
    db.sessions.create_index("user_id")
    db.sessions.create_index("expires_at", expireAfterSeconds=0)

    db.password_resets.create_index("token_hash", unique=True)
    db.password_resets.create_index("expires_at", expireAfterSeconds=0)

    db.messages.create_index([("conversation_id", ASCENDING), ("created_at", ASCENDING)])
    db.messages.create_index("msg_id", unique=True)
    db.messages.create_index([("sender", ASCENDING), ("recipient", ASCENDING)])

    # ReplayGuard: unique msg_id + TTL so entries expire after the window
    db.replay_ids.create_index("msg_id", unique=True)
    db.replay_ids.create_index("expires_at", expireAfterSeconds=0)

    db.security_logs.create_index([("created_at", DESCENDING)])
    db.security_logs.create_index("event_type")
    db.security_logs.create_index("username")
    db.security_logs.create_index("ip")


def utcnow():
    return datetime.now(timezone.utc)


def close_db():
    global _client, _db
    if _client is not None:
        _client.close()
    _client = None
    _db = None
