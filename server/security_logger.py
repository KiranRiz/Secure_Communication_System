# server/security_logger.py
# Persist security events to MongoDB

from server.db import get_db, utcnow


def log_security_event(
    event_type: str,
    *,
    username: str | None = None,
    user_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    details: dict | None = None,
):
    try:
        db = get_db()
        db.security_logs.insert_one(
            {
                "event_type": event_type,
                "username": username,
                "user_id": user_id,
                "ip": ip,
                "user_agent": user_agent,
                "details": details or {},
                "created_at": utcnow(),
            }
        )
    except Exception as exc:
        # Never break the main request path because logging failed
        print(f"[security_logger] failed: {exc}")
