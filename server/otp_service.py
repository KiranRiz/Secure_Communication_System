# server/otp_service.py
# Secure OTP generation, storage, verification, and resend controls

import secrets
from datetime import timedelta

from server.config import Config
from server.db import get_db, utcnow
from server.email_service import send_otp_email
from server.security_utils import hash_token


def _generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def create_and_send_otp(
    email: str,
    purpose: str = "verification",
    username: str | None = None,
) -> dict:
    """
    Create a hashed OTP, enforce resend cooldown, email the code.
    OTP expires after 5 minutes. Max 3 verify attempts.
    """
    db = get_db()
    now = utcnow()
    email = email.lower().strip()

    existing = db.otps.find_one(
        {"email": email, "purpose": purpose, "used": False},
        sort=[("created_at", -1)],
    )
    if existing:
        created = existing["created_at"]
        if created.tzinfo is None:
            from datetime import timezone
            created = created.replace(tzinfo=timezone.utc)
        elapsed = (now - created).total_seconds()
        if elapsed < Config.OTP_RESEND_SECONDS:
            wait = int(Config.OTP_RESEND_SECONDS - elapsed)
            return {
                "success": False,
                "message": f"Please wait {wait}s before requesting a new OTP",
                "retry_after": wait,
            }

    otp = _generate_otp()
    doc = {
        "email": email,
        "username": username,
        "purpose": purpose,
        "otp_hash": hash_token(otp),
        "attempts": 0,
        "max_attempts": Config.OTP_MAX_ATTEMPTS,
        "used": False,
        "created_at": now,
        "expires_at": now + timedelta(seconds=Config.OTP_EXPIRE_SECONDS),
    }
    # Invalidate previous unused OTPs for this email/purpose
    db.otps.update_many(
        {"email": email, "purpose": purpose, "used": False},
        {"$set": {"used": True, "invalidated": True}},
    )
    db.otps.insert_one(doc)

    sent = send_otp_email(email, otp, purpose=purpose)
    if not sent:
        return {"success": False, "message": "Failed to send OTP email"}

    result = {
        "success": True,
        "message": "OTP sent to your email",
        "expires_in": Config.OTP_EXPIRE_SECONDS,
    }
    if Config.EMAIL_DEV_MODE:
        result["dev_otp"] = otp  # visible only in local/dev mode
    return result


def verify_otp(email: str, otp: str, purpose: str = "verification") -> dict:
    db = get_db()
    now = utcnow()
    email = email.lower().strip()

    record = db.otps.find_one(
        {"email": email, "purpose": purpose, "used": False},
        sort=[("created_at", -1)],
    )
    if not record:
        return {"success": False, "message": "No OTP found. Request a new one."}

    expires = record["expires_at"]
    if expires.tzinfo is None:
        from datetime import timezone
        expires = expires.replace(tzinfo=timezone.utc)

    if now > expires:
        db.otps.update_one({"_id": record["_id"]}, {"$set": {"used": True}})
        return {"success": False, "message": "OTP expired. Request a new one."}

    if record.get("attempts", 0) >= record.get("max_attempts", Config.OTP_MAX_ATTEMPTS):
        db.otps.update_one({"_id": record["_id"]}, {"$set": {"used": True}})
        return {"success": False, "message": "Too many attempts. Request a new OTP."}

    if hash_token(otp) != record["otp_hash"]:
        attempts = record.get("attempts", 0) + 1
        db.otps.update_one({"_id": record["_id"]}, {"$set": {"attempts": attempts}})
        remaining = record.get("max_attempts", Config.OTP_MAX_ATTEMPTS) - attempts
        if remaining <= 0:
            db.otps.update_one({"_id": record["_id"]}, {"$set": {"used": True}})
            return {"success": False, "message": "Too many attempts. Request a new OTP."}
        return {
            "success": False,
            "message": f"Invalid OTP. {remaining} attempt(s) remaining",
        }

    # Success — delete / mark used to prevent reuse
    db.otps.delete_one({"_id": record["_id"]})
    return {"success": True, "message": "OTP verified", "username": record.get("username")}
