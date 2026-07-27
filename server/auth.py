# server/auth.py
# Author: Hamza + Kiran (extended)
# Purpose: User authentication with MongoDB Atlas, bcrypt, JWT sessions

import re
from datetime import timedelta

from bson import ObjectId

from server.config import Config
from server.db import get_db, utcnow
from server.email_service import send_password_reset_email
from server.otp_service import create_and_send_otp, verify_otp
from server.security_logger import log_security_event
from server.security_utils import (
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_token,
    is_valid_email,
    validate_password,
    verify_password,
)


class AuthManager:
    """
    MongoDB-backed authentication.
    Passwords hashed with bcrypt. Sessions use JWT + refresh tokens.
    Email OTP supports registration verification and password recovery.
    """

    def register(self, username: str, password: str, email: str,
                 meta: dict | None = None) -> dict:
        db = get_db()
        username = (username or "").strip()
        email = (email or "").strip().lower()
        meta = meta or {}

        if not username or len(username) < 3:
            return {"success": False, "message": "Username must be at least 3 characters"}
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            return {"success": False, "message": "Username may only contain letters, numbers, underscore"}
        if not is_valid_email(email):
            return {"success": False, "message": "Valid email is required"}

        pwd_err = validate_password(password)
        if pwd_err:
            return {"success": False, "message": pwd_err}

        if db.users.find_one({"username": username}):
            return {"success": False, "message": "Username already exists"}
        if db.users.find_one({"email": email}):
            return {"success": False, "message": "Email already registered"}

        now = utcnow()
        user_doc = {
            "username": username,
            "email": email,
            "password_hash": hash_password(password),
            "public_key": None,
            "role": "user",
            "email_verified": False,
            "profile": {
                "display_name": username,
                "bio": "",
                "avatar_url": "",
            },
            "is_deleted": False,
            "created_at": now,
            "updated_at": now,
            "last_login_at": None,
        }
        result = db.users.insert_one(user_doc)

        otp_result = create_and_send_otp(email, purpose="verification", username=username)
        log_security_event(
            "register",
            username=username,
            user_id=str(result.inserted_id),
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
        )

        response = {
            "success": True,
            "message": "Registered successfully. Verify the OTP sent to your email.",
            "requires_otp": True,
            "email": email,
            "username": username,
        }
        if otp_result.get("dev_otp"):
            response["dev_otp"] = otp_result["dev_otp"]
        if not otp_result.get("success"):
            response["message"] = (
                "Registered, but OTP email failed. Use resend OTP."
            )
        return response

    def verify_registration_otp(self, email: str, otp: str, meta: dict | None = None) -> dict:
        meta = meta or {}
        email = (email or "").strip().lower()
        result = verify_otp(email, otp, purpose="verification")
        log_security_event(
            "otp_verify",
            username=None,
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
            details={"email": email, "success": result.get("success")},
        )
        if not result.get("success"):
            return result

        db = get_db()
        user = db.users.find_one({"email": email})
        if not user:
            return {"success": False, "message": "User not found"}

        db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"email_verified": True, "updated_at": utcnow()}},
        )
        return {
            "success": True,
            "message": "Email verified. You can now log in.",
            "username": user["username"],
        }

    def resend_otp(self, email: str, purpose: str = "verification",
                   meta: dict | None = None) -> dict:
        meta = meta or {}
        email = (email or "").strip().lower()
        db = get_db()
        user = db.users.find_one({"email": email})
        username = user["username"] if user else None
        result = create_and_send_otp(email, purpose=purpose, username=username)
        log_security_event(
            "otp_request",
            username=username,
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
            details={"email": email, "purpose": purpose, "success": result.get("success")},
        )
        return result

    def login(self, username: str, password: str, meta: dict | None = None) -> dict:
        db = get_db()
        meta = meta or {}
        username = (username or "").strip()

        user = db.users.find_one({"username": username, "is_deleted": {"$ne": True}})
        if not user:
            log_security_event(
                "login_failed",
                username=username,
                ip=meta.get("ip"),
                user_agent=meta.get("user_agent"),
                details={"reason": "user_not_found"},
            )
            return {"success": False, "message": "Invalid username or password"}

        if not verify_password(password, user["password_hash"]):
            log_security_event(
                "login_failed",
                username=username,
                user_id=str(user["_id"]),
                ip=meta.get("ip"),
                user_agent=meta.get("user_agent"),
                details={"reason": "bad_password"},
            )
            return {"success": False, "message": "Invalid username or password"}

        if not user.get("email_verified"):
            return {
                "success": False,
                "message": "Email not verified. Complete registration OTP first.",
                "requires_otp": True,
                "otp_purpose": "verification",
                "email": user.get("email"),
            }

        # Password OK — send login OTP; tokens issued only after OTP confirm
        otp_result = create_and_send_otp(
            user["email"],
            purpose="login",
            username=user["username"],
        )
        log_security_event(
            "login_otp_sent",
            username=username,
            user_id=str(user["_id"]),
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
            details={"email": user.get("email"), "otp_sent": otp_result.get("success")},
        )

        if not otp_result.get("success"):
            return {
                "success": False,
                "message": otp_result.get("message", "Could not send login OTP"),
                "retry_after": otp_result.get("retry_after"),
            }

        response = {
            "success": True,
            "requires_otp": True,
            "otp_purpose": "login",
            "message": "Password correct. Enter the OTP sent to your email to finish login.",
            "email": user.get("email"),
            "username": user["username"],
        }
        if otp_result.get("dev_otp"):
            response["dev_otp"] = otp_result["dev_otp"]
        return response

    def verify_login_otp(self, email: str, otp: str, meta: dict | None = None) -> dict:
        """Complete login after password step by verifying email OTP."""
        meta = meta or {}
        email = (email or "").strip().lower()
        result = verify_otp(email, otp, purpose="login")
        log_security_event(
            "login_otp_verify",
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
            details={"email": email, "success": result.get("success")},
        )
        if not result.get("success"):
            return result

        db = get_db()
        user = db.users.find_one({"email": email, "is_deleted": {"$ne": True}})
        if not user:
            return {"success": False, "message": "User not found"}

        tokens = self._issue_tokens(user, meta)
        db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login_at": utcnow()}},
        )
        log_security_event(
            "login",
            username=user["username"],
            user_id=str(user["_id"]),
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
        )
        return {
            "success": True,
            "message": "Login successful",
            "username": user["username"],
            "email": user.get("email"),
            "has_email": bool(user.get("email")),
            "role": user.get("role", "user"),
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": "Bearer",
            "expires_in": Config.JWT_ACCESS_EXPIRES_MINUTES * 60,
        }

    def _issue_tokens(self, user: dict, meta: dict) -> dict:
        db = get_db()
        access = create_access_token(user)
        refresh = create_refresh_token()
        now = utcnow()
        db.sessions.insert_one(
            {
                "user_id": str(user["_id"]),
                "username": user["username"],
                "token_hash": hash_token(refresh),
                "created_at": now,
                "expires_at": now + timedelta(days=Config.JWT_REFRESH_EXPIRES_DAYS),
                "revoked": False,
                "rotated_from": None,
                "ip": meta.get("ip"),
                "user_agent": meta.get("user_agent"),
            }
        )
        return {"access_token": access, "refresh_token": refresh}

    def refresh(self, refresh_token: str, meta: dict | None = None) -> dict:
        db = get_db()
        meta = meta or {}
        if not refresh_token:
            return {"success": False, "message": "Refresh token required"}

        token_hash = hash_token(refresh_token)
        session = db.sessions.find_one({"token_hash": token_hash, "revoked": False})
        if not session:
            return {"success": False, "message": "Invalid refresh token"}

        expires = session["expires_at"]
        if expires.tzinfo is None:
            from datetime import timezone
            expires = expires.replace(tzinfo=timezone.utc)
        if utcnow() > expires:
            db.sessions.update_one({"_id": session["_id"]}, {"$set": {"revoked": True}})
            return {"success": False, "message": "Refresh token expired"}

        user = db.users.find_one({"_id": ObjectId(session["user_id"]), "is_deleted": {"$ne": True}})
        if not user:
            return {"success": False, "message": "User not found"}

        # Rotate refresh token
        db.sessions.update_one({"_id": session["_id"]}, {"$set": {"revoked": True}})
        tokens = self._issue_tokens(user, meta)
        db.sessions.update_one(
            {"token_hash": hash_token(tokens["refresh_token"])},
            {"$set": {"rotated_from": str(session["_id"])}},
        )
        return {
            "success": True,
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": "Bearer",
            "expires_in": Config.JWT_ACCESS_EXPIRES_MINUTES * 60,
        }

    def logout(self, refresh_token: str | None, user: dict | None,
               meta: dict | None = None) -> dict:
        db = get_db()
        meta = meta or {}
        if refresh_token:
            db.sessions.update_one(
                {"token_hash": hash_token(refresh_token)},
                {"$set": {"revoked": True}},
            )
        if user:
            log_security_event(
                "logout",
                username=user.get("username"),
                user_id=str(user.get("_id")),
                ip=meta.get("ip"),
                user_agent=meta.get("user_agent"),
            )
        return {"success": True, "message": "Logged out"}

    def logout_all(self, user: dict, meta: dict | None = None) -> dict:
        db = get_db()
        meta = meta or {}
        db.sessions.update_many(
            {"user_id": str(user["_id"]), "revoked": False},
            {"$set": {"revoked": True}},
        )
        log_security_event(
            "logout_all",
            username=user.get("username"),
            user_id=str(user["_id"]),
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
        )
        return {"success": True, "message": "All sessions revoked"}

    def store_public_key(self, username: str, public_key: str) -> bool:
        db = get_db()
        result = db.users.update_one(
            {"username": username, "is_deleted": {"$ne": True}},
            {"$set": {"public_key": public_key, "updated_at": utcnow()}},
        )
        return result.matched_count > 0

    def get_public_key(self, username: str) -> str | None:
        db = get_db()
        user = db.users.find_one(
            {"username": username, "is_deleted": {"$ne": True}},
            {"public_key": 1},
        )
        if user:
            return user.get("public_key")
        return None

    def lookup_user(self, username: str) -> dict | None:
        """Return basic public info if the account exists."""
        db = get_db()
        username = (username or "").strip()
        if not username:
            return None
        user = db.users.find_one(
            {"username": username, "is_deleted": {"$ne": True}},
            {"username": 1, "profile": 1, "public_key": 1},
        )
        if not user:
            return None
        profile = user.get("profile") or {}
        return {
            "username": user["username"],
            "display_name": profile.get("display_name") or user["username"],
            "avatar_url": profile.get("avatar_url") or "",
            "has_public_key": bool(user.get("public_key")),
        }

    def get_profile(self, username: str) -> dict | None:
        db = get_db()
        user = db.users.find_one(
            {"username": username, "is_deleted": {"$ne": True}},
            {"password_hash": 0},
        )
        if not user:
            return None
        return {
            "username": user["username"],
            "email": user.get("email"),
            "email_verified": user.get("email_verified", False),
            "role": user.get("role", "user"),
            "profile": user.get("profile", {}),
            "created_at": user.get("created_at"),
            "last_login_at": user.get("last_login_at"),
            "has_public_key": bool(user.get("public_key")),
        }

    def update_profile(self, user: dict, data: dict) -> dict:
        db = get_db()
        profile = user.get("profile") or {}
        if "display_name" in data:
            profile["display_name"] = str(data["display_name"])[:80]
        if "bio" in data:
            profile["bio"] = str(data["bio"])[:280]
        if "avatar_url" in data:
            profile["avatar_url"] = str(data["avatar_url"])[:500]

        db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"profile": profile, "updated_at": utcnow()}},
        )
        return {"success": True, "message": "Profile updated", "profile": profile}

    def change_password(self, user: dict, current_password: str,
                        new_password: str, meta: dict | None = None) -> dict:
        meta = meta or {}
        if not verify_password(current_password, user["password_hash"]):
            return {"success": False, "message": "Current password is incorrect"}
        pwd_err = validate_password(new_password)
        if pwd_err:
            return {"success": False, "message": pwd_err}

        db = get_db()
        db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"password_hash": hash_password(new_password), "updated_at": utcnow()}},
        )
        # Revoke other sessions
        db.sessions.update_many(
            {"user_id": str(user["_id"]), "revoked": False},
            {"$set": {"revoked": True}},
        )
        log_security_event(
            "password_change",
            username=user["username"],
            user_id=str(user["_id"]),
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
        )
        return {"success": True, "message": "Password changed. Please log in again."}

    def request_password_reset(self, email: str, meta: dict | None = None) -> dict:
        db = get_db()
        meta = meta or {}
        email = (email or "").strip().lower()
        # Always return success message to avoid email enumeration
        generic = {
            "success": True,
            "message": "If that email exists, a reset link has been sent.",
        }
        user = db.users.find_one({"email": email, "is_deleted": {"$ne": True}})
        log_security_event(
            "password_reset_request",
            username=user["username"] if user else None,
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
            details={"email": email, "found": bool(user)},
        )
        if not user:
            return generic

        import secrets
        token = secrets.token_urlsafe(32)
        now = utcnow()
        db.password_resets.insert_one(
            {
                "user_id": str(user["_id"]),
                "email": email,
                "token_hash": hash_token(token),
                "used": False,
                "created_at": now,
                "expires_at": now + timedelta(minutes=Config.PASSWORD_RESET_EXPIRE_MINUTES),
            }
        )
        link = f"{Config.CLIENT_URL}/reset-password?token={token}"
        send_password_reset_email(email, link)
        if Config.EMAIL_DEV_MODE:
            generic["dev_reset_token"] = token
            generic["dev_reset_link"] = link
        return generic

    def reset_password(self, token: str, new_password: str,
                       meta: dict | None = None) -> dict:
        db = get_db()
        meta = meta or {}
        pwd_err = validate_password(new_password)
        if pwd_err:
            return {"success": False, "message": pwd_err}
        if not token:
            return {"success": False, "message": "Reset token required"}

        record = db.password_resets.find_one(
            {"token_hash": hash_token(token), "used": False}
        )
        if not record:
            return {"success": False, "message": "Invalid or used reset token"}

        expires = record["expires_at"]
        if expires.tzinfo is None:
            from datetime import timezone
            expires = expires.replace(tzinfo=timezone.utc)
        if utcnow() > expires:
            db.password_resets.update_one({"_id": record["_id"]}, {"$set": {"used": True}})
            return {"success": False, "message": "Reset token expired"}

        user = db.users.find_one({"_id": ObjectId(record["user_id"])})
        if not user:
            return {"success": False, "message": "User not found"}

        db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"password_hash": hash_password(new_password), "updated_at": utcnow()}},
        )
        db.password_resets.update_one({"_id": record["_id"]}, {"$set": {"used": True}})
        db.sessions.update_many(
            {"user_id": str(user["_id"]), "revoked": False},
            {"$set": {"revoked": True}},
        )
        log_security_event(
            "password_reset",
            username=user["username"],
            user_id=str(user["_id"]),
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
        )
        return {"success": True, "message": "Password reset successful. Please log in."}

    def delete_account(self, user: dict, password: str, meta: dict | None = None) -> dict:
        meta = meta or {}
        if not verify_password(password, user["password_hash"]):
            return {"success": False, "message": "Incorrect password"}
        db = get_db()
        db.users.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "is_deleted": True,
                    "public_key": None,
                    "email": f"deleted_{user['_id']}@invalid.local",
                    "updated_at": utcnow(),
                }
            },
        )
        db.sessions.update_many(
            {"user_id": str(user["_id"])},
            {"$set": {"revoked": True}},
        )
        log_security_event(
            "account_delete",
            username=user["username"],
            user_id=str(user["_id"]),
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
        )
        return {"success": True, "message": "Account deleted"}
