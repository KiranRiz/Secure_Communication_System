# server/server.py
# Author: Hamza (extended)
# Purpose: Relay server — JWT auth, MongoDB, OTP, rate limits, chat persistence
# Server cannot read message plaintext (maliciously curious model)

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, disconnect, emit, join_room, leave_room
from flask_talisman import Talisman

from server.auth import AuthManager
from server.config import Config
from server.db import get_db
from server.messages import (
    edit_ciphertext,
    get_history,
    list_conversations,
    mark_delivered,
    mark_read,
    save_message,
    search_messages,
    soft_delete_message,
)
from server.replay_guard import ReplayGuard
from server.security_logger import log_security_event
from server.security_utils import (
    client_meta,
    decode_access_token,
    require_auth,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY
app.config["JSON_SORT_KEYS"] = False

# Restrict CORS to known client origins (not *)
CORS(
    app,
    origins=Config.CORS_ORIGINS,
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
)

# HTTPS-ready security headers (force_https off for local HTTP)
Talisman(
    app,
    force_https=False,
    content_security_policy=None,
    frame_options="DENY",
    strict_transport_security=False,
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

def _resolve_async_mode():
    """Prefer eventlet (Docker/production); fall back for incompatible Python envs."""
    try:
        import importlib

        importlib.import_module("engineio.async_drivers.eventlet")
        return "eventlet"
    except Exception:
        return "threading"


socketio = SocketIO(
    app,
    cors_allowed_origins=Config.CORS_ORIGINS,
    logger=False,
    engineio_logger=False,
    async_mode=_resolve_async_mode(),
)

auth = AuthManager()
replay_guard = ReplayGuard()

# username -> sid
connected_users = {}
# sid -> username
sid_users = {}


def _meta():
    return client_meta()


@app.errorhandler(429)
def ratelimit_handler(e):
    meta = _meta()
    log_security_event(
        "rate_limited",
        ip=meta.get("ip"),
        user_agent=meta.get("user_agent"),
        details={"path": request.path},
    )
    return jsonify({
        "success": False,
        "message": "Too many requests. Please wait one minute and try again.",
    }), 429


@app.errorhandler(Exception)
def unhandled_error(e):
    print(f"[server] error: {e}")
    return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route("/health", methods=["GET"])
def health():
    try:
        get_db().command("ping")
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({"success": True, "mongodb": db_ok})


# ─────────────────────────────────────────
# AUTH — Register / Login / OTP / Tokens
# ─────────────────────────────────────────

@app.route("/register", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_AUTH)
def register():
    data = request.get_json(silent=True) or {}
    result = auth.register(
        data.get("username"),
        data.get("password"),
        data.get("email"),
        meta=_meta(),
    )
    status = 200 if result.get("success") else 400
    return jsonify(result), status


@app.route("/verify-otp", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_AUTH)
def verify_otp_route():
    data = request.get_json(silent=True) or {}
    purpose = (data.get("purpose") or "verification").strip().lower()
    if purpose == "login":
        result = auth.verify_login_otp(
            data.get("email"),
            data.get("otp"),
            meta=_meta(),
        )
    else:
        result = auth.verify_registration_otp(
            data.get("email"),
            data.get("otp"),
            meta=_meta(),
        )
    status = 200 if result.get("success") else 400
    return jsonify(result), status


@app.route("/resend-otp", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_AUTH)
def resend_otp_route():
    data = request.get_json(silent=True) or {}
    purpose = data.get("purpose", "verification")
    if purpose not in ("verification", "login"):
        purpose = "verification"
    result = auth.resend_otp(
        data.get("email"),
        purpose=purpose,
        meta=_meta(),
    )
    status = 200 if result.get("success") else 400
    return jsonify(result), status


@app.route("/login", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_AUTH)
def login():
    data = request.get_json(silent=True) or {}
    result = auth.login(data.get("username"), data.get("password"), meta=_meta())
    # Password OK but OTP pending still returns success=True with requires_otp
    if result.get("requires_otp") and result.get("otp_purpose") == "login":
        return jsonify(result), 200
    if result.get("requires_otp"):
        return jsonify(result), 403
    status = 200 if result.get("success") else 401
    return jsonify(result), status


@app.route("/refresh", methods=["POST"])
@limiter.limit("20 per minute")
def refresh():
    data = request.get_json(silent=True) or {}
    result = auth.refresh(data.get("refresh_token"), meta=_meta())
    status = 200 if result.get("success") else 401
    return jsonify(result), status


@app.route("/logout", methods=["POST"])
@require_auth
def logout():
    data = request.get_json(silent=True) or {}
    result = auth.logout(data.get("refresh_token"), g.current_user, meta=_meta())
    return jsonify(result)


@app.route("/forgot-password", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_AUTH)
def forgot_password():
    data = request.get_json(silent=True) or {}
    result = auth.request_password_reset(data.get("email"), meta=_meta())
    return jsonify(result)


@app.route("/reset-password", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_AUTH)
def reset_password():
    data = request.get_json(silent=True) or {}
    result = auth.reset_password(
        data.get("token"),
        data.get("password"),
        meta=_meta(),
    )
    status = 200 if result.get("success") else 400
    return jsonify(result), status


# ─────────────────────────────────────────
# KEYS — authenticated
# ─────────────────────────────────────────

@app.route("/store_key", methods=["POST"])
@require_auth
def store_key():
    data = request.get_json(silent=True) or {}
    public_key = data.get("public_key")
    if not public_key or not isinstance(public_key, str) or len(public_key) < 32:
        return jsonify({"success": False, "message": "Invalid public key"}), 400
    # Only allow user to store their own key
    ok = auth.store_public_key(g.current_user["username"], public_key)
    if not ok:
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify({"success": True, "message": "Public key stored"})


@app.route("/get_key/<username>", methods=["GET"])
@require_auth
def get_key(username):
    username = (username or "").strip()
    info = auth.lookup_user(username)
    if not info:
        return jsonify({
            "success": False,
            "code": "user_not_found",
            "message": f"User '{username}' is not registered.",
        }), 404

    key = auth.get_public_key(username)
    if key:
        return jsonify({"success": True, "public_key": key, "user": info})

    return jsonify({
        "success": False,
        "code": "key_missing",
        "message": (
            f"User '{username}' is registered but has not connected yet. "
            "Ask them to log in so key exchange can complete."
        ),
        "online": username in connected_users,
        "user": info,
    }), 404


@app.route("/lookup/<username>", methods=["GET"])
@require_auth
def lookup_user(username):
    info = auth.lookup_user(username)
    if not info:
        return jsonify({
            "success": False,
            "code": "user_not_found",
            "message": f"User '{username}' is not registered.",
        }), 404
    info["online"] = username in connected_users
    return jsonify({"success": True, "user": info})


# ─────────────────────────────────────────
# PROFILE
# ─────────────────────────────────────────

@app.route("/profile", methods=["GET"])
@require_auth
def my_profile():
    profile = auth.get_profile(g.current_user["username"])
    return jsonify({"success": True, "user": profile})


@app.route("/profile/<username>", methods=["GET"])
@require_auth
def view_profile(username):
    profile = auth.get_profile(username)
    if not profile:
        return jsonify({"success": False, "message": "User not found"}), 404
    # Hide email from other users
    if username != g.current_user["username"]:
        profile.pop("email", None)
    return jsonify({"success": True, "user": profile})


@app.route("/profile", methods=["PUT"])
@require_auth
def update_profile():
    data = request.get_json(silent=True) or {}
    result = auth.update_profile(g.current_user, data)
    return jsonify(result)


@app.route("/change-password", methods=["POST"])
@require_auth
def change_password():
    data = request.get_json(silent=True) or {}
    result = auth.change_password(
        g.current_user,
        data.get("current_password"),
        data.get("new_password"),
        meta=_meta(),
    )
    status = 200 if result.get("success") else 400
    return jsonify(result), status


@app.route("/account", methods=["DELETE"])
@require_auth
def delete_account():
    data = request.get_json(silent=True) or {}
    result = auth.delete_account(g.current_user, data.get("password"), meta=_meta())
    status = 200 if result.get("success") else 400
    return jsonify(result), status


# ─────────────────────────────────────────
# MESSAGES (ciphertext persistence)
# ─────────────────────────────────────────

@app.route("/conversations", methods=["GET"])
@require_auth
def conversations():
    username = g.current_user["username"]
    convos = list_conversations(username)
    for c in convos:
        c["online"] = c["peer"] in connected_users
    me = auth.get_profile(username)
    return jsonify({
        "success": True,
        "conversations": convos,
        "me": me,
        "online_users": list(connected_users.keys()),
    })


@app.route("/messages/<peer>", methods=["GET"])
@require_auth
def message_history(peer):
    limit = request.args.get("limit", 50, type=int)
    before = request.args.get("before")
    msgs = get_history(g.current_user["username"], peer, limit=limit, before=before)
    return jsonify({"success": True, "messages": msgs})


@app.route("/messages/search", methods=["GET"])
@require_auth
def message_search():
    q = request.args.get("q", "")
    msgs = search_messages(g.current_user["username"], q)
    return jsonify({"success": True, "messages": msgs})


@app.route("/messages/<msg_id>", methods=["DELETE"])
@require_auth
def delete_message(msg_id):
    result = soft_delete_message(msg_id, g.current_user["username"])
    status = 200 if result.get("success") else 400
    return jsonify(result), status


@app.route("/messages/<msg_id>", methods=["PUT"])
@require_auth
def edit_message(msg_id):
    data = request.get_json(silent=True) or {}
    encrypted = data.get("encrypted")
    if not encrypted:
        return jsonify({"success": False, "message": "encrypted payload required"}), 400
    result = edit_ciphertext(msg_id, g.current_user["username"], encrypted)
    status = 200 if result.get("success") else 400
    return jsonify(result), status


# ─────────────────────────────────────────
# SOCKET.IO — authenticated real-time relay
# ─────────────────────────────────────────

def _authenticate_socket(auth_payload):
    token = None
    if isinstance(auth_payload, dict):
        token = auth_payload.get("token")
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload:
        return None
    return payload.get("username")


@socketio.on("connect")
def on_connect(auth_payload=None):
    username = _authenticate_socket(auth_payload)
    if not username:
        print(f"Rejected unauthenticated socket: {request.sid}")
        return False
    old_sid = connected_users.get(username)
    if old_sid and old_sid != request.sid:
        emit("force_logout", {"reason": "Logged in from another device"}, room=old_sid)
        disconnect(old_sid)
        sid_users.pop(old_sid, None)
    connected_users[username] = request.sid
    sid_users[request.sid] = username
    join_room(username)
    print(f"Client connected: {username} ({request.sid})")
    emit("status", {"message": f"Connected as {username}"})
    emit("presence", {"username": username, "status": "online"}, broadcast=True)


@socketio.on("join")
def on_join(data):
    """Kept for compatibility — identity comes from JWT, not client username."""
    username = sid_users.get(request.sid)
    if not username:
        disconnect()
        return
    claimed = (data or {}).get("username")
    if claimed and claimed != username:
        emit("error", {"message": "Username mismatch — identity bound to JWT"})
        return
    join_room(username)
    emit("status", {"message": f"Joined as {username}"})


@socketio.on("typing")
def on_typing(data):
    username = sid_users.get(request.sid)
    if not username:
        return
    recipient = (data or {}).get("recipient")
    if recipient:
        emit(
            "typing",
            {"sender": username, "is_typing": bool((data or {}).get("is_typing", True))},
            room=recipient,
        )


@socketio.on("send_message")
def on_message(data):
    username = sid_users.get(request.sid)
    if not username:
        disconnect()
        return

    data = data or {}
    msg_id = data.get("msg_id")
    recipient = data.get("recipient")
    encrypted_payload = data.get("encrypted")
    sender = username  # never trust client-supplied sender

    if not msg_id or not recipient or not encrypted_payload:
        emit("error", {"message": "Invalid message payload"})
        return

    if replay_guard.is_replay(msg_id):
        print(f"REPLAY ATTACK DETECTED — blocked msg_id: {msg_id}")
        log_security_event(
            "replay_blocked",
            username=username,
            details={"msg_id": msg_id, "recipient": recipient},
        )
        emit("error", {"message": "Replay attack detected — blocked"})
        return

    try:
        saved = save_message(msg_id, sender, recipient, encrypted_payload)
    except Exception as exc:
        # Duplicate msg_id
        print(f"save_message error: {exc}")
        emit("error", {"message": "Message could not be stored"})
        return

    print(f"[RELAYED] {sender} → {recipient} | Ciphertext: {str(encrypted_payload)[:30]}...")

    payload = {
        "sender": sender,
        "encrypted": encrypted_payload,
        "msg_id": msg_id,
        "created_at": saved.get("created_at"),
        "status": "sent",
    }
    emit("receive_message", payload, room=recipient)
    emit("message_status", {"msg_id": msg_id, "status": "sent"}, room=sender)

    # If recipient online, mark delivered immediately
    if recipient in connected_users:
        mark_delivered(msg_id)
        emit("message_status", {"msg_id": msg_id, "status": "delivered"}, room=sender)
        emit("message_status", {"msg_id": msg_id, "status": "delivered"}, room=recipient)


@socketio.on("message_read")
def on_message_read(data):
    username = sid_users.get(request.sid)
    if not username:
        return
    msg_id = (data or {}).get("msg_id")
    if not msg_id:
        return
    updated = mark_read(msg_id, username)
    if updated:
        emit(
            "message_status",
            {"msg_id": msg_id, "status": "read"},
            room=updated["sender"],
        )


@socketio.on("message_edited")
def on_message_edited(data):
    username = sid_users.get(request.sid)
    if not username:
        return
    data = data or {}
    msg_id = data.get("msg_id")
    encrypted = data.get("encrypted")
    recipient = data.get("recipient")
    result = edit_ciphertext(msg_id, username, encrypted)
    if result.get("success") and recipient:
        emit(
            "receive_edit",
            {"msg_id": msg_id, "encrypted": encrypted, "sender": username},
            room=recipient,
        )


@socketio.on("disconnect")
def on_disconnect():
    username = sid_users.pop(request.sid, None)
    if username and connected_users.get(username) == request.sid:
        del connected_users[username]
        emit("presence", {"username": username, "status": "offline"}, broadcast=True)
        print(f"{username} disconnected")


if __name__ == "__main__":
    print("Starting Secure Chat Server...")
    print("Server is a relay only — cannot read messages")
    print(f"MongoDB database: {Config.MONGODB_DB}")
    # Ensure DB + indexes on startup
    get_db()
    socketio.run(
        app,
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.FLASK_DEBUG,
        allow_unsafe_werkzeug=True,
    )
