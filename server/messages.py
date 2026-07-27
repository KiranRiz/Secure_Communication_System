# server/messages.py
# Persist ciphertext-only chat messages (server cannot read content)

from datetime import datetime, timezone

from bson import ObjectId

from server.db import get_db, utcnow
from server.security_utils import conversation_id


def save_message(msg_id: str, sender: str, recipient: str, encrypted: dict) -> dict:
    db = get_db()
    now = utcnow()
    doc = {
        "msg_id": msg_id,
        "conversation_id": conversation_id(sender, recipient),
        "sender": sender,
        "recipient": recipient,
        "encrypted": encrypted,  # ciphertext + nonce only
        "status": "sent",
        "delivered_at": None,
        "read_at": None,
        "edited": False,
        "deleted_for": [],
        "created_at": now,
        "updated_at": now,
    }
    db.messages.insert_one(doc)
    return serialize_message(doc)


def mark_delivered(msg_id: str) -> None:
    db = get_db()
    db.messages.update_one(
        {"msg_id": msg_id, "delivered_at": None},
        {"$set": {"status": "delivered", "delivered_at": utcnow(), "updated_at": utcnow()}},
    )


def mark_read(msg_id: str, reader: str) -> dict | None:
    db = get_db()
    msg = db.messages.find_one({"msg_id": msg_id, "recipient": reader})
    if not msg:
        return None
    db.messages.update_one(
        {"_id": msg["_id"]},
        {"$set": {"status": "read", "read_at": utcnow(), "updated_at": utcnow()}},
    )
    return serialize_message(db.messages.find_one({"_id": msg["_id"]}))


def get_history(user_a: str, user_b: str, limit: int = 50, before: str | None = None) -> list:
    db = get_db()
    query = {
        "conversation_id": conversation_id(user_a, user_b),
        "deleted_for": {"$ne": user_a},
    }
    if before:
        try:
            query["created_at"] = {"$lt": datetime.fromisoformat(before.replace("Z", "+00:00"))}
        except ValueError:
            pass
    cursor = (
        db.messages.find(query)
        .sort("created_at", -1)
        .limit(min(limit, 100))
    )
    msgs = [serialize_message(m) for m in cursor]
    msgs.reverse()
    return msgs


def search_messages(username: str, query_text: str, limit: int = 30) -> list:
    """
    Search is limited: ciphertext is opaque.
    We only match msg_id / sender / recipient metadata, not plaintext.
    """
    db = get_db()
    q = (query_text or "").strip()
    if not q:
        return []
    cursor = db.messages.find(
        {
            "$and": [
                {"$or": [{"sender": username}, {"recipient": username}]},
                {"deleted_for": {"$ne": username}},
                {
                    "$or": [
                        {"msg_id": {"$regex": q, "$options": "i"}},
                        {"sender": {"$regex": q, "$options": "i"}},
                        {"recipient": {"$regex": q, "$options": "i"}},
                    ]
                },
            ]
        }
    ).sort("created_at", -1).limit(min(limit, 50))
    return [serialize_message(m) for m in cursor]


def list_conversations(username: str) -> list:
    """
    Return recent conversation peers for the sidebar.
    Last-message preview is ciphertext-only on the server;
    clients may overlay a local decrypted preview.
    """
    db = get_db()
    pipeline = [
        {
            "$match": {
                "$or": [{"sender": username}, {"recipient": username}],
                "deleted_for": {"$ne": username},
            }
        },
        {"$sort": {"created_at": -1}},
        {
            "$group": {
                "_id": "$conversation_id",
                "last_message": {"$first": "$$ROOT"},
                "message_count": {"$sum": 1},
            }
        },
        {"$sort": {"last_message.created_at": -1}},
        {"$limit": 100},
    ]
    rows = list(db.messages.aggregate(pipeline))
    conversations = []
    for row in rows:
        last = row["last_message"]
        peer = last["recipient"] if last["sender"] == username else last["sender"]
        user = db.users.find_one(
            {"username": peer, "is_deleted": {"$ne": True}},
            {"username": 1, "profile": 1, "public_key": 1},
        )
        profile = (user or {}).get("profile") or {}
        conversations.append(
            {
                "conversation_id": row["_id"],
                "peer": peer,
                "display_name": profile.get("display_name") or peer,
                "avatar_url": profile.get("avatar_url") or "",
                "has_public_key": bool((user or {}).get("public_key")),
                "message_count": row.get("message_count", 0),
                "last_message": {
                    "msg_id": last.get("msg_id"),
                    "sender": last.get("sender"),
                    "status": last.get("status"),
                    "created_at": _iso(last.get("created_at")),
                    "encrypted": True,
                },
            }
        )
    return conversations


def soft_delete_message(msg_id: str, username: str) -> dict:
    db = get_db()
    msg = db.messages.find_one({"msg_id": msg_id})
    if not msg:
        return {"success": False, "message": "Message not found"}
    if username not in (msg["sender"], msg["recipient"]):
        return {"success": False, "message": "Not allowed"}
    db.messages.update_one(
        {"_id": msg["_id"]},
        {"$addToSet": {"deleted_for": username}, "$set": {"updated_at": utcnow()}},
    )
    return {"success": True, "message": "Message deleted for you"}


def edit_ciphertext(msg_id: str, sender: str, encrypted: dict) -> dict:
    """Allow sender to replace ciphertext (client re-encrypts edited text)."""
    db = get_db()
    msg = db.messages.find_one({"msg_id": msg_id, "sender": sender})
    if not msg:
        return {"success": False, "message": "Message not found"}
    db.messages.update_one(
        {"_id": msg["_id"]},
        {
            "$set": {
                "encrypted": encrypted,
                "edited": True,
                "updated_at": utcnow(),
            }
        },
    )
    return {
        "success": True,
        "message": "Message updated",
        "msg": serialize_message(db.messages.find_one({"_id": msg["_id"]})),
    }


def serialize_message(msg: dict) -> dict:
    if not msg:
        return {}
    created = msg.get("created_at")
    updated = msg.get("updated_at")
    return {
        "msg_id": msg.get("msg_id"),
        "conversation_id": msg.get("conversation_id"),
        "sender": msg.get("sender"),
        "recipient": msg.get("recipient"),
        "encrypted": msg.get("encrypted"),
        "status": msg.get("status"),
        "delivered_at": _iso(msg.get("delivered_at")),
        "read_at": _iso(msg.get("read_at")),
        "edited": msg.get("edited", False),
        "created_at": _iso(created),
        "updated_at": _iso(updated),
    }


def _iso(value):
    if not value:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)
