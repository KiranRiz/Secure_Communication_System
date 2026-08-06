# server/replay_guard.py
# Author: Hamza
# Purpose: Prevent replay attacks using unique message IDs
# Seen IDs are persisted in MongoDB with TTL so protection
# survives process restarts and works across workers.

from datetime import timedelta

from pymongo.errors import DuplicateKeyError

from server.db import get_db, utcnow


class ReplayGuard:
    """
    Replay Attack Protection.
    Problem: Attacker captures a message and resends it later.
    Solution: Every message has unique ID — server remembers
    seen IDs in MongoDB and blocks duplicates within the window.
    """

    def __init__(self, window_seconds=300):
        self.window = window_seconds

    def is_replay(self, message_id: str) -> bool:
        """
        Returns True if message is a replay attack.
        Returns False if message is fresh/new.
        """
        if not message_id:
            return True

        db = get_db()
        now = utcnow()
        expires_at = now + timedelta(seconds=self.window)

        try:
            db.replay_ids.insert_one(
                {
                    "msg_id": message_id,
                    "created_at": now,
                    "expires_at": expires_at,
                }
            )
            return False
        except DuplicateKeyError:
            return True
