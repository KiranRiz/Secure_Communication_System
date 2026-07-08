# server/replay_guard.py
# Author: Hamza
# Purpose: Prevent replay attacks using unique message IDs

import time


class ReplayGuard:
    """
    Replay Attack Protection.
    Problem: Attacker captures a message and resends it later.
    Solution: Every message has unique ID — server remembers
    seen IDs and blocks duplicates.
    """

    def __init__(self, window_seconds=300):
        # Store seen message IDs with timestamp
        self.seen_ids = {}
        # Only remember messages from last 5 minutes
        self.window = window_seconds

    def is_replay(self, message_id: str) -> bool:
        """
        Returns True if message is a replay attack.
        Returns False if message is fresh/new.
        """
        now = time.time()

        # Clean old entries outside time window
        self.seen_ids = {
            k: v for k, v in self.seen_ids.items()
            if now - v < self.window
        }

        # Check if we have seen this ID before
        if message_id in self.seen_ids:
            return True  # REPLAY DETECTED

        # New message — store it
        self.seen_ids[message_id] = now
        return False
