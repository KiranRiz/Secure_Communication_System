# server/auth.py
# Author: Hamza + Kiran
# Purpose: User authentication — register and login

import hashlib
import os
import json


class AuthManager:
    """
    Simple authentication using hashed passwords.
    Passwords are NEVER stored in plain text.
    Uses SHA-256 with salt for security.
    """

    def __init__(self):
        self.users_file = "users.json"
        self.users = self._load_users()

    def _load_users(self) -> dict:
        """Load users from file if exists"""
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_users(self):
        """Save users to file"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)

    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using SHA-256"""
        combined = password + salt
        return hashlib.sha256(combined.encode()).hexdigest()

    def register(self, username: str, password: str) -> dict:
        """Register a new user"""
        if username in self.users:
            return {"success": False, "message": "User already exists"}

        # Generate random salt for each user
        salt = os.urandom(16).hex()
        hashed = self._hash_password(password, salt)
        self.users[username] = {
            "password_hash": hashed,
            "salt": salt,
            "public_key": None  # Set during key exchange
        }
        self._save_users()
        return {"success": True, "message": "Registered successfully"}

    def login(self, username: str, password: str) -> dict:
        """Verify user credentials"""
        if username not in self.users:
            return {"success": False, "message": "User not found"}

        user = self.users[username]
        hashed = self._hash_password(password, user["salt"])
        if hashed == user["password_hash"]:
            return {"success": True, "message": "Login successful"}
        return {"success": False, "message": "Wrong password"}

    def store_public_key(self, username: str, public_key: str):
        """Store user's ECDH public key on server"""
        if username in self.users:
            self.users[username]["public_key"] = public_key
            self._save_users()

    def get_public_key(self, username: str) -> str:
        """Get user's public key for key exchange"""
        if username in self.users:
            return self.users[username].get("public_key")
        return None
