# security/ecdh.py
# Author: Mubashir
# Purpose: ECDH Key Exchange — allows two parties to create
# a shared secret without ever meeting to exchange keys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization

#ECDH (Elliptic Curve Diffie-Hellman) Key Exchange Implementation
class ECDHKeyExchange:
    """
    Elliptic Curve Diffie-Hellman (X25519) key exchange.
    
    How it works:
    1. Alice generates her private + public key
    2. Bob generates his private + public key  
    3. They exchange PUBLIC keys only (safe to share)
    4. Both derive the SAME shared secret independently
    5. Server never sees the shared secret
    """
 # Note: In a real application, you would use the shared secret to encrypt
    def __init__(self):
        # Generate a new private key (keep this secret always)
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
# Note: The public key can be safely sent to the server or other party
    def get_public_bytes(self) -> bytes:
        """Return public key as bytes — safe to send to server"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
#Note: The shared secret is never sent to the server, only derived locally
    def derive_shared_secret(self, peer_public_bytes: bytes) -> bytes:
        """
        Derive shared secret using peer's public key.
        Both parties get the same secret without sending it.
        """
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret

 # Helper method to get public key as hex string for easy transmission
    def get_public_hex(self) -> str:
        """Return public key as hex string for easy transmission"""
        return self.get_public_bytes().hex()