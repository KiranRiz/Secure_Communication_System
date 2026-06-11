# Added proper security comments and clarified AES-GCM + HKDF flow
# security/aes_gcm.py
# Author: Mubashir
# Purpose: AES-256-GCM encryption — encrypts messages so only
# intended recipient can read them

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# AES-GCM (Galois/Counter Mode) Authenticated Encryption Implementation
class SecureMessage:
    """
    AES-256-GCM Authenticated Encryption.
    
    Why GCM mode?
    - Provides CONFIDENTIALITY (no one can read)
    - Provides INTEGRITY (no one can tamper)
    - Server cannot modify messages without detection
    """
# Note: In a real application, you would use the shared secret to encrypt
    def derive_key_from_secret(self, shared_secret: bytes) -> bytes:
        """
        Convert ECDH shared secret into a proper AES-256 key.
        Uses HKDF (industry standard key derivation).
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,          # 32 bytes = 256 bits = AES-256
            salt=None,
            info=b'secure-chat-aes-key-v1'
        )
        # Note: The shared secret is never sent to the server, only derived locally
        return hkdf.derive(shared_secret)
# Note: The shared secret is never sent to the server, only derived locally
    def encrypt(self, aes_key: bytes, plaintext: str) -> dict:
        """
        Encrypt a message.
        Returns nonce + ciphertext (both needed for decryption).
        """
        aesgcm = AESGCM(aes_key)

        # Nonce must be unique for every single message
        nonce = os.urandom(12)  # 96 bits — GCM standard
        # Note: The nonce is not secret, but must be unique for each message. It can be sent to the server.
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode('utf-8'),
            None  # No additional data for now
        )
# Note: Both nonce and ciphertext are needed to decrypt, so we return both.
        return {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }
# Note: The nonce is not secret, but must be unique for each message. It can be sent to the server.
    def decrypt(self, aes_key: bytes, nonce_hex: str,
                ciphertext_hex: str) -> str:
        """
        Decrypt a message.
        Will raise error if message was tampered with.
        """
       # Note: The nonce is not secret, but must be unique for each message. It can be sent to the server.
        aesgcm = AESGCM(aes_key)
    # Note: If decryption fails (e.g. message was modified), an exception is raised.
        plaintext_bytes = aesgcm.decrypt(
            bytes.fromhex(nonce_hex),
            bytes.fromhex(ciphertext_hex),
            None
        )
        #Note: If decryption fails (e.g. message was modified), an exception is raised.
        return plaintext_bytes.decode('utf-8')