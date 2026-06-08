# security/fingerprint.py
# Author: Mubashir
# Purpose: Key fingerprint verification — prevents MITM attacks
# by letting users verify they talk to right person

import hashlib

# Key fingerprint generation and verification
def generate_fingerprint(public_key_bytes: bytes) -> str:
    """
    Create a short human-readable fingerprint of a public key.
    Users can compare fingerprints out-of-band (e.g., over phone)
    to verify they are talking to the right person.
    """
    full_hash = hashlib.sha256(public_key_bytes).hexdigest()

    # Format like SSH fingerprints — easier to compare
    chunks = [full_hash[i:i+4] for i in range(0, 16, 4)]
    return ':'.join(chunks)

# Example usage:
def verify_fingerprint(public_key_bytes: bytes,
                       expected: str) -> bool:
    """Check if a key matches expected fingerprint"""
    return generate_fingerprint(public_key_bytes) == expected