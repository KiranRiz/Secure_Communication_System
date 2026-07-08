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
    # Compute SHA-256 hash of the public key bytes
    full_hash = hashlib.sha256(public_key_bytes).hexdigest()

    # Format like SSH fingerprints — easier to compare
    chunks = [full_hash[i:i+4] for i in range(0, 16, 4)]
    # Return the fingerprint as a colon-separated string
    return ':'.join(chunks)

# Example usage:
def verify_fingerprint(public_key_bytes: bytes,
                       expected: str) -> bool:
    """Check if a key matches expected fingerprint"""
    # Generate the fingerprint from the public key bytes
    return generate_fingerprint(public_key_bytes) == expected