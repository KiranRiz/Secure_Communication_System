# tests/test_encryption.py
# Quick test to verify encryption works correctly

from crypto_core.ecdh import ECDHKeyExchange
from crypto_core.aes_gcm import SecureMessage
from crypto_core.fingerprint import generate_fingerprint

# This test simulates a full flow:
def test_full_flow():
    print("Testing ECDH + AES-256-GCM encryption...\n")

    # Alice and Bob generate their own ECDH key pairs
    alice = ECDHKeyExchange()
    bob = ECDHKeyExchange()

    # They exchange their public keys (safe to share)

    alice_public = alice.get_public_bytes()
    bob_public = bob.get_public_bytes()

    # Both derive the same shared secret independently
    alice_secret = alice.derive_shared_secret(bob_public)
    bob_secret = bob.derive_shared_secret(alice_public)

    # Verify that both secrets match (they should!)
    assert alice_secret == bob_secret, "Secrets don't match!"
    print("✅ ECDH Key Exchange: PASSED")

   # Now they have a shared secret, they can derive an AES key and encrypt messages
    crypto = SecureMessage()
    alice_key = crypto.derive_key_from_secret(alice_secret)
    bob_key = crypto.derive_key_from_secret(bob_secret)

    # Alice encrypts a message for Bob
    message = "Hello Bob! This is a secret message."
    encrypted = crypto.encrypt(alice_key, message)
    print(f"✅ Encrypted: {encrypted['ciphertext'][:30]}...")

    # Bob decrypts the message using the same shared secret
    decrypted = crypto.decrypt(
        bob_key,
        encrypted['nonce'],
        encrypted['ciphertext']
    )

    # Verify that the decrypted message matches the original
    assert decrypted == message, "Decryption failed!"
    print(f"✅ Decrypted: {decrypted}")

    # Fingerprint test
    fp = generate_fingerprint(alice_public)
    print(f"✅ Key Fingerprint: {fp}")

    print("\n🎉 ALL TESTS PASSED!")

if __name__ == "__main__":
    test_full_flow()