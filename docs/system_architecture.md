# System Architecture
## B9IS129 - Secure Communication System
### Written by the group - Mubashir, Hamza, Kiran

---

This document explains how the different parts of our system connect and why we made the structural decisions we did. It's meant to be readable by another developer who wants to understand the codebase quickly, or by someone who wants to test or attack the system (which is literally part of the assignment).

---

## High level picture

```
[ Alice's Browser ]                         [ Bob's Browser ]
  - Generates ECDH key pair                  - Generates ECDH key pair
  - Encrypts with AES-256-GCM                - Decrypts with AES-256-GCM
  - Fingerprint shown to user                - Fingerprint shown to user
        |                                           |
        |  public key upload / message relay        |
        |                                           |
        +-----------> [ Flask Server ] <------------+
                         - Stores public keys
                         - Relays ciphertext only
                         - Checks replay attack IDs
                         - Handles login / register
                         - CANNOT read messages
```

The key thing to notice is that the actual encryption and decryption happen entirely in the browser. The server is in the middle but it never touches any plaintext - by the time a message reaches the server it's already encrypted, and it stays encrypted until it reaches the other person's browser.

---

## Module breakdown

### crypto_core/ - Mubashir

This is the Python implementation of the cryptographic layer. Even though the browser does the actual encryption in production (using Web Crypto API), we built this Python module for three reasons: to verify our understanding of the algorithms before implementing them in JavaScript, to run proper automated tests, and to have a server-side
encryption option if needed.

Files:
- `ecdh.py` - X25519 key pair generation and shared secret derivation
- `aes_gcm.py` - AES-256-GCM encrypt/decrypt, HKDF key derivation
- `fingerprint.py` - SHA-256 fingerprint generation and verification

The Python `cryptography` library is used here rather than something like PyCryptodome because it's more actively maintained and provides better support for modern curves like X25519.

### server/ - Hamza

The server is a Flask application with Socket.IO added for real-time bidirectional messaging. We chose Flask because it's lightweight and we don't need the overhead of a larger framework for what is essentially a relay with a few REST endpoints.

Files:
- `server.py` - main application, REST endpoints, Socket.IO event handlers
- `auth.py` - user registration, login, password hashing
- `replay_guard.py` - message ID tracking to block replay attacks

REST endpoints:
- `POST /register` - create account
- `POST /login` - authenticate
- `POST /store_key` - upload ECDH public key after login
- `GET /get_key/<username>` - fetch another user's public key

Socket.IO events:
- `join` - user connects and registers their session
- `send_message` - relay encrypted message to recipient
- `receive_message` - received by the other user's browser

User data is stored in a `users.json` file. We chose this over a database because the assignment scope doesn't require scalability and a flat file keeps the setup simpler - there's nothing to install or configure separately. A production version would use a proper database.

### client/ - Kiran

The client is a second Flask application (running on port 3000) that serves the web interface and proxies API calls to the main server on port 5000.

Files:
- `app.py` - Flask app, serves HTML templates, proxies login/register
- `templates/index.html` - login and register page
- `templates/chat.html` - main chat interface
- `static/style.css` - styling
- `static/chat.js` - all encryption logic runs here in the browser

The reason encryption is done in JavaScript in the browser rather than in the Flask client app is important: if the client app handled encryption, the app itself would see plaintext messages. By using the Web Crypto API directly in the browser, even the client server cannot read messages. The only place plaintext ever exists is inside the user's
own browser tab.

---

## Data flow for a single message

Here is the exact sequence when Alice sends "Hello" to Bob:

```
1. Alice types "Hello" and clicks Send

2. chat.js calls encryptMessage():
   - Gets the AES key derived from ECDH exchange
   - Generates a random 12-byte nonce
   - Calls window.crypto.subtle.encrypt() with AES-GCM
   - Returns {nonce: "...", ciphertext: "..."}

3. chat.js generates a UUID for this message

4. Socket.IO emits 'send_message' to the server:
   {
     msg_id: "550e8400-...",
     sender: "alice",
     recipient: "bob",
     encrypted: {nonce: "a3f9...", ciphertext: "7b2c..."}
   }

5. Server's on_message() handler receives this:
   - Checks msg_id against ReplayGuard - if seen before, drop it
   - If new, stores the ID and forwards the whole payload to Bob's
     socket room
   - Server never looks at the encrypted field content

6. Bob's browser receives 'receive_message' event

7. chat.js calls decryptMessage():
   - Uses Bob's copy of the AES key (derived from same ECDH exchange)
   - Decrypts using the nonce from the payload
   - If ciphertext was tampered with, GCM authentication fails here

8. Plaintext "Hello" is displayed in Bob's chat window
```

---

## Key exchange flow (first time two users connect)

This happens before any messages can be sent:

```
1. Alice clicks "Connect" and enters Bob's username

2. Browser generates fresh ECDH key pair (P-256 curve via Web Crypto)

3. Alice's public key is uploaded to server via POST /store_key

4. Browser fetches Bob's public key via GET /get_key/bob

5. Browser calls window.crypto.subtle.deriveKey() with:
   - Alice's private key + Bob's public key
   - Result: AES-256-GCM key, stored in memory only

6. Fingerprint is displayed to Alice
   (Bob sees a corresponding fingerprint on his side)

7. Alice and Bob can optionally verify fingerprints match
   via phone call / other channel - this step prevents MITM
```

---

## Why we didn't use a database

A few people might wonder why we're using a JSON file for storage instead of SQLite or PostgreSQL. Honest answer: the assignment is about secure communications, not database design. A JSON file is readable, requires no setup, and is easy to inspect when debugging. The security properties we care about (password hashing, encryption) work exactly the
same way regardless of what stores the data. If this were going into production we'd switch to a proper database, but for a group project of this scope it would be complexity without benefit.

---

## Deployment

The server is designed to run on any platform that supports Python 3.9+.
For cloud deployment we are targeting Render (simple Git-connected deployment) or Azure App Service. The `host='0.0.0.0'` setting in `server.py` means it will accept connections from any network interface, which is needed for cloud hosting.

Environment variables (see `.env.example`):
- `SECRET_KEY` - Flask session secret
- `SERVER_URL` - used by client app to know where the server is

---

## Limitations we're aware of

We'd rather be upfront about these than have them pointed out in the pentest reports as surprises.

**No forward secrecy across sessions** - each new chat session generates fresh keys, but there's no Signal-style ratchet mechanism. If a session key were ever extracted from memory, only that session is affected.

**Manual fingerprint verification** - the system shows the fingerprint but doesn't enforce that users check it. A first-time user might skip this step.

**In-memory replay protection** - the replay guard lives in the server process memory. If the server restarts, the seen-ID history is lost. A Redis-backed version would be more robust.

**JSON storage** - not appropriate for production scale, and the users.json file should be excluded from version control in a real deployment (we have it in .gitignore).
