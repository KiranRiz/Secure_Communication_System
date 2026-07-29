# System Architecture
## B9IS129 - Secure Communication System
### Written by the group - Mubashir, Hamza, Kiran

---

This document explains how the different parts of our system connect and why we made the structural decisions we did. It's meant to be readable by another developer who wants to understand the codebase quickly, or by someone who wants to test or attack the system (which is literally part of the assignment).

**Live application:** https://100.60.238.30.sslip.io

---

## High level picture

```
[ Alice's Browser ]                         [ Bob's Browser ]
  - ECDH P-256 key pair (Web Crypto)         - ECDH P-256 key pair (Web Crypto)
  - AES-256-GCM encrypt/decrypt              - AES-256-GCM encrypt/decrypt
  - Fingerprint shown to user                - Fingerprint shown to user
        |                                           |
        |         HTTPS (Let's Encrypt)             |
        +----------> [ Nginx reverse proxy ] <------+
                         |              |
              client :3000         server :5000
              (Docker)             (Docker)
                         |
              [ Flask + Socket.IO API ]
                - JWT / OTP / bcrypt auth
                - Public-key directory
                - Ciphertext relay + ReplayGuard
                - CANNOT read messages
                         |
              [ MongoDB Atlas ]
                Secure_Communication
                users, OTPs, sessions,
                ciphertext messages, security logs
```

The key thing to notice is that the actual encryption and decryption happen entirely in the browser. The server is in the middle but it never touches any plaintext — by the time a message reaches the server it's already encrypted, and it stays encrypted until it reaches the other person's browser. Nginx terminates TLS; Docker isolates the client and server processes; MongoDB Atlas persists account and ciphertext data off the EC2 box.

---

## Runtime layers

| Layer | Technology | Role |
|-------|------------|------|
| Client UI | Flask templates + JS/CSS (`client/`) | Auth UX, chat UI, Web Crypto |
| Relay API | Flask + Flask-SocketIO (`server/`) | REST + real-time events |
| Database | MongoDB Atlas (`Secure_Communication`) | Users, OTP, sessions, ciphertext, logs |
| Crypto reference | Python `crypto_core/` | Algorithm reference + automated tests |
| Reverse proxy | Nginx | HTTPS termination, routing to containers |
| Containerization | Docker + Docker Compose | Isolated client/server runtime |
| Hosting | AWS EC2 + Elastic IP | Public deployment |

---

## Module breakdown

### crypto_core/ — Mubashir

This is the Python implementation of the cryptographic layer. Even though the browser does the actual encryption in production (using Web Crypto API), we built this Python module for three reasons: to verify our understanding of the algorithms before implementing them in JavaScript, to run proper automated tests, and to have a server-side reference for the write-up.

Files:
- `ecdh.py` — key pair generation and shared secret derivation
- `aes_gcm.py` — AES-256-GCM encrypt/decrypt, HKDF key derivation
- `fingerprint.py` — SHA-256 fingerprint generation and verification

**Note:** The live browser path uses **ECDH P-256** via Web Crypto. The Python `crypto_core` module is a reference/test implementation and may use related curves — read it with that distinction in mind.

### server/ — Hamza (API & data); Docker packaging shared with Kiran

The server is a Flask application with Socket.IO for real-time bidirectional messaging. We chose Flask because it's lightweight and we don't need the overhead of a larger framework for what is essentially a relay with auth and a few REST endpoints.

Files:
- `server.py` — main application, REST endpoints, Socket.IO handlers, rate limits, health check
- `auth.py` — registration, login, OTP verification, JWT issue/refresh/logout, profile, password reset, public keys
- `replay_guard.py` — message ID tracking to block replay attacks (5-minute window)
- `db.py` — MongoDB Atlas connection and indexes
- `messages.py` — ciphertext persistence, history, conversations, delivery/read status
- `otp_service.py` — OTP create/verify (hashed, TTL, attempt limits)
- `email_service.py` — OTP and password-reset email delivery (or console in `EMAIL_DEV_MODE`)
- `security_utils.py` — bcrypt, JWT helpers, `require_auth`, validation
- `security_logger.py` — security audit events
- `config.py` — environment-driven configuration

Representative REST endpoints:
- `POST /register`, `POST /verify_otp`, `POST /resend_otp`
- `POST /login`, `POST /refresh`, `POST /logout`
- `POST /forgot_password`, `POST /reset_password`
- `POST /store_key`, `GET /get_key/<username>`
- Profile, conversations, message history/search (JWT-protected)

Socket.IO events (JWT-authenticated connect):
- `join` — user connects and registers their session / room
- `send_message` — relay encrypted message; ReplayGuard on `msg_id`
- `receive_message` — delivered to recipient's browser
- Typing, delivery/read, and related presence events

### client/ — Kiran

The client is a second Flask application (port 3000 locally; behind Nginx in production) that serves the web interface and talks to the relay API.

Files:
- `app.py` — Flask app, serves HTML templates, proxies/forwards API calls where needed
- `templates/` — login, register, OTP, chat, profile screens
- `static/style.css` — styling
- `static/chat.js` — browser ECDH/AES-GCM, fingerprint UI, Socket.IO chat logic

Encryption runs in JavaScript in the browser via the Web Crypto API so that plaintext never exists on either Flask process — only inside the user's own browser tab.

### Deployment packaging — Kiran

- `docker-compose.yml` — orchestrates `client` and `server` containers
- Per-service Dockerfiles under `server/` and `client/`
- Nginx + Certbot on the EC2 host for HTTPS and WebSocket upgrades

---

## Data storage — MongoDB Atlas

### Why MongoDB Atlas (not a local JSON file)

Earlier prototypes used a flat `users.json` file. The current system uses **MongoDB Atlas** (database name `Secure_Communication`) because:

- Data is naturally document-shaped (users, sessions, messages) rather than strictly relational
- Managed hosting removes the need to run and harden a database on the EC2 instance itself
- Encryption at rest and network controls (IP allowlisting) support the assessment's security requirements
- Flexible schema fits fields that evolved during development (OTP metadata, session rotation, ciphertext history)

The security properties we care about (password hashing, ciphertext-only message storage) work the same regardless of storage engine; Atlas is the production-appropriate choice for a live demo.

### Main entities

| Entity | Key fields | Notes |
|--------|------------|-------|
| Users | username, email, password_hash, public_key, created_at, is_deleted | bcrypt hash; public_key for ECDH directory |
| OTPs | email/username, otp_hash, purpose, expires_at, attempts | Hashed, time-limited, attempt-limited |
| Sessions / refresh tokens | username, refresh_token_hash, issued_at, expires_at | JWT access + hashed refresh rotation |
| Messages | msg_id, sender, recipient, ciphertext, nonce, timestamp, read_status | **Ciphertext only** — never plaintext |
| Security logs | event_type, ip, user_agent, path, timestamp | Abuse auditing / investigation |

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
   - Authenticates the socket session (JWT)
   - Checks msg_id against ReplayGuard — if seen before, drop it
   - Persists ciphertext metadata to MongoDB Atlas
   - Forwards the payload to Bob's socket room
   - Server never looks at plaintext (it has none)

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
1. Alice starts a chat with Bob (sidebar / connect flow)

2. Browser generates fresh ECDH key pair (P-256 curve via Web Crypto)

3. Alice's public key is uploaded to server via POST /store_key

4. Browser fetches Bob's public key via GET /get_key/bob

5. Browser calls window.crypto.subtle.deriveKey() with:
   - Alice's private key + Bob's public key
   - Result: AES-256-GCM key, stored in memory only

6. Fingerprint is displayed to Alice
   (Bob sees a corresponding fingerprint on his side)

7. Alice and Bob can optionally verify fingerprints match
   via phone call / other channel — this step detects MITM (TOFU-style)
```

---

## Authentication & session architecture

```
Register → email OTP verify → account active
Login    → password check (bcrypt) → login OTP → JWT access + refresh
```

- **bcrypt** for password storage (never plaintext, never fast unsalted hashes alone)
- **6-digit OTP** hashed server-side with TTL and attempt limits (register + login step-up)
- **JWT access token** (short-lived) + **hashed refresh token** with rotation
- **Rate limiting** on auth routes (~5/min) via flask-limiter
- **Single-device session enforcement** — a new login can force-disconnect an older session for the same user (avoids dual-browser key confusion / decryption failures)
- Socket.IO connections present JWT at connect time before joining rooms

---

## Deployment — AWS cloud

### Architecture

| Piece | Choice |
|-------|--------|
| Cloud provider | AWS EC2 (Ubuntu, t3.micro) |
| Addressing | Elastic IP (stable public IP across restarts) |
| App packaging | Docker + Docker Compose (`client` :3000, `server` :5000) |
| Reverse proxy | Nginx — routes HTTP(S) to containers; WebSocket upgrade for Socket.IO |
| TLS | Let's Encrypt (Certbot) via sslip.io hostname mapped to the Elastic IP |
| Process model | `docker compose up -d` so the app survives SSH disconnect |
| Database | MongoDB Atlas (external to EC2) |

Public URL pattern: `https://<elastic-ip>.sslip.io` (current live link in README).

### Trust boundaries in production

1. **Browser ↔ Nginx:** HTTPS (confidentiality/integrity of transport to our host)
2. **Nginx ↔ containers:** local Docker network routing (client UI vs API/WebSocket)
3. **Server ↔ MongoDB Atlas:** TLS connection string; server still stores only hashes and ciphertext
4. **End-to-end content:** still protected by client-side AES-GCM regardless of TLS — TLS protects the channel; E2E protects content from the relay

### Environment configuration

See `.env.example`. At minimum production needs:
- `MONGODB_URI` — Atlas connection string
- `SECRET_KEY` — Flask secret
- `JWT_SECRET` — token signing
- `SERVER_URL` / `CLIENT_URL` / `CORS_ORIGINS` — must match the deployed HTTPS origin (not `localhost`)
- SMTP settings (or `EMAIL_DEV_MODE` for console OTPs during local testing)

### Deployment challenges (summary)

Issues hit during AWS bring-up and how they were fixed are documented in the README Section 10 (wrong `SERVER_URL` inside Docker, CORS/`CLIENT_URL`, eventlet for Socket.IO, HTTPS required for Web Crypto, Socket.IO transport order, Nginx path routing for `/store_key` and `/get_key`, single-device session enforcement).

---

## Threat model reminder (architecture implications)

| Assumption | Architectural response |
|------------|------------------------|
| Server is curious but protocol-honest | Ciphertext-only relay + DB; no private keys on server |
| Network may be observed or attacked | HTTPS at edge + AES-GCM authenticity; fingerprint for active MITM awareness |
| Compromised end device | Out of scope for E2E — architecture cannot save a stolen browser |
| User skips fingerprint | Documented TOFU limitation |

**Server can see:** usernames, emails, public ECDH keys, metadata (who/when/size), ciphertext blobs.  
**Server cannot see:** private keys, shared ECDH secrets, plaintext message content.

---

## Limitations we're aware of

**Manual fingerprint verification** — shown in UI but not enforced before chat.

**No Signal-style double ratchet** — per-session keys only; no full forward-secrecy protocol beyond that.

**Offline / re-key edge case** — messages sent while a peer is offline can fail to decrypt if the session key is re-established before that peer reads them.

**In-memory ReplayGuard** — seen `msg_id` set lives in the server process; a restart clears it. A Redis-backed store would be more robust for multi-instance scale.

**Compromised client devices** — outside what end-to-end encryption can promise.
