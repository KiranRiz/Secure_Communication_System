# Secure Communication System

## Course & Assessment Information

| Field | Details |
|-------|---------|
| **Module code** | B9IS129 |
| **Module title** | Computer Systems Security |
| **Class / CRN** | B9IS129_2526_TMD3 |
| **Institution** | Dublin Business School (DBS) |
| **Assessment** | CA_ONE_(100%) |
| **Assessment weight** | 100% of module |
| **Lecturer** | Paul Laird |
| **Semester** | Semester 2, Academic Year 2025/26 |
| **Project title** | Secure Communication System |
| **Submission type** | Group project (repository + documentation + demo evidence) |

---

## Group Members & Roles

| Member | Primary responsibility | Main deliverables |
|--------|------------------------|-------------------|
| **Mubashir** | Security & encryption core | `crypto_core/`, threat model, algorithm justification, security docs & tests |
| **Hamza** | Backend server & deployment | `server/`, MongoDB Atlas, JWT/OTP APIs, Socket.IO relay, replay protection, deployment |
| **Kiran** | Client & authentication UI | `client/`, browser ECDH/AES (Web Crypto), auth screens, chat UX, user docs |

Group meetings were held over Zoom with captions enabled. Recordings, minutes, and AI assistance log links are kept in the shared M365 folder as required by module submission guidelines.

---

## 1. Abstract

This Continuous Assessment (CA_ONE) delivers an end-to-end encrypted messaging system in which two users who have **never previously met to exchange keys** can communicate securely through an untrusted relay server.

Clients perform **ECDH (P-256)** key agreement and **AES-256-GCM** message encryption in the browser via the Web Crypto API. The Flask + Socket.IO server stores public keys, authenticates users, and relays **ciphertext only**. It is designed under a **maliciously curious server** threat model: the server is trusted to deliver messages, but **must not** be able to read message content.

Identity is supported by **email OTP verification** plus **out-of-band key fingerprint checking** (idiosyncratic / TOFU-style MITM detection). Additional hardening includes **bcrypt** password hashing, **JWT** access/refresh sessions, rate limiting, replay protection, ciphertext persistence, and security audit logs.

---

## 2. Assessment Brief Alignment

The CA_ONE brief requires a communications system where parties can message securely **without a prior shared secret**, with a server that **must not be trusted with confidentiality**.

| Brief requirement | How this project meets it |
|-------------------|---------------------------|
| Secure messaging without prior key meeting | Browser ECDH key exchange via public-key directory |
| Untrusted / maliciously curious server | AES-GCM encryption client-side; server sees only ciphertext |
| Identity approach | Email OTP + human-readable session fingerprint |
| Replay resistance | Unique `msg_id` + 5-minute ReplayGuard window |
| Documented, testable design | README, `docs/`, `crypto_core` pytest suite |
| Team ownership split | Crypto / server / client owned by named members |
| No security through obscurity | Standard algorithms (ECDH, AES-GCM, bcrypt, JWT) |

---

## 3. Project Objectives

1. Enable real-time encrypted chat between two registered users.
2. Establish a shared session key without pre-shared passwords between peers.
3. Ensure the relay server cannot decrypt message payloads.
4. Authenticate users and protect accounts (hashing, OTP, JWT, rate limits).
5. Detect or discourage MITM during first key exchange via fingerprint comparison.
6. Block simple replay of captured ciphertext messages at the relay.
7. Provide clear architecture, security, and setup documentation for markers and peers.

---

## 4. System Overview

```
[ Alice Browser ]                          [ Bob Browser ]
  ECDH P-256 key pair                        ECDH P-256 key pair
  AES-256-GCM encrypt/decrypt                AES-256-GCM encrypt/decrypt
  Fingerprint display                        Fingerprint display
        |                                           |
        |  JWT + public keys + ciphertext only      |
        +------------> [ Flask Server :5000 ] <-----+
                         MongoDB Atlas
                         Auth / OTP / Sessions
                         Public key directory
                         Ciphertext relay + history
                         ReplayGuard
                         Security logs
        |
[ Client UI :3000 ]  — login, OTP, chat sidebar, profile
```

**Runtime split**

| Layer | Technology | Role |
|-------|------------|------|
| Client UI | Flask templates + JS/CSS (`client/`) | Auth UX, chat UI, Web Crypto |
| Relay API | Flask + Flask-SocketIO (`server/`) | REST + real-time events |
| Database | MongoDB Atlas (`Secure_Communication`) | Users, OTP, sessions, ciphertext, logs |
| Crypto reference | Python `crypto_core/` | Algorithm reference + automated tests |

---

## 5. Security Design

### 5.1 Threat model

| Assumption | Implication |
|------------|-------------|
| Server is honest in protocol execution but curious | May log all traffic; design must keep plaintext off-server |
| Network may be observed or actively attacked | Need authenticated encryption + MITM detection option |
| End devices are not fully compromised | E2E encryption cannot protect a compromised browser |
| Users may skip fingerprint check | TOFU risk acknowledged as a documented limitation |

### 5.2 Cryptographic controls

| Control | Algorithm / mechanism | Where |
|---------|----------------------|-------|
| Peer key agreement | ECDH **P-256** (Web Crypto) | Browser (`client/static/chat.js`) |
| Message confidentiality + integrity | **AES-256-GCM** (fresh nonce per message) | Browser |
| Password storage | **bcrypt** | Server (`server/auth.py`) |
| Session auth | **JWT** access + hashed refresh rotation | Server |
| Email verification / login step-up | **6-digit OTP** (hashed, TTL, attempt limits) | Server + email |
| Replay protection | UUID `msg_id` + 5-minute seen set | `server/replay_guard.py` |
| MITM awareness | Session key fingerprint shown in UI | Client |
| Auth abuse resistance | Rate limit (~5/min on auth) | flask-limiter |
| Transport hardening (app layer) | CORS lockdown, security headers (Talisman) | Server |

### 5.3 What the server can and cannot see

**Can see:** usernames, emails (account data), public ECDH keys, metadata (who messaged whom, approximate size/time), ciphertext blobs.

**Cannot see:** private keys, shared ECDH secrets, plaintext message content.

---

## 6. Functional Features

### 6.1 Core CA_ONE features

- User registration and login
- Public key store/fetch (`/store_key`, `/get_key`)
- ECDH session establishment without prior meeting
- Real-time encrypted messaging over Socket.IO
- Key fingerprint display for out-of-band verification
- Replay attack rejection on duplicate message IDs

### 6.2 Security & account enhancements

- MongoDB Atlas persistence (users, OTPs, sessions, messages, security logs)
- Email OTP for registration verification
- Login OTP step (password then email code)
- Password reset via emailed one-time token
- JWT-protected REST and Socket.IO identity
- Rate limiting and security audit logging
- Profile update, change password, soft-delete account

### 6.3 Client / UX features

- Modern Login / Register / OTP / Forgot-password flows
- WhatsApp-style sidebar (conversations, search, new chat)
- Typing indicators, presence, delivery/read status
- Ciphertext message history load (decryptable when keys persist)
- Profile page with avatar URL support
- Loaders/skeletons and logout confirmation

---

## 7. Repository Structure

```
Secure_Communication_System/
├── crypto_core/          # Mubashir — ECDH / AES-GCM / fingerprint (Python)
├── server/               # Hamza — Flask API, Socket.IO, auth, MongoDB
├── client/               # Kiran — UI templates, static JS/CSS, client app
├── tests/                # pytest for crypto_core
├── docs/                 # Architecture, security, setup/API, feature PDF
├── .env.example          # Required environment variables (no secrets)
├── requirements.txt
└── README.md             # This CA_ONE report overview
```

Supporting docs:

| Document | Purpose |
|----------|---------|
| `docs/security_requirements.md` | Security rationale (Mubashir) |
| `docs/system_architecture.md` | Architecture narrative |
| `docs/design_specification.md` | FR / NFR / SR tables |
| `docs/SETUP_AND_API.md` | Env, schema, API & Socket.IO reference |
| `docs/CA_ONE_Feature_Breakdown_Group.pdf` | Feature ownership PDF for the group |

---

## 8. How to Run (Local)

### Prerequisites

- Python 3.10+ recommended
- MongoDB Atlas connection string
- (Optional) Gmail App Password for real OTP email

### Setup

1. Copy `.env.example` to `.env` and set at least:
   - `MONGODB_URI`
   - `SECRET_KEY`
   - `JWT_SECRET`
2. Install dependencies:

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
# source venv/bin/activate
pip install -r requirements.txt
```

3. Start the relay server (port **5000**):

```bash
python -m server.server
```

4. In a second terminal, start the client UI (port **3000**):

```bash
python client/app.py
```

5. Open `http://localhost:3000`

### Demo flow (recommended for marking)

1. Register User A → complete email OTP
2. Register User B → complete email OTP
3. Log in each user (password + login OTP) in separate browsers/profiles
4. Start chat from sidebar → establish encryption
5. Compare fingerprints out-of-band
6. Exchange messages; confirm ciphertext-only on server/DB
7. Optionally resend a captured `msg_id` to show replay rejection

**Email OTP:** with `EMAIL_DEV_MODE=true`, OTP is printed in the server console (and may appear in API for local testing). For real email, configure SMTP and set `EMAIL_DEV_MODE=false`.

Full API tables: `docs/SETUP_AND_API.md`.

---

## 9. Testing

```bash
python -m pytest tests/
```

`crypto_core` tests verify encryption/decryption round-trips and related helpers. Auth and chat flows are demonstrated manually via the two-browser demo above.

---

## 10. Contribution Summary (for CA_ONE marking)

### Mubashir — Security & encryption core

- Cryptographic design and threat model documentation
- `crypto_core` Python implementation and pytest coverage
- Algorithm selection rationale (ECDH, AES-GCM, fingerprint)
- Peer-system / vulnerability analysis contribution for the write-up

### Hamza — Backend server & deployment

- Flask-SocketIO relay and public-key directory
- MongoDB Atlas schema, indexes, ciphertext persistence
- bcrypt + JWT + OTP services, password reset, rate limiting
- ReplayGuard, security logging, CORS/headers, health endpoint
- Environment/config documentation and deployment ownership

### Kiran — Client & authentication

- Auth UI (register, login, OTP, forgot/reset password)
- Browser Web Crypto ECDH/AES wiring and fingerprint UI
- Chat UX (sidebar, presence, typing, receipts, history)
- Profile page and client-facing usability polish

---

## 11. Known Limitations

- Fingerprint verification is **manual**; the app does not force users to confirm before chatting.
- Browser runtime uses **P-256** Web Crypto; the Python `crypto_core` reference may use related curves for testing — docs should be read with that distinction in mind.
- No Signal-style double ratchet / full forward-secrecy protocol beyond per-session keys.
- Compromised client devices are out of scope for E2E guarantees.
- Cloud deployment may be demonstrated separately from local run instructions.

---

## 12. AI Assistance Statement

Parts of this project were developed with assistance from AI tools (including Cursor / Claude and ChatGPT), primarily for explaining cryptographic concepts, drafting boilerplate, and iterating UI/API structure. All AI-assisted work was reviewed, tested, and adapted by the group. Conversation links and logs are included in the AI assistance evidence submitted with this CA, as required by module guidelines.

---

## 13. Declaration

This submission is the work of the named group members for **B9IS129 Computer Systems Security (B9IS129_2526_TMD3), CA_ONE_(100%)**. Sources, libraries, and AI assistance are acknowledged. Secrets (MongoDB credentials, JWT secrets, SMTP App Passwords) are kept in `.env` and are **not** committed to the repository.

---

**Module:** B9IS129 — Computer Systems Security
**Assessment:** CA_ONE_(100%)
**Class:** B9IS129_2526_TMD3
**Project:** Secure Communication System
**Team:** Mubashir · Hamza · Kiran


### 14.1 Live demo links (if deployed)

- Frontend deployment URL
- Backend/API deployment URL
- Short note on expected startup latency (if free-tier hosting sleeps)

### 14.2 Deployment configuration summary

- Hosting platforms used (for example Render/Railway/Azure)
- Required environment variables per service
- Build/start commands used in production

### 14.3 Security verification evidence

- Short replay-attack test evidence (input, expected output)
- OTP/rate-limit behaviour evidence (`429` after threshold)
- Screenshot or note proving ciphertext-only storage in DB

### 14.4 Demo video and evidence links

- Viva/demo recording link
- Shared folder path for meeting minutes
- AI assistance log link

### 14.5 Future work roadmap

- Prioritised improvements (for example enforced fingerprint verification, key ratcheting, stronger session trust)
- Clear distinction between "nice-to-have" and "security-critical next steps"
