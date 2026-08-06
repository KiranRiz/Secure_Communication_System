# Secure Communication System

**Live application:** https://100.60.238.30.sslip.io

## Group Members
| Name | Role & Responsibilities |
|---|---|
| Mubashir | Security & encryption core — crypto_core/, threat model, algorithm justification, security docs & tests |
| Hamza | Backend server — server/, MongoDB Atlas, JWT/OTP APIs, Socket.IO relay, replay protection |
| Kiran | Client, authentication UI & cloud deployment — client/, browser ECDH/AES (Web Crypto), auth screens, chat UX, AWS deployment, Dockerization, HTTPS setup, user docs |

---

## Updates — Peer Vulnerability Fixes

Following peer penetration testing (StudySafe Vulnerability Analysis, August 2026), the issues below were remediated **without removing features or redesigning the UI**. Full write-up: [`docs/Vulnerability_Remediation_Report.md`](docs/Vulnerability_Remediation_Report.md).

| ID | Finding | Severity | Fix applied |
|---|---|---|---|
| 1.1 | Private ECDH keys stored in `localStorage` (extractable JWK) | Critical / High | Private keys stored as **non-extractable** `CryptoKey` objects in **IndexedDB** only; legacy `localStorage` key material cleared |
| 1.2 | Derived AES session keys stored in `localStorage` | High | AES-256-GCM keys kept **in memory only** (`extractable: false`); no raw AES hex persisted to disk |
| 1.3 | Fingerprint verification optional — users could chat without confirming | High | **Send blocked** until user confirms peer fingerprint out-of-band; peer key change requires re-verification (TOFU) |
| 1.4 | ReplayGuard held seen `msg_id`s in process memory only | Medium–High | Seen IDs persisted in **MongoDB** (`replay_ids`) with **unique + TTL** indexes (5-minute window; survives restarts) |
| 1.5 | Registration revealed “username already exists” / “email already registered” | Medium | **Generic** registration conflict message; no account enumeration via distinct errors |

**Also addressed during hardening:** Socket.IO `eventlet` compatibility on Python 3.14 (`async_mode` fallback), and local demo `SERVER_URL` corrected to localhost when a stale LAN IP caused “Server not reachable”.

---

## 1. Project Overview

This Continuous Assessment (CA_ONE) delivers an end-to-end encrypted messaging system in which two users who have never previously met to exchange keys can communicate securely through an untrusted relay server.

Clients perform ECDH (P-256) key agreement and AES-256-GCM message encryption in the browser via the Web Crypto API. The Flask + Socket.IO server stores public keys, authenticates users, and relays ciphertext only. It is designed under a **maliciously curious server** threat model: the server is trusted to deliver messages, but must not be able to read message content.

Identity is supported by email OTP verification plus out-of-band key fingerprint checking (TOFU-style MITM detection). Additional hardening includes bcrypt password hashing, JWT access/refresh sessions, rate limiting, replay protection, ciphertext persistence, and security audit logs.

The application is deployed live on AWS EC2 with Docker containerization and HTTPS — see the [Deployment](#10-deployment-aws-cloud) section.

---

## 2. Assessment Brief Alignment

| Brief requirement | How this project meets it |
|---|---|
| Secure messaging without prior key meeting | Browser ECDH key exchange via public-key directory |
| Untrusted / maliciously curious server | AES-GCM encryption client-side; server sees only ciphertext |
| Identity approach | Email OTP + human-readable session fingerprint |
| Replay resistance | Unique msg_id + 5-minute ReplayGuard window |
| Documented, testable design | README, docs/, crypto_core pytest suite |
| Team ownership split | Crypto / server / client + deployment owned by named members |
| No security through obscurity | Standard algorithms (ECDH, AES-GCM, bcrypt, JWT) |

---

## 3. Project Objectives

- Enable real-time encrypted chat between two registered users
- Establish a shared session key without pre-shared passwords between peers
- Ensure the relay server cannot decrypt message payloads
- Authenticate users and protect accounts (hashing, OTP, JWT, rate limits)
- Detect or discourage MITM during first key exchange via fingerprint comparison
- Block simple replay of captured ciphertext messages at the relay
- Deploy the system to a publicly reachable, HTTPS-secured cloud environment
- Provide clear architecture, security, and setup documentation for markers and peers

---

## 4. System Architecture

**Runtime split**

| Layer | Technology | Role |
|---|---|---|
| Client UI | Flask templates + JS/CSS (`client/`) | Auth UX, chat UI, Web Crypto |
| Relay API | Flask + Flask-SocketIO (`server/`) | REST + real-time events |
| Database | MongoDB Atlas (`Secure_Communication`) | Users, OTP, sessions, ciphertext, logs |
| Crypto reference | Python `crypto_core/` | Algorithm reference + automated tests |
| Reverse proxy | Nginx | HTTPS termination, routing to client/server containers |
| Containerization | Docker + Docker Compose | Isolated, reproducible client/server runtime |

---

## 5. Data Requirements & Storage

### 5.1 Storage choice — MongoDB Atlas

MongoDB Atlas (cloud-hosted MongoDB) was chosen because:

- Data is naturally document-shaped (users, sessions, messages) rather than strictly relational
- Managed hosting removes the need to provision and secure a self-hosted database server
- Built-in encryption at rest and network-level access controls (IP allowlisting) support the assessment's security requirements
- Flexible schema suits fields that evolve during development (e.g. OTP fields, session metadata)

### 5.2 Entities & Fields

| Entity | Key Fields | Notes |
|---|---|---|
| Users | username, email, password_hash, public_key, created_at, is_deleted | password_hash via bcrypt; public_key is the ECDH public key for the directory |
| OTPs | username/email, otp_hash, purpose (register/login/reset), expires_at, attempts | Hashed, time-limited, attempt-limited |
| Sessions / Refresh Tokens | username, refresh_token_hash, issued_at, expires_at | Supports JWT access/refresh rotation |
| Messages | msg_id, sender, recipient, ciphertext, nonce, timestamp, read_status | Server stores ciphertext only — never plaintext |
| Security Logs | event_type, ip, user_agent, path, timestamp | Powers rate-limit and abuse auditing |

---

## 6. Security Design

### 6.1 Threat model

| Assumption | Implication |
|---|---|
| Server is honest in protocol execution but curious | May log all traffic; design must keep plaintext off-server |
| Network may be observed or actively attacked | Need authenticated encryption + MITM detection option |
| End devices are not fully compromised | E2E encryption cannot protect a compromised browser |
| Users may skip fingerprint check | TOFU risk acknowledged as a documented limitation |

### 6.2 Cryptographic controls

| Control | Algorithm / mechanism | Where |
|---|---|---|
| Peer key agreement | ECDH P-256 (Web Crypto) | Browser (`client/static/chat.js`) |
| Message confidentiality + integrity | AES-256-GCM (fresh nonce per message) | Browser |
| Password storage | bcrypt | Server (`server/auth.py`) |
| Session auth | JWT access + hashed refresh rotation | Server |
| Email verification / login step-up | 6-digit OTP (hashed, TTL, attempt limits) | Server + email |
| Replay protection | UUID msg_id + 5-minute seen set | `server/replay_guard.py` |
| MITM awareness | Session key fingerprint shown in UI | Client |
| Auth abuse resistance | Rate limit (~5/min on auth) | flask-limiter |
| Transport hardening (app layer) | CORS lockdown, security headers (Talisman) | Server |
| Transport hardening (network layer) | HTTPS via Let's Encrypt, single-device session enforcement | Nginx + Server |

### 6.3 What the server can and cannot see

**Can see:** usernames, emails (account data), public ECDH keys, metadata (who messaged whom, approximate size/time), ciphertext blobs.

**Cannot see:** private keys, shared ECDH secrets, plaintext message content.

---

## 7. Functional Features

### 7.1 Core CA_ONE features
- User registration and login
- Public key store/fetch (`/store_key`, `/get_key`)
- ECDH session establishment without prior meeting
- Real-time encrypted messaging over Socket.IO
- Key fingerprint display for out-of-band verification
- Replay attack rejection on duplicate message IDs

### 7.2 Security & account enhancements
- MongoDB Atlas persistence (users, OTPs, sessions, messages, security logs)
- Email OTP for registration verification
- Login OTP step (password then email code)
- Password reset via emailed one-time token
- JWT-protected REST and Socket.IO identity
- Rate limiting and security audit logging
- Single-device session enforcement (new login disconnects older sessions)
- Profile update, change password, soft-delete account

### 7.3 Client / UX features
- Modern Login / Register / OTP / Forgot-password flows
- WhatsApp-style sidebar (conversations, search, new chat)
- Typing indicators, presence, delivery/read status
- Ciphertext message history load (decryptable when keys persist)
- Profile page with avatar URL support
- Loaders/skeletons and logout confirmation

---

## 8. Repository Structure
Secure_Communication_System/
├── crypto_core/ # Mubashir — ECDH / AES-GCM / fingerprint (Python)
├── server/ # Hamza & Kiran — Flask API, Socket.IO, auth, MongoDB, Dockerfile
├── client/ # Kiran — UI templates, static JS/CSS, client app, Dockerfile
├── tests/ # pytest for crypto_core
├── docs/ # Architecture, security, setup/API, feature PDF
├── docker-compose.yml # Kiran — orchestrates client + server containers
├── .env.example # Required environment variables (no secrets)
├── requirements.txt
└── README.md # This CA_ONE report overview

**Supporting docs**

| Document | Purpose |
| `docs/security_requirements.md` | Security rationale (Mubashir) |
| `docs/system_architecture.md` | Architecture narrative |
| `docs/design_specification.md` | FR / NFR / SR tables |
| `docs/SETUP_AND_API.md` | Env, schema, API & Socket.IO reference |
| `docs/CA_ONE_Feature_Breakdown_Group.pdf` | Feature ownership PDF for the group |

---

## 9. How to Run (Local)

### Prerequisites
- Python 3.10+ recommended
- MongoDB Atlas connection string
- (Optional) Gmail App Password for real OTP email

### Setup
1. Copy `.env.example` to `.env` and set at least `MONGODB_URI`, `SECRET_KEY`, `JWT_SECRET`
2. Install dependencies:
- python -m venv venv
- venv\Scripts\activate # Windows
- pip install -r requirements.txt

3. Start the relay server (port 5000): `python -m server.server`
4. In a second terminal, start the client UI (port 3000): `python client/app.py`
5. Open http://localhost:3000

---

## 10. Deployment (AWS Cloud)

The application is deployed to a live, publicly reachable environment on AWS, containerized with Docker and secured with HTTPS.

### 10.1 Deployment architecture

- **Cloud provider:** AWS EC2 (Ubuntu 26.04 LTS, t3.micro)
- **Static addressing:** AWS Elastic IP, so the public IP never changes across instance restarts
- **Containerization:** Docker + Docker Compose — separate containers for `client` (port 3000) and `server` (port 5000), each with its own Dockerfile
- **Reverse proxy:** Nginx routes all incoming traffic to the correct container and handles WebSocket upgrade headers for Socket.IO
- **HTTPS:** Free TLS certificate issued via Let's Encrypt (Certbot), using an sslip.io hostname mapped to the Elastic IP, since the project does not use a purchased domain
- **Process management:** Containers run in detached mode (`docker compose up -d`) so the application stays up independently of any active SSH session


### 10.2 Deployment Challenges & Fixes

| # | Challenge | Fix |
|---|---|---|
| 1 | Client couldn't reach server ("Server not reachable") | Set correct `SERVER_URL` in `.env` (Docker's "localhost" pointed to the wrong container) |
| 2 | Login worked but kept returning to login screen | Added deployed URL to `CORS_ORIGINS` and `CLIENT_URL` (server only allowed `localhost` origin) |
| 3 | Chat stuck on "Reconnecting…" forever | Added `eventlet` and set `async_mode="eventlet"` on SocketIO (Flask's default server lacks real WebSocket support) |
| 4 | Encryption failed with `importKey` undefined | Installed Nginx + Certbot and served app over free HTTPS via sslip.io (Web Crypto needs HTTPS or localhost) |
| 5 | WebSocket handshake returned HTTP 400 (even over HTTPS) | Reordered client transports to `["polling", "websocket"]` (was skipping the required polling handshake) |
| 6 | `/store_key` and `/get_key` failed with invalid JSON (HTML 404) | Added dedicated Nginx `location` blocks for both endpoints (Nginx wasn't routing them to the backend) |
| 7 | Same user on two browsers caused "Decryption failed" errors | Added single-device session enforcement — new login force-disconnects any existing session |

## 11. Contribution Summary

**Mubashir — Security & encryption core**
- Cryptographic design and threat model documentation
- crypto_core Python implementation and pytest coverage
- Algorithm selection rationale (ECDH, AES-GCM, fingerprint)
- Peer-system / vulnerability analysis contribution for the write-up

**Hamza — Backend server**
- Flask-SocketIO relay and public-key directory
- MongoDB Atlas schema, indexes, ciphertext persistence
- bcrypt + JWT + OTP services, password reset, rate limiting
- ReplayGuard, security logging, CORS/headers, health endpoint

**Kiran — Client, authentication & cloud deployment**
- Auth UI (register, login, OTP, forgot/reset password)
- Browser Web Crypto ECDH/AES wiring and fingerprint UI
- Chat UX (sidebar, presence, typing, receipts, history)
- Profile page and client-facing usability polish
- End-to-end AWS deployment: EC2 provisioning, Elastic IP, security groups
- Dockerized the client and server (Dockerfiles + docker-compose.yml)
- Configured Nginx reverse proxy and obtained/installed a free HTTPS certificate
- Diagnosed and resolved all deployment-stage bugs listed in Section 10.3, including a server-side single-device session fix

---

## 12. Known Limitations

- Fingerprint verification is enforced before messaging (compare out-of-band, then confirm in UI); a peer key change requires re-verification
- Browser runtime uses P-256 Web Crypto; the Python crypto_core reference may use related curves for testing — docs should be read with that distinction in mind
- No Signal-style double ratchet / full forward-secrecy protocol beyond per-session keys — messages sent while a peer is offline can fail to decrypt if the session key is re-established before that peer reads them
- Compromised client devices are out of scope for E2E guarantees

---

## 13. Learning Resources

- [MDN Web Docs — Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Flask-SocketIO documentation](https://flask-socketio.readthedocs.io/)
- [MongoDB Atlas documentation](https://www.mongodb.com/docs/atlas/)
- [Let's Encrypt / Certbot documentation](https://certbot.eff.org/)
- [Docker Compose documentation](https://docs.docker.com/compose/)
- [OWASP Cheat Sheet Series — Authentication & Session Management](https://cheatsheetseries.owasp.org/)

---

## 14. AI Assistance Statement

Parts of this project were developed with assistance from AI tools (including Cursor / Claude and ChatGPT), primarily for explaining cryptographic concepts, drafting boilerplate, iterating UI/API structure, and troubleshooting the AWS/Docker/Nginx deployment pipeline. All AI-assisted work was reviewed, tested, and adapted by the group. Conversation links and logs are included in the AI assistance evidence submitted with this CA, as required by module guidelines.
