# Design Specification
## B9IS129 CA One — Secure Communication System
### Group: Mubashir, Hamza, Kiran

---

## Functional Requirements

| ID | Requirement | Implementation |
|----|-------------|----------------|
| FR1 | Two users must exchange encrypted messages | AES-256-GCM |
| FR2 | Key exchange without prior meeting | ECDH P-256 |
| FR3 | Users must register with username + email | server/auth.py |
| FR4 | Users must login before chatting | Flask /login endpoint |
| FR5 | Messages relayed through server | Flask-SocketIO |
| FR6 | Real-time message delivery | Socket.IO events |
| FR7 | Key fingerprint displayed after exchange | chat.js |

---

## Non-Functional Requirements

| ID | Requirement | Implementation |
|----|-------------|----------------|
| NFR1 | Server cannot read messages | Encryption client-side |
| NFR2 | Passwords never stored in plain text | SHA-256 + salt |
| NFR3 | Replay attacks must be blocked | UUID + 5 min window |
| NFR4 | No secret algorithms used | All NIST standards |
| NFR5 | System documented for other developers | README + docs/ |
| NFR6 | Cloud deployment | Render/Azure |

---

## Security Requirements

| ID | Requirement | Algorithm | Reason |
|----|-------------|-----------|--------|
| SR1 | Key exchange | ECDH P-256 | No prior meeting needed |
| SR2 | Message encryption | AES-256-GCM | Confidentiality + integrity |
| SR3 | Key derivation | HKDF-SHA256 | Proper key stretching |
| SR4 | Password storage | SHA-256 + salt | Prevent rainbow tables |
| SR5 | Replay protection | UUID tracking | Block captured messages |
| SR6 | MITM prevention | Key fingerprint | Out-of-band verification |

---

## Identity Verification Approach

We use a combination of two methods:

**Method 1 — Email-based identity**
Users register with an email address. This ties their account to a real-world identity that can
be verified independently. The email is stored server-side but never exposed to other users.

**Method 2 — Key fingerprint verification**
After ECDH key exchange, both users see a fingerprint of their session key. Verifying
this fingerprint via phone/in-person confirms no MITM attack occurred during key exchange.

This satisfies the assignment requirement: "Communications channel based identity" (email)
combined with "Idiosyncratic identity verification" (fingerprint).

---

## Threat Model

| Threat | Mitigation |
|--------|------------|
| Server reads messages | AES-256-GCM client-side encryption |
| MITM during key exchange | Key fingerprint verification |
| Replay attack | UUID + 5 minute window |
| Password theft | SHA-256 + unique salt per user |
| Weak keys | ECDH P-256 — 128-bit security level |