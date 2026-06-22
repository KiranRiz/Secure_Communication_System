# Design Specification
## Secure Communication System — B9IS129 CA One

### Functional Requirements
- FR1: Two users must be able to exchange encrypted messages
- FR2: Key exchange must work without prior meeting
- FR3: Users must register and login with credentials
- FR4: Messages must be relayed through a server
- FR5: Fingerprint verification must be available

### Non-Functional Requirements
- NFR1: All messages encrypted with AES-256-GCM
- NFR2: Server must never see plaintext messages
- NFR3: System must detect and block replay attacks
- NFR4: Passwords must never be stored in plain text

### Security Requirements
- SR1: ECDH X25519 for key exchange
- SR2: AES-256-GCM for message encryption
- SR3: SHA-256 with salt for password hashing
- SR4: UUID-based replay attack protection
- SR5: Key fingerprint for MITM prevention

### Threat Model
- Server is maliciously curious — cannot be trusted with content
- Network traffic may be intercepted
- Replay attacks must be blocked