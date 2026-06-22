# Secure_Communication_System

CA One project for B9IS129 Computer Systems Security (DBS, Semester 2), under Paul Laird. Built by Mubashir, Hamza and Kiran.

## What this project actually does

The brief asks for a communications system where two people can message each other securely **without having met before to exchange keys**. That's the hard requirement - and it's the whole reason this project is built the way it is.

So here's the basic idea: when two users want to chat, their browsers each generate a key pair on the spot (using the Web Crypto API), exchange only the *public* part of that key through our server, and from that they each independently work out the same shared secret. Nobody had to meet up beforehand or share a password over the phone. This is done using ECDH (Elliptic Curve Diffie-Hellman, X25519 curve).

Once both sides have that shared secret, every message is encrypted with AES-256-GCM before it ever leaves the browser. The server in the middle only ever sees ciphertext - it relays messages between users but has no
way of reading them, even if someone broke into the server itself. The assignment calls this a "maliciously curious" server model, and that's exactly the assumption we built around: trust the server to deliver messages, don't trust it with the content.

## Why we picked this approach

We looked at a few options from the brief (PKI/HTTPS identity, social media identity, email/SMS identity, etc.) and went with what the brief calls "idiosyncratic identity verification" - basically, key fingerprint checking. After the key exchange happens, both users are shown a short fingerprint of the session key. If they want to be sure no one is sitting in the middle of their conversation (a MITM attack), they can read that fingerprint out to each other over a phone call or in person. If the two
fingerprints match, the connection is genuine. If they don't, someone has tampered with the exchange.

We picked this over something like email-based verification because it doesn't depend on trusting a third party (an email provider, a social media company, etc.) - it only depends on the two people involved actually checking the fingerprint, which fits the brief's requirement that the system shouldn't lean on a trusted third party it can't verify.

## How the pieces fit together

```
crypto_core/   - the actual cryptography: ECDH key exchange,
                 AES-256-GCM encrypt/decrypt, fingerprint generation
                 (Mubashir)

server/        - Flask + Socket.IO relay server. Handles login/register,
                 stores public keys so users can look each other up,
                 forwards encrypted messages, and blocks replay attacks
                 (Hamza)

client/        - the web app itself: login page, chat page, and the
                 JavaScript that does the actual key exchange and
                 encryption inside the browser
                 (Kiran)

tests/         - pytest tests for the crypto_core module, to check
                 encryption/decryption actually round-trips correctly
```

A simplified flow for one message:

1. Alice and Bob both register on the server with a username/password
   (passwords are salted and hashed with SHA-256 - never stored in
   plain text).
2. When Alice opens a chat with Bob, her browser generates an ECDH key
   pair and uploads only the public key to the server.
3. Her browser fetches Bob's public key from the server the same way.
4. Both browsers now derive the same AES-256 key locally - this key
   never touches the server.
5. Alice types a message → encrypted in her browser → sent to the
   server as ciphertext → server relays it to Bob → Bob's browser
   decrypts it locally.
6. If someone replays an old captured message back at the server, the
   server checks the message's unique ID against ones it's already
   seen in the last 5 minutes and drops the duplicate.

## Threat model / assumptions

This is straight from how we interpreted the assignment brief:

- The server is assumed to behave correctly (it won't deliberately
  corrupt the protocol) but **is not trusted with confidentiality** -
  it could be logging everything, and our design has to be safe even
  then.
- We are not protecting against an attacker who has already compromised
  one of the two end devices (that's outside what end-to-end encryption
  can ever promise).
- We are relying on users actually checking the fingerprint if they want
  protection against an active MITM during the *first* key exchange. If
  they skip that step, an attacker controlling the network at that exact
  moment could theoretically insert themselves - this is a known
  trade-off of trust-on-first-use type systems generally and we've noted
  it as a limitation rather than pretending it doesn't exist.

## Running it locally

```bash
python -m venv venv
venv\Scripts\activate          # (Windows) or source venv/bin/activate on Mac/Linux
pip install -r requirements.txt
```

Start the relay server:
```bash
python -m server.server
```

In a second terminal, start the client web app:
```bash
python client/app.py
```

Then open `http://localhost:3000` in a browser, register two test users,
log in as each one (e.g. two different browser tabs), and start a chat.

## Testing

Encryption module has pytest coverage:
```bash
python -m pytest tests/
```

## Who did what

- **Mubashir** - security/cryptography layer: ECDH key exchange, AES-256-GCM
  encryption, key fingerprinting, vulnerability analysis of the two
  assigned peer systems.
- **Hamza** - server: Flask-SocketIO relay, authentication, replay attack
  protection, cloud deployment.
- **Kiran** - client: web interface, browser-side encryption logic,
  documentation.

Group meetings were held over Zoom with captions enabled; recordings and
minutes are kept in our shared M365 folder along with links to AI
assistance logs, as required by the module submission guidelines.

## AI assistance

Parts of this project were built with help from Claude (Anthropic) and ChatGPT, mainly for explaining concepts (ECDH, AES-GCM modes, replay attack handling) and getting a first draft of some boilerplate code, which was then reviewed, tested, and in places rewritten by us. Full conversation links are included in the AI assistance log submitted alongside this repository, as required by the assignment guidelines.

## Known limitations / what we'd improve with more time

- Fingerprint verification is currently manual - relies on the user
  remembering to check it rather than the app enforcing it.
- User/key storage is a simple JSON file rather than a proper database;
  fine for a project of this scope but wouldn't scale.
- No forward secrecy beyond a single session - if a session key were
  ever compromised, only that session's messages would be exposed
  (past and future sessions use fresh keys), but we haven't implemented
  key ratcheting like Signal does.
