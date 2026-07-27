# MongoDB Schema, API Docs & Setup

## Database

- **Name:** `Secure_Communication` (isolated from Job_Portal)
- **Cluster:** MongoDB Atlas (`MONGODB_URI` in `.env`)

### Collections

| Collection | Purpose | Key indexes |
|------------|---------|-------------|
| `users` | Accounts, bcrypt hashes, profile, public ECDH key | unique `username`, unique sparse `email` |
| `otps` | Hashed OTPs, attempts, expiry | `email`, TTL on `expires_at` |
| `sessions` | Hashed refresh tokens (rotation) | unique `token_hash`, TTL on `expires_at` |
| `password_resets` | One-time reset tokens | unique `token_hash`, TTL |
| `messages` | Ciphertext-only chat history | unique `msg_id`, `conversation_id+created_at` |
| `security_logs` | Auth / OTP / rate-limit audit trail | `created_at`, `event_type`, `ip` |

Messages store **only** `{nonce, ciphertext}` — plaintext never touches MongoDB.

---

## Environment

Copy `.env.example` → `.env` and fill values. Never commit `.env`.

Required:
- `MONGODB_URI`
- `SECRET_KEY`
- `JWT_SECRET`

Email OTP:
- Set `EMAIL_DEV_MODE=true` to print OTP in server console (and return `dev_otp` in API for local testing).
- For real email: set SMTP_* and `EMAIL_DEV_MODE=false`.

---

## Installation

```powershell
cd C:\Users\Supreme_traders\Projects\Secure_Communication_System
py -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

Terminal 1 — relay server:
```powershell
.\venv\Scripts\python.exe -m server.server
```

Terminal 2 — UI:
```powershell
.\venv\Scripts\python.exe client\app.py
```

Open http://localhost:3000

---

## API Endpoints (server :5000)

### Auth (rate limited: 5/min/IP)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/register` | No | Create user + send OTP |
| POST | `/verify-otp` | No | Verify email OTP |
| POST | `/resend-otp` | No | Resend OTP (60s cooldown) |
| POST | `/login` | No | Returns access + refresh JWT |
| POST | `/refresh` | No | Rotate refresh token |
| POST | `/logout` | Bearer | Revoke refresh token |
| POST | `/forgot-password` | No | Email reset link |
| POST | `/reset-password` | No | Set new password with token |

### Keys / Profile
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/store_key` | Bearer | Store own ECDH public key |
| GET | `/get_key/<user>` | Bearer | Fetch peer public key |
| GET | `/profile` | Bearer | Own profile |
| PUT | `/profile` | Bearer | Update profile |
| GET | `/profile/<user>` | Bearer | View profile |
| POST | `/change-password` | Bearer | Change password |
| DELETE | `/account` | Bearer | Soft-delete account |

### Messages
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/messages/<peer>` | Bearer | Conversation history (ciphertext) |
| GET | `/messages/search?q=` | Bearer | Metadata search |
| PUT | `/messages/<msg_id>` | Bearer | Edit ciphertext |
| DELETE | `/messages/<msg_id>` | Bearer | Soft-delete for self |

### Socket.IO (auth via `auth: { token }`)
| Event | Direction | Purpose |
|-------|-----------|---------|
| `connect` | c→s | JWT required |
| `join` | c→s | Join own room (JWT identity) |
| `send_message` | c→s | Relay + persist ciphertext |
| `receive_message` | s→c | Deliver ciphertext |
| `typing` | both | Typing indicator |
| `presence` | s→c | online/offline |
| `message_status` | s→c | sent/delivered/read |
| `message_read` | c→s | Mark read |

Client UI proxies many routes under `/api/*` on port 3000.

---

## Security improvements summary

1. MongoDB Atlas persistence (no `users.json` for new accounts)
2. bcrypt password hashing (replaces SHA-256)
3. JWT access tokens (15 min) + refresh token rotation
4. Protected REST + Socket.IO identity bound to JWT
5. Email OTP (5 min expiry, 60s resend, 3 attempts, hashed, one-time)
6. Rate limit 5/min on auth endpoints → HTTP 429
7. CORS locked to client origins; Talisman security headers
8. Password complexity (8+, upper/lower/digit)
9. Security audit logs collection
10. Ciphertext-only message persistence + receipts / presence / typing
11. Forgot/reset password with hashed, expiring tokens
12. Secrets via `.env` only

---

## Files created / modified

### Created
- `.env` (local only), `.env.example`
- `server/config.py`, `server/db.py`, `server/security_utils.py`
- `server/security_logger.py`, `server/email_service.py`, `server/otp_service.py`
- `server/messages.py`
- `client/templates/reset_password.html`, `client/templates/profile.html`
- `docs/SETUP_AND_API.md` (this file)

### Modified
- `server/auth.py`, `server/server.py`
- `client/app.py`, `client/templates/index.html`, `client/templates/chat.html`
- `client/static/chat.js`, `requirements.txt`
