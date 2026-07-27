"""Generate CA_ONE feature breakdown PDF for the group."""
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = Path(__file__).resolve().parent / "docs" / "CA_ONE_Feature_Breakdown_Group.pdf"
OUT.parent.mkdir(parents=True, exist_ok=True)

TEAL = colors.HexColor("#0f766e")
DARK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#475569")
LIGHT = colors.HexColor("#f1f5f9")
ACCENT = colors.HexColor("#14b8a6")


def styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "t",
            parent=base["Title"],
            fontSize=20,
            textColor=DARK,
            spaceAfter=6,
            leading=24,
        ),
        "sub": ParagraphStyle(
            "s",
            parent=base["Normal"],
            fontSize=10,
            textColor=MUTED,
            alignment=TA_CENTER,
            spaceAfter=16,
            leading=14,
        ),
        "h1": ParagraphStyle(
            "h1",
            parent=base["Heading1"],
            fontSize=14,
            textColor=TEAL,
            spaceBefore=14,
            spaceAfter=8,
            leading=18,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontSize=11.5,
            textColor=DARK,
            spaceBefore=10,
            spaceAfter=6,
            leading=15,
        ),
        "body": ParagraphStyle(
            "b",
            parent=base["Normal"],
            fontSize=9.5,
            textColor=DARK,
            leading=13,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
        ),
        "bullet": ParagraphStyle(
            "bu",
            parent=base["Normal"],
            fontSize=9.5,
            textColor=DARK,
            leading=13,
            leftIndent=4,
        ),
        "small": ParagraphStyle(
            "sm",
            parent=base["Normal"],
            fontSize=8.5,
            textColor=MUTED,
            leading=11,
            spaceAfter=4,
        ),
        "cell": ParagraphStyle(
            "c",
            parent=base["Normal"],
            fontSize=8.5,
            textColor=DARK,
            leading=11,
        ),
        "cell_h": ParagraphStyle(
            "ch",
            parent=base["Normal"],
            fontSize=8.5,
            textColor=colors.white,
            leading=11,
            fontName="Helvetica-Bold",
        ),
    }


def bullets(items, st):
    return ListFlowable(
        [ListItem(Paragraph(i, st["bullet"]), leftIndent=8, bulletColor=TEAL) for i in items],
        bulletType="bullet",
        start="•",
        leftIndent=12,
        bulletFontSize=9,
    )


def table(rows, col_widths):
    data = []
    for r_i, row in enumerate(rows):
        data.append(
            [
                Paragraph(str(c), styles()["cell_h" if r_i == 0 else "cell"])
                for c in row
            ]
        )
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), TEAL),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, -1), LIGHT),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ]
        )
    )
    return t


def build():
    st = styles()
    story = []

    story.append(Paragraph("Secure Communication System", st["title"]))
    story.append(
        Paragraph(
            "CA One (B9IS129) — Complete Feature Breakdown for Group Members<br/>"
            "Mubashir (Security &amp; Crypto) · Hamza (Server &amp; Deployment) · Kiran (Client &amp; Auth UI)",
            st["sub"],
        )
    )

    story.append(Paragraph("1. Purpose of this document", st["h1"]))
    story.append(
        Paragraph(
            "This PDF summarises everything implemented in the project so far: original CA_ONE "
            "security requirements plus later enhancements (MongoDB Atlas, JWT, OTP, chat UI, etc.). "
            "Use it to align ownership, prepare the report/viva, and avoid duplicated work.",
            st["body"],
        )
    )

    story.append(Paragraph("2. Group ownership (agreed split)", st["h1"]))
    story.append(
        table(
            [
                ["Member", "Primary responsibility", "Main folders / areas"],
                [
                    "Mubashir",
                    "Security & encryption core, threat model, crypto docs/tests",
                    "crypto_core/, docs/security_*, tests/",
                ],
                [
                    "Hamza",
                    "Backend relay server, MongoDB, JWT APIs, Socket.IO, deployment",
                    "server/, .env.example, deployment config",
                ],
                [
                    "Kiran",
                    "Client UI, browser crypto wiring, auth screens, chat UX",
                    "client/, templates, static JS/CSS",
                ],
            ],
            [2.6 * cm, 7.2 * cm, 7.0 * cm],
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Note: Some features cross boundaries (e.g. OTP needs server + client). "
            "The tables below mark Primary owner and Supporting owner.",
            st["small"],
        )
    )

    story.append(Paragraph("3. Original CA_ONE core features (must-have)", st["h1"]))
    story.append(
        table(
            [
                ["Feature", "What it does", "Primary", "Support"],
                [
                    "ECDH key exchange (no prior meeting)",
                    "Browsers derive a shared secret from public keys via the relay server.",
                    "Mubashir / Kiran",
                    "Hamza (store/fetch keys)",
                ],
                [
                    "AES-256-GCM message encryption",
                    "Messages encrypted in browser; server only relays ciphertext.",
                    "Mubashir / Kiran",
                    "Hamza (relay)",
                ],
                [
                    "Maliciously curious server model",
                    "Server cannot read plaintext; designed as untrusted for confidentiality.",
                    "Mubashir",
                    "All",
                ],
                [
                    "Public key directory",
                    "POST /store_key + GET /get_key for peer public keys.",
                    "Hamza",
                    "Kiran",
                ],
                [
                    "Real-time relay (Socket.IO)",
                    "send_message → receive_message between users.",
                    "Hamza",
                    "Kiran",
                ],
                [
                    "Replay attack protection",
                    "Unique msg_id + 5-minute seen-ID window (ReplayGuard).",
                    "Hamza",
                    "Mubashir (threat analysis)",
                ],
                [
                    "Key fingerprint UI",
                    "Out-of-band MITM check after session establish.",
                    "Kiran",
                    "Mubashir",
                ],
                [
                    "Register / Login (baseline)",
                    "User accounts before chat.",
                    "Hamza / Kiran",
                    "—",
                ],
                [
                    "crypto_core Python module",
                    "Reference ECDH/AES/fingerprint + pytest round-trip.",
                    "Mubashir",
                    "—",
                ],
                [
                    "Architecture / design docs",
                    "README + docs/ design, architecture, security requirements.",
                    "All",
                    "Kiran (client docs)",
                ],
            ],
            [4.0 * cm, 7.6 * cm, 3.0 * cm, 2.2 * cm],
        )
    )

    story.append(Paragraph("4. Enhanced features added later (extensions)", st["h1"]))
    story.append(
        Paragraph(
            "These go beyond the minimum brief and strengthen security, usability, and deployability.",
            st["body"],
        )
    )

    story.append(Paragraph("4.1 Backend / server / data (Hamza primary)", st["h2"]))
    story.append(
        bullets(
            [
                "<b>MongoDB Atlas integration</b> — database <i>Secure_Communication</i>; collections: users, otps, sessions, password_resets, messages, security_logs (+ indexes/TTL).",
                "<b>Environment secrets</b> — .env / .env.example; no hardcoded DB credentials or JWT secrets in source.",
                "<b>AuthManager on MongoDB</b> — register/login/profile/password reset backed by Atlas (replaced users.json for new accounts).",
                "<b>bcrypt password hashing</b> — replaces plain SHA-256; password complexity rules (8+, upper/lower/digit).",
                "<b>JWT access tokens + refresh token rotation</b> — short-lived access JWT; hashed refresh tokens in sessions collection.",
                "<b>Protected REST + Socket.IO</b> — Bearer JWT required for keys/profile/messages; socket identity from JWT (not spoofable username alone).",
                "<b>Email OTP service</b> — 6-digit OTP, hashed at rest, 5 min expiry, 60s resend, max 3 attempts, one-time use; Gmail SMTP support + EMAIL_DEV_MODE.",
                "<b>Login OTP (2FA step)</b> — after password OK, login completes only after email OTP verification.",
                "<b>Registration email verification OTP</b> — account must verify email before full login.",
                "<b>Forgot / reset password</b> — hashed reset tokens, expiry, email link to reset page.",
                "<b>Rate limiting</b> — flask-limiter ~5/min on auth endpoints → HTTP 429 + security log.",
                "<b>Security audit logs</b> — login/logout/fail/OTP/reset/rate-limit/replay events with IP/UA/time.",
                "<b>Message persistence (ciphertext only)</b> — history stored without plaintext; soft delete/edit ciphertext APIs.",
                "<b>Conversations API</b> — GET /conversations for sidebar chat list + online flags.",
                "<b>User lookup API</b> — GET /lookup/&lt;username&gt; distinguishes user_not_found vs key_missing (stops endless polling).",
                "<b>CORS lockdown + Talisman headers</b> — restricted origins; security headers (local HTTP-friendly).",
                "<b>Health check</b> — GET /health (Mongo ping).",
                "<b>Docs for setup/API</b> — docs/SETUP_AND_API.md.",
            ],
            st,
        )
    )

    story.append(Paragraph("4.2 Client / UI / auth UX (Kiran primary)", st["h2"]))
    story.append(
        bullets(
            [
                "<b>Modern auth page</b> — Login/Register tabs only; Forgot password as link; OTP as step screen.",
                "<b>Resend OTP cooldown UI</b> — button disabled 60 seconds with countdown.",
                "<b>Button loading locks</b> — disable while API in flight (login/register/OTP/forgot).",
                "<b>JWT session in localStorage</b> — access/refresh tokens; redirect to chat after login OTP.",
                "<b>WhatsApp-style chat layout</b> — left sidebar (profile + chat list), right conversation pane.",
                "<b>Conversation list + search + new chat</b> — previous chats, online dots, start chat by username.",
                "<b>Persistent browser ECDH/AES keys</b> — survive refresh so history can decrypt again.",
                "<b>Typing indicators, presence, read/delivery status</b> — Socket.IO events wired in UI.",
                "<b>Loaders &amp; skeletons</b> — app connect, sidebar, messages, profile page skeletons.",
                "<b>Unregistered user handling</b> — lookup before open chat; clear error state; no infinite get_key loop.",
                "<b>Modern profile page</b> — live avatar preview, sections, validation hints, danger zone.",
                "<b>Avatar images</b> — direct image URL rendering with fallback initials.",
                "<b>Logout confirmation modal</b> — Cancel / Log out dialog before signing out.",
                "<b>Establish encryption control</b> — manual ECDH retry if peer key not ready.",
            ],
            st,
        )
    )

    story.append(Paragraph("4.3 Security / crypto (Mubashir primary)", st["h2"]))
    story.append(
        bullets(
            [
                "<b>Threat model documentation</b> — maliciously curious server; what server can/cannot see.",
                "<b>crypto_core algorithms</b> — ECDH, AES-GCM, fingerprint helpers + pytest.",
                "<b>Algorithm justification</b> — why GCM, why ECDH, why fingerprint MITM check.",
                "<b>Security requirements &amp; design specs</b> — docs used for CA_ONE write-up.",
                "<b>Review of applied controls</b> — bcrypt, JWT, OTP, rate limit, replay, ciphertext storage (coordinate with Hamza).",
                "<b>Known limitations to document</b> — fingerprint is manual; browser uses P-256 Web Crypto (align docs if README still says X25519); no Signal-style ratcheting.",
            ],
            st,
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("5. Main API surface (Hamza / Kiran integration)", st["h1"]))
    story.append(
        table(
            [
                ["Area", "Endpoints / events", "Auth"],
                [
                    "Auth",
                    "/register, /verify-otp, /resend-otp, /login, /refresh, /logout, /forgot-password, /reset-password",
                    "Mixed (JWT on logout)",
                ],
                [
                    "Keys",
                    "/store_key, /get_key/&lt;user&gt;, /lookup/&lt;user&gt;",
                    "JWT",
                ],
                [
                    "Profile",
                    "GET/PUT /profile, GET /profile/&lt;user&gt;, /change-password, DELETE /account",
                    "JWT",
                ],
                [
                    "Chat data",
                    "/conversations, /messages/&lt;peer&gt;, message edit/delete/search",
                    "JWT",
                ],
                [
                    "Socket.IO",
                    "connect(auth.token), join, send_message, receive_message, typing, presence, message_status, message_read",
                    "JWT on connect",
                ],
            ],
            [3.2 * cm, 11.0 * cm, 2.6 * cm],
        )
    )

    story.append(Paragraph("6. Suggested ownership for remaining CA_ONE work", st["h1"]))
    story.append(
        table(
            [
                ["Task", "Owner", "Why"],
                [
                    "Update README/docs: P-256 vs X25519, bcrypt (not SHA-256), OTP/JWT",
                    "Mubashir + Hamza",
                    "Markers check consistency",
                ],
                [
                    "Demo script (2 browsers): register→OTP→login OTP→chat→fingerprint→replay",
                    "All (Kiran leads UI demo)",
                    "Viva / marking demo",
                ],
                [
                    "Cloud deployment (Render/Azure/Railway) + HTTPS notes",
                    "Hamza",
                    "NFR deployment",
                ],
                [
                    "crypto_core tests green + short security test evidence",
                    "Mubashir",
                    "Security ownership",
                ],
                [
                    "Client polish + screenshots for report",
                    "Kiran",
                    "UI ownership",
                ],
                [
                    "Group report sections + AI assistance log links",
                    "All",
                    "Submission requirement",
                ],
            ],
            [8.2 * cm, 4.0 * cm, 4.6 * cm],
        )
    )

    story.append(Paragraph("7. What is enough vs optional for marks", st["h1"]))
    story.append(
        Paragraph(
            "<b>Already enough for the brief:</b> E2E chat without prior key meeting, untrusted relay server, "
            "identity approach, replay protection, docs, team split.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Extensions already done (bonus strength):</b> MongoDB, bcrypt, JWT, OTP (register+login), "
            "rate limiting, audit logs, ciphertext history, modern UI.",
            st["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Do not prioritise for CA_ONE unless spare time:</b> groups, file sharing, video, admin dashboards. "
            "They add little security marks compared to clean docs + demo.",
            st["body"],
        )
    )

    story.append(Paragraph("8. Key project paths", st["h1"]))
    story.append(
        bullets(
            [
                "Project root: <b>C:\\Users\\Supreme_traders\\Projects\\Secure_Communication_System</b>",
                "Server run: <b>python -m server.server</b> (port 5000)",
                "Client run: <b>python client/app.py</b> (port 3000)",
                "Setup/API doc: <b>docs/SETUP_AND_API.md</b>",
                "This PDF: <b>docs/CA_ONE_Feature_Breakdown_Group.pdf</b>",
            ],
            st,
        )
    )

    story.append(Spacer(1, 12))
    story.append(
        Paragraph(
            "Prepared for group sharing — Secure Communication System (CA One). "
            "Keep secrets in .env only; never commit MongoDB passwords or Gmail App Passwords to GitHub.",
            st["small"],
        )
    )

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title="CA_ONE Feature Breakdown — Secure Communication System",
        author="Secure Communication System Group",
    )
    doc.build(story)
    print(OUT)


if __name__ == "__main__":
    build()
