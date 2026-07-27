# server/email_service.py
# Send OTP / password-reset emails (SMTP or console in dev mode)

import smtplib
from email.message import EmailMessage

from server.config import Config


def send_email(to_email: str, subject: str, body: str) -> bool:
    """Send email via SMTP. In EMAIL_DEV_MODE, print to console instead."""
    if Config.EMAIL_DEV_MODE or not Config.SMTP_HOST:
        print("=" * 60)
        print(f"[EMAIL DEV] To: {to_email}")
        print(f"[EMAIL DEV] Subject: {subject}")
        print(body)
        print("=" * 60)
        print("[EMAIL DEV] Tip: set EMAIL_DEV_MODE=false in .env to send real Gmail.")
        return True

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = Config.SMTP_FROM
    msg["To"] = to_email
    msg.set_content(body)

    # Gmail App Passwords are often copied with spaces — strip them
    password = (Config.SMTP_PASSWORD or "").replace(" ", "")

    try:
        print(f"[email] Sending via {Config.SMTP_HOST} as {Config.SMTP_USER} to {to_email}")
        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=20) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(Config.SMTP_USER, password)
            smtp.send_message(msg)
        print(f"[email] Sent successfully to {to_email}")
        return True
    except Exception as exc:
        print(f"[email_service] send failed: {exc}")
        return False


def send_otp_email(to_email: str, otp: str, purpose: str = "verification") -> bool:
    subject = "SecureChat — Your verification code"
    body = (
        f"Your SecureChat {purpose} code is: {otp}\n\n"
        f"This code expires in 5 minutes.\n"
        f"If you did not request this, ignore this email.\n"
    )
    return send_email(to_email, subject, body)


def send_password_reset_email(to_email: str, reset_link: str) -> bool:
    subject = "SecureChat — Password reset"
    body = (
        "You requested a password reset for SecureChat.\n\n"
        f"Open this link to set a new password (expires in 30 minutes):\n"
        f"{reset_link}\n\n"
        "If you did not request this, ignore this email.\n"
    )
    return send_email(to_email, subject, body)
