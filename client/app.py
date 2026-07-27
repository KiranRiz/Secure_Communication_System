# client/app.py
# UI Flask app — proxies auth APIs and serves chat pages

import os

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, url_for
import requests as http_requests

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "client-secret-key-change-me")

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000")


def _forward(method: str, path: str, json_body=None, headers=None):
    try:
        resp = http_requests.request(
            method,
            f"{SERVER_URL}{path}",
            json=json_body,
            headers=headers or {},
            timeout=15,
        )
        try:
            body = resp.json()
        except Exception:
            body = {"success": False, "message": "Invalid server response"}
        return jsonify(body), resp.status_code
    except Exception as exc:
        return jsonify({"success": False, "message": "Server not reachable"}), 503


def _auth_headers():
    auth = request.headers.get("Authorization")
    if auth:
        return {"Authorization": auth}
    return {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/chat")
def chat():
    username = request.args.get("username", "")
    if not username:
        return redirect(url_for("index"))
    return render_template(
        "chat.html",
        username=username,
        server_url=SERVER_URL,
    )


@app.route("/reset-password")
def reset_password_page():
    token = request.args.get("token", "")
    return render_template("reset_password.html", token=token)


@app.route("/profile-page")
def profile_page():
    username = request.args.get("username", "")
    if not username:
        return redirect(url_for("index"))
    return render_template(
        "profile.html",
        username=username,
        server_url=SERVER_URL,
    )


# ── Auth proxies ──

@app.route("/api/register", methods=["POST"])
def register():
    return _forward("POST", "/register", request.get_json(silent=True) or {})


@app.route("/api/login", methods=["POST"])
def login():
    return _forward("POST", "/login", request.get_json(silent=True) or {})


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    return _forward("POST", "/verify-otp", request.get_json(silent=True) or {})


@app.route("/api/resend-otp", methods=["POST"])
def resend_otp():
    return _forward("POST", "/resend-otp", request.get_json(silent=True) or {})


@app.route("/api/refresh", methods=["POST"])
def refresh():
    return _forward("POST", "/refresh", request.get_json(silent=True) or {})


@app.route("/api/logout", methods=["POST"])
def logout():
    return _forward(
        "POST",
        "/logout",
        request.get_json(silent=True) or {},
        headers=_auth_headers(),
    )


@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    return _forward("POST", "/forgot-password", request.get_json(silent=True) or {})


@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    return _forward("POST", "/reset-password", request.get_json(silent=True) or {})


@app.route("/api/profile", methods=["GET", "PUT"])
def profile():
    if request.method == "GET":
        return _forward("GET", "/profile", headers=_auth_headers())
    return _forward(
        "PUT",
        "/profile",
        request.get_json(silent=True) or {},
        headers=_auth_headers(),
    )


@app.route("/api/change-password", methods=["POST"])
def change_password():
    return _forward(
        "POST",
        "/change-password",
        request.get_json(silent=True) or {},
        headers=_auth_headers(),
    )


@app.route("/api/account", methods=["DELETE"])
def delete_account():
    return _forward(
        "DELETE",
        "/account",
        request.get_json(silent=True) or {},
        headers=_auth_headers(),
    )


@app.route("/api/lookup/<username>", methods=["GET"])
def lookup_user(username):
    return _forward("GET", f"/lookup/{username}", headers=_auth_headers())


@app.route("/api/conversations", methods=["GET"])
def conversations():
    return _forward("GET", "/conversations", headers=_auth_headers())


@app.route("/api/messages/<peer>", methods=["GET"])
def messages(peer):
    qs = request.query_string.decode()
    path = f"/messages/{peer}" + (f"?{qs}" if qs else "")
    return _forward("GET", path, headers=_auth_headers())


if __name__ == "__main__":
    print("Starting Secure Chat Client...")
    print("Open browser: http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=True)
