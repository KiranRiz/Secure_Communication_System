# server/server.py
# Author: Hamza
# Purpose: Main relay server — forwards encrypted messages
# Server cannot read any messages (maliciously curious model)

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room
from server.auth import AuthManager
from server.replay_guard import ReplayGuard
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-chat-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

auth = AuthManager()
replay_guard = ReplayGuard()

# Store connected users {username: session_id}
connected_users = {}

# ─────────────────────────────────────────
# REST ENDPOINTS — Register / Login / Keys
# ─────────────────────────────────────────

@app.route('/register', methods=['POST'])
def register():
    """Register new user"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"success": False,
                        "message": "Username and password required"}), 400
    result = auth.register(username, password)
    return jsonify(result)


@app.route('/login', methods=['POST'])
def login():
    """Login user"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    result = auth.login(username, password)
    return jsonify(result)


@app.route('/store_key', methods=['POST'])
def store_key():
    """Store user's public key for key exchange"""
    data = request.json
    username = data.get('username')
    public_key = data.get('public_key')
    auth.store_public_key(username, public_key)
    return jsonify({"success": True,
                    "message": "Public key stored"})


@app.route('/get_key/<username>', methods=['GET'])
def get_key(username):
    """Get user's public key"""
    key = auth.get_public_key(username)
    if key:
        return jsonify({"success": True, "public_key": key})
    return jsonify({"success": False,
                    "message": "Key not found"}), 404

# ─────────────────────────────────────────
# SOCKET.IO — Real-time messaging
# ─────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    print(f"Client connected: {request.sid}")


@socketio.on('join')
def on_join(data):
    """User joins with their username"""
    username = data.get('username')
    connected_users[username] = request.sid
    join_room(username)
    print(f"{username} joined")
    emit('status', {'message': f'Connected as {username}'})


@socketio.on('send_message')
def on_message(data):
    """
    Relay encrypted message to recipient.
    Server only sees ciphertext — cannot read content.
    """
    msg_id = data.get('msg_id')
    recipient = data.get('recipient')
    sender = data.get('sender')
    encrypted_payload = data.get('encrypted')

    # Replay attack check
    if replay_guard.is_replay(msg_id):
        emit('error', {'message': 'Replay attack detected — blocked'})
        return

    # Forward to recipient — server never decrypts
    emit('receive_message', {
        'sender': sender,
        'encrypted': encrypted_payload,
        'msg_id': msg_id
    }, room=recipient)
    print(f"[RELAYED] {sender} → {recipient} | "
          f"Ciphertext: {str(encrypted_payload)[:30]}...")


@socketio.on('disconnect')
def on_disconnect():
    # Remove from connected users
    for username, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[username]
            print(f"{username} disconnected")
            break


if __name__ == '__main__':
    print("Starting Secure Chat Server...")
    print("Server is a relay only — cannot read messages")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
