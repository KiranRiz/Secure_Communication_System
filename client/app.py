# client/app.py
# Author: Kiran
# Flask web app that serves the chat UI and forwards auth requests to the relay server

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import requests as http_requests

app = Flask(__name__)
app.secret_key = 'client-secret-key-2024'
socketio = SocketIO(app)

SERVER_URL = "http://localhost:5000"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat')
def chat():
    username = request.args.get('username', '')
    if not username:
        return render_template('index.html')
    return render_template('chat.html', username=username, server_url=SERVER_URL)

@app.route('/api/register', methods=['POST'])
def register():
    try:
        res = http_requests.post(f"{SERVER_URL}/register", json=request.get_json(), timeout=5)
        return jsonify(res.json()), res.status_code
    except Exception:
        return jsonify({"success": False, "message": "Server not reachable"}), 503

@app.route('/api/login', methods=['POST'])
def login():
    try:
        res = http_requests.post(f"{SERVER_URL}/login", json=request.get_json(), timeout=5)
        return jsonify(res.json()), res.status_code
    except Exception:
        return jsonify({"success": False, "message": "Server not reachable"}), 503

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=3000, debug=True)
