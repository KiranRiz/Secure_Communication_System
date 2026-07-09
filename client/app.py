from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import requests as http_requests


app = Flask(__name__)

app.secret_key = 'client-secret-key-2024'

socketio = SocketIO(app)


# Server URL — change this after deployment
SERVER_URL = "http://localhost:5000"


@app.route('/')
def index():
    """Login/Register page"""
    return render_template('index.html')


@app.route('/chat')
def chat():
    """Main chat page"""
    username = request.args.get('username', '')

    if not username:
        return render_template('index.html')

    return render_template(
        'chat.html',
        username=username,
        server_url=SERVER_URL
    )


@app.route('/api/register', methods=['POST'])
def register():
    """Forward registration to main server"""
    data = request.json

    try:
        response = http_requests.post(
            f"{SERVER_URL}/register",
            json=data,
            timeout=5
        )

        return jsonify(response.json())

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        })


@app.route('/api/login', methods=['POST'])
def login():
    """Forward login to main server"""
    data = request.json

    try:
        response = http_requests.post(
            f"{SERVER_URL}/login",
            json=data,
            timeout=5
        )

        return jsonify(response.json())

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        })


if __name__ == '__main__':

    print("Starting Secure Chat Client...")
    print("Open browser: http://localhost:3000")

    socketio.run(
        app,
        host='0.0.0.0',
        port=3000,
        debug=True
    )