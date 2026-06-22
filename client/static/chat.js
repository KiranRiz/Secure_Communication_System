// Handles ECDH key exchange, AES-256-GCM encryption, and Socket.IO messaging

// State variables
let socket       = null;   // Socket.IO connection to the relay server
let myKeyPair    = null;   // Our ECDH key pair {publicKey, privateKey}
let myPublicRaw  = null;   // Our public key as Uint8Array (to share with peer)
let aesKey       = null;   // Derived AES-256-GCM key (after key exchange)
let peerName     = null;   // Username of the person we are chatting with

// Utility: convert between ArrayBuffer and hex strings

function bufToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBuf(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, 2 + i), 16);
    }
    return bytes.buffer;
}

// Generate a short fingerprint from raw public key bytes using SHA-256
// Used to verify keys out-of-band and detect MITM attacks
async function makeFingerprint(rawKeyBytes) {
    const hash = await crypto.subtle.digest('SHA-256', rawKeyBytes);
    return bufToHex(hash).substring(0, 32).toUpperCase().match(/.{4}/g).join('-');
}

// Add a chat bubble to the messages area
function appendMessage(sender, text, isMine) {
    const area = document.getElementById('messages');
    const div  = document.createElement('div');
    div.className = 'message-bubble ' + (isMine ? 'sent' : 'received');
    div.innerHTML = `<div class="sender">${sender}</div><div>${text}</div>`;
    area.appendChild(div);
    area.scrollTop = area.scrollHeight;
}

// Add a grey system message (e.g. "Connected to Alice")
function appendSystem(text) {
    const area = document.getElementById('messages');
    const div  = document.createElement('div');
    div.className   = 'system-msg';
    div.textContent = text;
    area.appendChild(div);
    area.scrollTop = area.scrollHeight;
}

// Update the connection status badge in the sidebar
function setStatus(text, cssClass) {
    const el = document.getElementById('connection-status');
    el.textContent = text;
    el.className   = 'status-badge ' + (cssClass || '');
}

// Enable or disable the message input and send button
function setInputEnabled(enabled) {
    document.getElementById('message-input').disabled = !enabled;
    document.getElementById('send-btn').disabled       = !enabled;
}
