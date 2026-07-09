// chat.js — Author: Kiran
// Purpose: Client-side encryption and real-time messaging
// Fix: Proper ECDH key exchange — both parties must have
//      uploaded keys before AES key derivation happens

// ── State ──
let socket = null;
let currentRecipient = null;
let aesKey = null;
let myKeyPair = null;       // Store key pair permanently for session
let myPublicKeyHex = null;  // Store our public key hex

// ── Connect to server via Socket.IO ──
function initSocket() {
    console.log("Connecting to server:", SERVER_URL);

    socket = io(SERVER_URL, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000
    });

    socket.on('connect', () => {
        console.log("Socket connected:", socket.id);
        document.getElementById('status-dot').textContent =
            '🟢 Connected';
        socket.emit('join', {username: CURRENT_USER});

        // Upload our key as soon as we connect
        uploadMyKey();
    });

    socket.on('connect_error', (err) => {
        console.error("Connection error:", err);
        document.getElementById('status-dot').textContent =
            '🔴 Connection Failed';
    });

    socket.on('disconnect', () => {
        document.getElementById('status-dot').textContent =
            '🔴 Disconnected';
    });

    socket.on('status', (data) => {
        addSystemMessage(data.message);
    });

    // Receive encrypted message from server
    socket.on('receive_message', async (data) => {
        if (!aesKey) {
            addSystemMessage(
                '⚠️ Message received but no key yet — ' +
                'click Connect first'
            );
            return;
        }
        try {
            const plaintext = await decryptMessage(
                aesKey,
                data.encrypted.nonce,
                data.encrypted.ciphertext
            );
            addMessage(data.sender, plaintext, 'received');
        } catch (e) {
            console.error("Decryption error:", e);
            addSystemMessage(
                '⚠️ Decryption failed — please click Connect ' +
                'again to refresh keys'
            );
        }
    });

    socket.on('error', (data) => {
        addSystemMessage('❌ ' + data.message);
    });
}

// ── Generate key pair and upload to server on login ──
async function uploadMyKey() {
    try {
        // Generate fresh ECDH key pair for this session
        myKeyPair = await window.crypto.subtle.generateKey(
            {name: 'ECDH', namedCurve: 'P-256'},
            true,
            ['deriveKey']
        );

        const myPublicKeyBuffer = await window.crypto.subtle.exportKey(
            'raw', myKeyPair.publicKey
        );
        myPublicKeyHex = bufferToHex(myPublicKeyBuffer);

        // Upload to server immediately
        const res = await fetch(`${SERVER_URL}/store_key`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: CURRENT_USER,
                public_key: myPublicKeyHex
            })
        });

        if (res.ok) {
            console.log("My public key uploaded to server");
            addSystemMessage(
                '🔑 Your key has been uploaded. ' +
                'Enter recipient username and click Connect.'
            );
        }
    } catch (e) {
        console.error("Key upload error:", e);
        addSystemMessage('❌ Failed to upload key: ' + e.message);
    }
}

// ── ECDH Key Exchange — derive AES key with recipient ──
async function startKeyExchange() {
    const recipient =
        document.getElementById('recipient-input').value.trim();

    if (!recipient) {
        alert('Enter recipient username');
        return;
    }
    if (recipient === CURRENT_USER) {
        alert('Cannot chat with yourself');
        return;
    }
    if (!socket || !socket.connected) {
        addSystemMessage('⏳ Not connected yet — please wait...');
        return;
    }
    if (!myKeyPair || !myPublicKeyHex) {
        addSystemMessage('⏳ Key not ready yet — please wait...');
        await uploadMyKey();
        return;
    }

    currentRecipient = recipient;
    addSystemMessage(`🔄 Fetching ${recipient}'s key from server...`);

    try {
        // Fetch recipient's public key from server
        const getRes = await fetch(
            `${SERVER_URL}/get_key/${recipient}`
        );
        const data = await getRes.json();

        if (!data.success) {
            addSystemMessage(
                `❌ "${recipient}" has not uploaded a key yet. ` +
                `Make sure they are logged in and connected. ` +
                `Retrying in 5 seconds...`
            );
            // Auto retry after 5 seconds
            setTimeout(() => startKeyExchange(), 5000);
            return;
        }

        // Derive shared AES-256 key using our private key
        // + recipient's public key
        const recipientPublicKeyBuffer = hexToBuffer(data.public_key);
        const recipientPublicKey =
            await window.crypto.subtle.importKey(
                'raw',
                recipientPublicKeyBuffer,
                {name: 'ECDH', namedCurve: 'P-256'},
                false,
                []
            );

        aesKey = await window.crypto.subtle.deriveKey(
            {name: 'ECDH', public: recipientPublicKey},
            myKeyPair.privateKey,
            {name: 'AES-GCM', length: 256},
            false,
            ['encrypt', 'decrypt']
        );

        console.log("AES key derived successfully");

        // Show fingerprint for MITM verification
        const fingerprint = formatFingerprint(myPublicKeyHex);
        const fpBox = document.getElementById('fingerprint-display');
        fpBox.style.display = 'block';
        fpBox.innerHTML =
            `🔑 Session established with <b>${recipient}</b><br>
             Your key fingerprint:
             <code>${fingerprint}</code><br>
             <small>⚠️ Verify this fingerprint with
             ${recipient} via phone/in-person to prevent
             MITM attack</small>`;

        // Enable messaging
        document.getElementById('message-input').disabled = false;
        document.getElementById('send-btn').disabled = false;
        document.getElementById('key-panel').style.background =
            '#0a2e1a';

        addSystemMessage(
            `✅ Encrypted session ready with ${recipient} — ` +
            `you can now send messages`
        );

    } catch (e) {
        console.error("Key exchange error:", e);
        addSystemMessage('❌ Key exchange failed: ' + e.message);
    }
}

// ── Format fingerprint like SSH ──
function formatFingerprint(publicKeyHex) {
    const short = publicKeyHex.substring(0, 32);
    return short.match(/.{1,4}/g).join(':');
}

// ── Encrypt message using AES-GCM ──
async function encryptMessage(key, plaintext) {
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = await window.crypto.subtle.encrypt(
        {name: 'AES-GCM', iv: nonce},
        key,
        encoded
    );
    return {
        nonce: bufferToHex(nonce),
        ciphertext: bufferToHex(ciphertext)
    };
}

// ── Decrypt message using AES-GCM ──
async function decryptMessage(key, nonceHex, ciphertextHex) {
    const nonce = hexToBuffer(nonceHex);
    const ciphertext = hexToBuffer(ciphertextHex);
    const decrypted = await window.crypto.subtle.decrypt(
        {name: 'AES-GCM', iv: nonce},
        key,
        ciphertext
    );
    return new TextDecoder().decode(decrypted);
}

// ── Send encrypted message ──
async function sendMessage() {
    const input = document.getElementById('message-input');
    const text = input.value.trim();

    if (!text) return;

    if (!socket || !socket.connected) {
        addSystemMessage('❌ Not connected to server');
        return;
    }
    if (!aesKey) {
        addSystemMessage(
            '❌ No encryption key — click Connect first'
        );
        return;
    }
    if (!currentRecipient) {
        addSystemMessage('❌ No recipient selected');
        return;
    }

    try {
        const encrypted = await encryptMessage(aesKey, text);
        const msgId = generateUUID();

        socket.emit('send_message', {
            msg_id: msgId,
            sender: CURRENT_USER,
            recipient: currentRecipient,
            encrypted: encrypted
        });

        addMessage('You', text, 'sent');
        input.value = '';

    } catch (e) {
        addSystemMessage('❌ Send failed: ' + e.message);
    }
}

// ── UI Helpers ──
function addMessage(sender, text, type) {
    const area = document.getElementById('messages-area');
    const time = new Date().toLocaleTimeString([], {
        hour: '2-digit', minute: '2-digit'
    });
    const div = document.createElement('div');
    div.className = `message-bubble ${type}`;
    div.innerHTML = `
        <div class="sender">${sender}</div>
        <div>${escapeHtml(text)}</div>
        <div class="time">${time} 🔒</div>
    `;
    area.appendChild(div);
    area.scrollTop = area.scrollHeight;
}

function addSystemMessage(text) {
    const area = document.getElementById('messages-area');
    const div = document.createElement('div');
    div.className = 'system-msg';
    div.textContent = text;
    area.appendChild(div);
    area.scrollTop = area.scrollHeight;
}

// Prevent XSS in messages
function escapeHtml(text) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}

function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
}

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(
        /[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        }
    );
}

// ── Start on page load ──
window.onload = () => {
    initSocket();
};