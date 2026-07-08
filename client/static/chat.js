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

// Socket.IO connection and messaging logic
// Connect to the relay server and register our username
function initSocket() {
    socket = io(SERVER_URL);
    socket.on('connect', () => {
        socket.emit('join', { username: USERNAME });
        appendSystem('Connected to server as ' + USERNAME);
    });

    socket.on('disconnect', () => {
        appendSystem('Disconnected from server');
        setStatus('Not connected');
        setInputEnabled(false);
    });

    // Peer has sent us their public key complete the key exchange
    socket.on('key_exchange', async (data) => {
        peerName = data.from;
        appendSystem(peerName + ' connected — completing key exchange...');
        setStatus('Connecting...', 'connecting');
        await completeKeyExchange(data.public_key);
    });

    // Relay server forwarded an encrypted message from our peer
    socket.on('receive_message', async (data) => {
        try {
            const plaintext = await decryptMessage(data.ciphertext, data.nonce);
            appendMessage(data.from, plaintext, false);
        } catch (e) {
            appendSystem('[Could not decrypt message — possible tampering]');
        }
    });
}
// Check if running in demo mode (no server needed)
const IS_DEMO = new URLSearchParams(window.location.search).get('demo') === '1';

if (IS_DEMO) {
    loadDemoMode();
} else {
    initSocket();
}

// TODO: Remove demo mode when server integration is complete
function loadDemoMode() {
    peerName = 'Alice';
    setStatus('Demo Mode — Connected to Alice', 'connected');
    setInputEnabled(true);

    appendSystem('Demo mode active — server integration pending');
    appendMessage('Alice', 'Hey! Can you see my message?', false);
    appendMessage(USERNAME, 'Yes! End-to-end encryption is working.', true);
    appendMessage('Alice', 'Great — the server only sees encrypted ciphertext, never plaintext.', false);
    appendMessage(USERNAME, 'Exactly. AES-256-GCM with ECDH key exchange.', true);
    appendMessage('Alice', 'And the fingerprints confirm no MITM attack.', false);

    document.getElementById('my-fingerprint').textContent  = 'A1B2-C3D4-E5F6-G7H8';
    document.getElementById('peer-fingerprint').textContent = 'X9Y8-Z7W6-V5U4-T3S2';

    // In demo mode, send button just shows the message locally
    document.getElementById('send-btn').onclick = function () {
        const input = document.getElementById('message-input');
        const text  = input.value.trim();
        if (!text) return;
        appendMessage(USERNAME, text, true);
        input.value = '';
        setTimeout(() => appendMessage('Alice', '(Demo: encrypted reply would appear here)', false), 800);
    };
}

//ECDH Key Generation and AES Key Derivation

// Generate our ECDH P-256 key pair when the page loads.
// The public key is shared with the peer; the private key never leaves the browser.
async function generateMyKeys() {
    myKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,                        
        ['deriveKey']                
    );

    // Export public key as raw bytes so we can send it as a hex string
    const rawBuf    = await crypto.subtle.exportKey('raw', myKeyPair.publicKey);
    myPublicRaw     = new Uint8Array(rawBuf);

    // Show our own fingerprint in the sidebar so the peer can verify it
    const fp = await makeFingerprint(myPublicRaw);
    document.getElementById('my-fingerprint').textContent = fp;
}

// Called when the user clicks "Connect" in the sidebar.
// Sends our public key to the peer through the relay server.
async function startKeyExchange() {
    const target = document.getElementById('peer-username').value.trim();
    if (!target) { alert('Enter a peer username'); return; }
    if (!myPublicRaw) { alert('Keys not ready yet, please wait'); return; }

    peerName = target;
    setStatus('Connecting...', 'connecting');
    appendSystem('Sending public key to ' + target + '...');

    socket.emit('key_exchange', {
        target:     target,
        public_key: bufToHex(myPublicRaw.buffer)
    });
}

// Called when we receive the peer's public key via the 'key_exchange' socket event.
// Imports the peer key and derives our shared AES-256-GCM key.
async function completeKeyExchange(peerPublicHex) {
    // Import peer's raw public key into Web Crypto
    const peerRaw    = new Uint8Array(hexToBuf(peerPublicHex));
    const peerCrypto = await crypto.subtle.importKey(
        'raw',
        peerRaw,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,          
        []             
    );

    // Derive a 256-bit AES-GCM key from the ECDH shared secret
    aesKey = await crypto.subtle.deriveKey(
        { name: 'ECDH', public: peerCrypto },
        myKeyPair.privateKey,
        { name: 'AES-GCM', length: 256 },
        false,                          
        ['encrypt', 'decrypt']
    );

    // Show peer fingerprint so user can verify out-of-band (anti-MITM)
    const fp = await makeFingerprint(peerRaw);
    document.getElementById('peer-fingerprint').textContent = fp;

    setStatus('Connected to ' + peerName, 'connected');
    appendSystem('Key exchange complete — chat is end-to-end encrypted');
    setInputEnabled(true);
}

generateMyKeys();

// AES-256-GCM Encrypt / Decrypt 
// Encrypt a plaintext string with our shared AES key.
// Returns { ciphertext: hex, nonce: hex }
async function encryptMessage(plaintext) {
    const iv      = crypto.getRandomValues(new Uint8Array(12));   // 96-bit random nonce
    const encoded = new TextEncoder().encode(plaintext);

    const cipherBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        encoded
    );

    return {
        ciphertext: bufToHex(cipherBuf),
        nonce:      bufToHex(iv.buffer)
    };
}

// Decrypt a ciphertext received from the peer.
// Returns the plaintext string.
async function decryptMessage(ciphertextHex, nonceHex) {
    const cipherBuf = hexToBuf(ciphertextHex);
    const iv        = new Uint8Array(hexToBuf(nonceHex));

    const plainBuf  = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        cipherBuf
    );

    return new TextDecoder().decode(plainBuf);
}

// Send Message

// Called when the user presses Send or hits Enter.
// Encrypts the message locally, then sends ciphertext to the relay server.
// The server never sees the plaintext — only the hex-encoded ciphertext.
async function sendMessage() {
    const input = document.getElementById('message-input');
    const text  = input.value.trim();
    if (!text || !aesKey || !peerName) return;

    try {
        const { ciphertext, nonce } = await encryptMessage(text);

        socket.emit('send_message', {
            target:     peerName,
            ciphertext: ciphertext,
            nonce:      nonce
        });
        appendMessage(USERNAME, text, true);
        input.value = '';
    } catch (e) {
        appendSystem('[Encryption failed — message not sent]');
    }
}
