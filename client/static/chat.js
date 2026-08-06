// chat.js — WhatsApp-style sidebar + ECDH/AES chat with persistent keys

let socket = null;
let currentRecipient = null;
let aesKey = null;
let myKeyPair = null;
let myPublicKeyHex = null;
let currentPeerPublicKeyHex = null;
let fingerprintVerified = false;
let typingTimer = null;
let historyLoadedFor = null;
let requestInFlight = false;
let keyRetryTimer = null;
let keyRetryCount = 0;
const MAX_KEY_RETRIES = 3;
const messageStatus = {};
const renderedMsgIds = new Set();
const onlineUsers = new Set();
let conversations = [];
let myProfile = null;
/** In-memory only: peer -> CryptoKey[] (never persisted) */
const conversationKeyRing = {};
const IDB_NAME = "sc_secure_keys";
const IDB_STORE = "ecdh_keys";
const IDB_VERSION = 1;

function storageKey(suffix) {
  return `sc_${CURRENT_USER}_${suffix}`;
}

function getAccessToken() {
  return localStorage.getItem("access_token") || "";
}

function authHeaders() {
  return {
    "Content-Type": "application/json",
    Authorization: "Bearer " + getAccessToken(),
  };
}

async function refreshAccessToken() {
  const refresh = localStorage.getItem("refresh_token");
  if (!refresh) return false;
  try {
    const res = await fetch("/api/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refresh }),
    });
    const data = await res.json();
    if (data.success) {
      localStorage.setItem("access_token", data.access_token);
      localStorage.setItem("refresh_token", data.refresh_token);
      return true;
    }
  } catch (e) {}
  return false;
}

async function ensureAuth() {
  const storedUser = localStorage.getItem("username");
  if (!getAccessToken() || (storedUser && storedUser !== CURRENT_USER)) {
    window.location.href = "/";
    return false;
  }
  return true;
}

function initials(name) {
  const s = (name || "?").trim();
  return (s.slice(0, 2) || "?").toUpperCase();
}

function isLikelyImageUrl(url) {
  if (!url || typeof url !== "string") return false;
  const u = url.trim();
  if (!/^https?:\/\//i.test(u)) return false;
  // Reject obvious HTML pages / search pages
  if (/\/(free-png-vectors|search|collection|category)(\/|$)/i.test(u))
    return false;
  return true;
}

function setAvatar(el, name, avatarUrl) {
  if (!el) return;
  el.querySelectorAll("img.avatar-img").forEach((img) => img.remove());
  el.style.backgroundImage = "";

  const label = initials(name);
  el.classList.remove("has-image");
  el.textContent = label;

  if (!avatarUrl || !isLikelyImageUrl(avatarUrl)) return;

  const img = document.createElement("img");
  img.className = "avatar-img";
  img.alt = name || "avatar";
  img.decoding = "async";
  img.referrerPolicy = "no-referrer";
  img.onload = () => {
    if (!el.isConnected) return;
    el.classList.add("has-image");
    // Keep only the image inside the circle
    el.replaceChildren(img);
  };
  img.onerror = () => {
    if (!el.isConnected) return;
    el.classList.remove("has-image");
    el.textContent = label;
  };
  img.src = avatarUrl.trim();
}

function formatListTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function getLocalPreview(peer) {
  return localStorage.getItem(storageKey("preview_" + peer)) || "";
}

function setLocalPreview(peer, text) {
  localStorage.setItem(
    storageKey("preview_" + peer),
    (text || "").slice(0, 100),
  );
}

// ── ECDH in IndexedDB (non-extractable private key) + in-memory AES ──

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onerror = () => reject(req.error || new Error("IndexedDB open failed"));
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
  });
}

async function idbSet(key, value) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readwrite");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.objectStore(IDB_STORE).put(value, key);
  });
}

async function idbGet(key) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readonly");
    const req = tx.objectStore(IDB_STORE).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbDelete(key) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(IDB_STORE, "readwrite");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.objectStore(IDB_STORE).delete(key);
  });
}

function clearLegacyKeyStorage() {
  // Remove insecure localStorage key material from older builds
  try {
    localStorage.removeItem(storageKey("ecdh"));
    localStorage.removeItem(storageKey("conv_keys"));
  } catch (e) {}
}

async function saveMyKeyPair() {
  // Persist CryptoKey objects via IndexedDB structured clone.
  // Private key is non-extractable — cannot be exported as JWK.
  await idbSet(storageKey("ecdh"), {
    privateKey: myKeyPair.privateKey,
    publicKey: myKeyPair.publicKey,
    publicKeyHex: myPublicKeyHex,
  });
}

async function loadMyKeyPair() {
  clearLegacyKeyStorage();
  try {
    const data = await idbGet(storageKey("ecdh"));
    if (!data || !data.privateKey || !data.publicKey || !data.publicKeyHex) {
      return false;
    }
    myKeyPair = {
      privateKey: data.privateKey,
      publicKey: data.publicKey,
    };
    myPublicKeyHex = data.publicKeyHex;
    return true;
  } catch (e) {
    try {
      await idbDelete(storageKey("ecdh"));
    } catch (err) {}
    return false;
  }
}

async function generateNonExtractableKeyPair() {
  // generateKey extractable flag applies to both keys, so we:
  // 1) generate extractable once, 2) export public raw, 3) re-import
  // private as non-extractable, then discard extractable originals.
  const temp = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );
  const publicRaw = await window.crypto.subtle.exportKey("raw", temp.publicKey);
  const privateJwk = await window.crypto.subtle.exportKey("jwk", temp.privateKey);

  const privateKey = await window.crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false, // non-extractable — never exportable again
    ["deriveKey", "deriveBits"],
  );
  const publicKey = await window.crypto.subtle.importKey(
    "raw",
    publicRaw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );

  return {
    privateKey,
    publicKey,
    publicKeyHex: bufferToHex(publicRaw),
  };
}

function rememberConversationKeyInMemory(peer, peerPublicKeyHex, key) {
  if (!conversationKeyRing[peer]) conversationKeyRing[peer] = [];
  const list = conversationKeyRing[peer];
  if (!list.includes(key)) {
    list.push(key);
    conversationKeyRing[peer] = list.slice(-5);
  }
  currentPeerPublicKeyHex = peerPublicKeyHex;
  sessionStorage.setItem(storageKey("last_recipient"), peer);
  sessionStorage.setItem(storageKey("peer_pub_" + peer), peerPublicKeyHex);
}

async function decryptWithKeyRing(peer, nonceHex, ciphertextHex) {
  const candidates = [];
  if (aesKey && currentRecipient === peer) candidates.push(aesKey);
  for (const key of conversationKeyRing[peer] || []) {
    candidates.push(key);
  }
  let lastErr = null;
  for (const key of candidates) {
    try {
      return await decryptMessage(key, nonceHex, ciphertextHex);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("No key could decrypt message");
}

function getTrustedPeers() {
  try {
    return JSON.parse(sessionStorage.getItem(storageKey("trusted_peers")) || "{}");
  } catch (e) {
    return {};
  }
}

function setPeerTrusted(peer, peerPublicKeyHex) {
  const map = getTrustedPeers();
  map[peer] = peerPublicKeyHex;
  sessionStorage.setItem(storageKey("trusted_peers"), JSON.stringify(map));
}

function isPeerTrusted(peer, peerPublicKeyHex) {
  if (!peer || !peerPublicKeyHex) return false;
  return getTrustedPeers()[peer] === peerPublicKeyHex;
}

function setComposerEnabled(enabled) {
  const input = document.getElementById("message-input");
  const sendBtn = document.getElementById("send-btn");
  if (input) input.disabled = !enabled;
  if (sendBtn) sendBtn.disabled = !enabled;
}

// ── Loaders & skeletons ──

function showAppLoader(show) {
  const el = document.getElementById("app-loader");
  if (!el) return;
  if (show) {
    el.classList.remove("is-hidden");
    el.hidden = false;
  } else {
    el.classList.add("is-hidden");
    el.hidden = true;
  }
}

function showSidebarSkeleton(show) {
  const profile = document.getElementById("sidebar-profile");
  const profileSkel = document.getElementById("profile-skeleton");
  const listSkel = document.getElementById("chat-list-skeleton");
  const empty = document.getElementById("chat-list-empty");
  const spinner = document.getElementById("chat-list-spinner");

  if (profile) profile.hidden = !!show;
  if (profileSkel) profileSkel.hidden = !show;
  if (listSkel) listSkel.hidden = !show;
  if (spinner) spinner.hidden = !show;
  if (show && empty) empty.hidden = true;
  if (show) {
    document
      .querySelectorAll("#chat-list .chat-item")
      .forEach((el) => el.remove());
  }
}

function showMessagesSkeleton(show) {
  const skel = document.getElementById("messages-skeleton");
  const area = document.getElementById("messages-area");
  if (skel) skel.hidden = !show;
  if (area) {
    area.style.visibility = show ? "hidden" : "visible";
    area.setAttribute("aria-busy", show ? "true" : "false");
  }
}

function showChatLoader(show, text) {
  const el = document.getElementById("chat-panel-loader");
  const label = document.getElementById("chat-panel-loader-text");
  if (!el) return;
  if (text && label) label.textContent = text;
  el.hidden = !show;
}

function setControlLoading(btn, loading, loadingText) {
  if (!btn) return;
  if (loading) {
    if (!btn.dataset.originalText) btn.dataset.originalText = btn.textContent;
    btn.disabled = true;
    btn.classList.add("is-loading");
    if (loadingText) btn.textContent = loadingText;
  } else {
    btn.classList.remove("is-loading");
    if (btn.dataset.originalText) {
      btn.textContent = btn.dataset.originalText;
      delete btn.dataset.originalText;
    }
    btn.disabled = false;
  }
}

// ── Sidebar ──

async function loadSidebar() {
  showSidebarSkeleton(true);
  try {
    let res = await fetch("/api/conversations", { headers: authHeaders() });
    if (res.status === 401 && (await refreshAccessToken())) {
      res = await fetch("/api/conversations", { headers: authHeaders() });
    }
    const data = await res.json();
    if (!data.success) return;

    conversations = data.conversations || [];
    myProfile = data.me || null;
    onlineUsers.clear();
    (data.online_users || []).forEach((u) => onlineUsers.add(u));

    renderMyProfile();
    renderChatList();
  } catch (e) {
    console.error("sidebar load failed", e);
    const empty = document.getElementById("chat-list-empty");
    if (empty) {
      empty.hidden = false;
      empty.textContent = "Could not load chats. Try refresh.";
    }
  } finally {
    showSidebarSkeleton(false);
  }
}

function renderMyProfile() {
  const name =
    (myProfile && myProfile.profile && myProfile.profile.display_name) ||
    CURRENT_USER;
  const avatar =
    (myProfile && myProfile.profile && myProfile.profile.avatar_url) || "";
  document.getElementById("my-display-name").textContent = name;
  document.getElementById("my-username").textContent = "@" + CURRENT_USER;
  setAvatar(document.getElementById("my-avatar"), name, avatar);
}

function renderChatList() {
  const list = document.getElementById("chat-list");
  const empty = document.getElementById("chat-list-empty");
  const listSkel = document.getElementById("chat-list-skeleton");
  if (listSkel) listSkel.hidden = true;

  const q = (document.getElementById("chat-search").value || "")
    .trim()
    .toLowerCase();

  const items = conversations.filter((c) => {
    if (!q) return true;
    return (
      (c.peer || "").toLowerCase().includes(q) ||
      (c.display_name || "").toLowerCase().includes(q)
    );
  });

  list.querySelectorAll(".chat-item").forEach((el) => el.remove());

  if (!items.length) {
    empty.hidden = false;
    empty.style.display = "block";
    empty.textContent = conversations.length
      ? "No chats match your search."
      : "No conversations yet. Start a new chat above.";
    return;
  }
  empty.hidden = true;
  empty.style.display = "none";

  items.forEach((c) => {
    const preview = getLocalPreview(c.peer) || "Encrypted message 🔒";
    const active = currentRecipient === c.peer ? " active" : "";
    const online = onlineUsers.has(c.peer);
    const item = document.createElement("button");
    item.type = "button";
    item.className = "chat-item" + active;
    item.dataset.peer = c.peer;
    item.onclick = () => openConversation(c.peer, c.display_name, c.avatar_url);
    item.innerHTML = `
            <div class="avatar chat-item-avatar">${escapeHtml(initials(c.display_name || c.peer))}</div>
            <div class="chat-item-body">
                <div class="chat-item-top">
                    <span class="chat-item-name">${escapeHtml(c.display_name || c.peer)}</span>
                    <span class="chat-item-time">${escapeHtml(formatListTime(c.last_message && c.last_message.created_at))}</span>
                </div>
                <div class="chat-item-bottom">
                    <span class="chat-item-preview">${escapeHtml(preview)}</span>
                    <span class="presence-dot ${online ? "online" : ""}" title="${online ? "online" : "offline"}"></span>
                </div>
            </div>
        `;
    const av = item.querySelector(".chat-item-avatar");
    if (c.avatar_url) setAvatar(av, c.display_name || c.peer, c.avatar_url);
    list.appendChild(item);
  });
}

function filterChatList() {
  renderChatList();
}

function upsertConversationLocal(peer, previewText) {
  if (previewText) setLocalPreview(peer, previewText);
  const existing = conversations.find((c) => c.peer === peer);
  const nowIso = new Date().toISOString();
  if (existing) {
    existing.last_message = existing.last_message || {};
    existing.last_message.created_at = nowIso;
    existing.last_message.sender = CURRENT_USER;
    conversations = [existing, ...conversations.filter((c) => c.peer !== peer)];
  } else {
    conversations.unshift({
      peer,
      display_name: peer,
      avatar_url: "",
      online: onlineUsers.has(peer),
      last_message: {
        created_at: nowIso,
        sender: CURRENT_USER,
        encrypted: true,
      },
      message_count: 1,
    });
  }
  renderChatList();
}

function showSidebarOnly() {
  document.body.classList.remove("chat-open");
}

function showChatPanel() {
  document.getElementById("chat-empty").hidden = true;
  document.getElementById("chat-panel").hidden = false;
  document.body.classList.add("chat-open");
}

function showEmptyState() {
  showMessagesSkeleton(false);
  showChatLoader(false);
  showSidebarOnly();
  document.getElementById("chat-empty").hidden = false;
  document.getElementById("chat-panel").hidden = true;
  document.getElementById("message-input").disabled = true;
  document.getElementById("send-btn").disabled = true;
  document.getElementById("key-panel").hidden = true;
}

function stopKeyRetries() {
  clearTimeout(keyRetryTimer);
  keyRetryTimer = null;
}

function showChatErrorState(title, message) {
  showMessagesSkeleton(false);
  showChatLoader(false);
  const area = document.getElementById("messages-area");
  if (area) {
    area.innerHTML = `
            <div class="chat-error-state">
                <div class="chat-error-title">${escapeHtml(title)}</div>
                <div class="chat-error-msg">${escapeHtml(message)}</div>
                // <button type="button" class="btn-secondary" id="chat-error-back-btn">
                //     Back to chats
                // </button>
            </div>
        `;
    const backBtn = document.getElementById("chat-error-back-btn");
    if (backBtn) {
      backBtn.onclick = () => {
        showSidebarOnly();
        document.getElementById("chat-empty").hidden = false;
        document.getElementById("chat-panel").hidden = true;
        document.body.classList.remove("chat-open");
        currentRecipient = null;
      };
    }
  }
  document.getElementById("message-input").disabled = true;
  document.getElementById("send-btn").disabled = true;
  document.getElementById("key-panel").hidden = true;
}

async function lookupUser(username) {
  let res = await fetch(`/api/lookup/${encodeURIComponent(username)}`, {
    headers: authHeaders(),
  });
  if (res.status === 401 && (await refreshAccessToken())) {
    res = await fetch(`/api/lookup/${encodeURIComponent(username)}`, {
      headers: authHeaders(),
    });
  }
  return res.json();
}

async function startNewChat() {
  const btn = document.getElementById("new-chat-btn");
  const peer = document.getElementById("new-chat-user").value.trim();
  if (!peer) return;
  if (peer === CURRENT_USER) {
    openNoticeModal(
      "Cannot chat with yourself",
      "Enter another registered username to start a secure chat.",
    );
    return;
  }

  setControlLoading(btn, true, "...");
  try {
    const data = await lookupUser(peer);
    if (!data.success) {
      openNoticeModal(
        "User not registered",
        data.message ||
          `User "${peer}" is not registered. Ask them to create an account first.`,
      );
      return;
    }
    document.getElementById("new-chat-user").value = "";
    const user = data.user || {};
    await openConversation(
      user.username || peer,
      user.display_name || peer,
      user.avatar_url || "",
    );
  } catch (e) {
    openNoticeModal(
      "Lookup failed",
      "Could not look up that user. Check your connection and try again.",
    );
  } finally {
    setControlLoading(btn, false);
  }
}

async function openConversation(peer, displayName, avatarUrl) {
  if (requestInFlight) return;
  stopKeyRetries();
  currentRecipient = peer;
  historyLoadedFor = null;
  aesKey = null;
  renderedMsgIds.clear();

  document.getElementById("recipient-input").value = peer;
  document.getElementById("peer-name").textContent = displayName || peer;
  document.getElementById("peer-status").textContent = onlineUsers.has(peer)
    ? "online"
    : "offline";
  setAvatar(
    document.getElementById("peer-avatar"),
    displayName || peer,
    avatarUrl || "",
  );

  const area = document.getElementById("messages-area");
  area.innerHTML =
    '<div class="system-msg">Messages are end-to-end encrypted. Server cannot read them.</div>';

  document.getElementById("message-input").disabled = true;
  document.getElementById("send-btn").disabled = true;
  document.getElementById("key-panel").hidden = false;
  document.getElementById("fingerprint-display").style.display = "none";
  fingerprintVerified = false;
  currentPeerPublicKeyHex = null;
  aesKey = null;
  document.getElementById("key-panel").style.background = "";

  showChatPanel();
  showMessagesSkeleton(true);
  showChatLoader(true, "Establishing secure session...");
  renderChatList();
  await startKeyExchange(false, { silent: false });
}

// ── Socket ──

function initSocket() {
  socket = io(SERVER_URL, {
    transports: ["polling", "websocket"],
    reconnection: true,
    reconnectionAttempts: 5,
    reconnectionDelay: 1000,
    auth: { token: getAccessToken() },
  });

  socket.on("connect", async () => {
    document.getElementById("status-dot").textContent = "Connected";
    document.getElementById("status-dot").classList.add("ok");
    socket.emit("join", { username: CURRENT_USER });
    await uploadMyKey();
    await loadSidebar();
    showAppLoader(false);

    const last = sessionStorage.getItem(storageKey("last_recipient"));
    if (last) {
      const found = conversations.find((c) => c.peer === last);
      await openConversation(
        last,
        (found && found.display_name) || last,
        (found && found.avatar_url) || "",
      );
    }
  });

  socket.on("connect_error", async () => {
    document.getElementById("status-dot").textContent = "Auth failed";
    document.getElementById("status-dot").classList.remove("ok");
    const loaderText = document.querySelector("#app-loader p");
    if (loaderText) loaderText.textContent = "Reconnecting...";
    if (await refreshAccessToken()) {
      socket.auth = { token: getAccessToken() };
      socket.connect();
    } else {
      window.location.href = "/";
    }
  });

  socket.on("disconnect", () => {
    document.getElementById("status-dot").textContent = "Disconnected";
    document.getElementById("status-dot").classList.remove("ok");
  });

  socket.on("status", (data) => {
    if (currentRecipient) addSystemMessage(data.message);
  });

  socket.on("force_logout", (data) => {
  alert(data.reason || "Logged in from another device");
  logout();
  });

  socket.on("presence", (data) => {
    if (data.status === "online") onlineUsers.add(data.username);
    else onlineUsers.delete(data.username);
    if (currentRecipient === data.username) {
      document.getElementById("peer-status").textContent =
        data.status === "online" ? "online" : "offline";
      // Peer came online — try key exchange once (no endless loop)
      if (data.status === "online" && !aesKey) {
        keyRetryCount = 0;
        startKeyExchange(true, { silent: false });
      }
    }
    renderChatList();
  });

  socket.on("typing", (data) => {
    const el = document.getElementById("typing-indicator");
    if (data.sender === currentRecipient && data.is_typing) {
      el.style.display = "block";
      el.textContent = `${data.sender} is typing...`;
    } else {
      el.style.display = "none";
    }
  });

  socket.on("receive_message", async (data) => {
    const fromPeer = data.sender;
    try {
      const text = await decryptWithKeyRing(
        fromPeer,
        data.encrypted.nonce,
        data.encrypted.ciphertext,
      );
      upsertConversationLocal(fromPeer, text);

      if (currentRecipient === fromPeer) {
        addMessage(fromPeer, text, "received", data.msg_id);
        socket.emit("message_read", { msg_id: data.msg_id });
      } else {
        loadSidebar();
      }
    } catch (e) {
      console.error("Decryption error:", e);
      upsertConversationLocal(fromPeer, "Encrypted message 🔒");
      if (currentRecipient === fromPeer) {
        addSystemMessage("Decryption failed — click Establish encryption");
      } else {
        loadSidebar();
      }
    }
  });

  socket.on("receive_edit", async (data) => {
    try {
      const plaintext = await decryptWithKeyRing(
        data.sender,
        data.encrypted.nonce,
        data.encrypted.ciphertext,
      );
      const bubble = document.querySelector(`[data-msgid="${data.msg_id}"]`);
      if (bubble) {
        bubble.querySelector(".msg-body").textContent = plaintext + " (edited)";
      }
    } catch (e) {}
  });

  socket.on("message_status", (data) => {
    messageStatus[data.msg_id] = data.status;
    const el = document.querySelector(
      `[data-msgid="${data.msg_id}"] .msg-status`,
    );
    if (el) {
      el.textContent = data.status === "sent" ? "✓" : "✓✓";
      if (data.status === "read") el.classList.add("read");
    }
  });

  socket.on("error", (data) => {
    if (currentRecipient) addSystemMessage(data.message);
  });
}

async function uploadMyKey() {
  try {
    const restored = await loadMyKeyPair();
    if (!restored) {
      const generated = await generateNonExtractableKeyPair();
      myKeyPair = {
        privateKey: generated.privateKey,
        publicKey: generated.publicKey,
      };
      myPublicKeyHex = generated.publicKeyHex;
      await saveMyKeyPair();
    }

    let res = await fetch(`${SERVER_URL}/store_key`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ public_key: myPublicKeyHex }),
    });
    if (res.status === 401 && (await refreshAccessToken())) {
      res = await fetch(`${SERVER_URL}/store_key`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ public_key: myPublicKeyHex }),
      });
    }
  } catch (e) {
    console.error("key upload failed", e);
  }
}

async function startKeyExchange(isAuto = false, options = {}) {
  const silent = !!options.silent;
  const recipient = (
    document.getElementById("recipient-input").value ||
    currentRecipient ||
    ""
  ).trim();

  const clearLoaders = () => {
    showMessagesSkeleton(false);
    showChatLoader(false);
  };

  if (!recipient || recipient === CURRENT_USER) {
    clearLoaders();
    return;
  }
  if (!socket || !socket.connected) {
    if (!silent) addSystemMessage("Not connected yet — please wait...");
    clearLoaders();
    return;
  }
  if (!myKeyPair || !myPublicKeyHex) {
    await uploadMyKey();
  }

  if (requestInFlight && silent) return;

  requestInFlight = true;
  const connectBtn = document.getElementById("connect-btn");
  if (!silent) {
    keyRetryCount = 0;
    setControlLoading(connectBtn, true, "Connecting...");
    showChatLoader(true, "Establishing secure session...");
    showMessagesSkeleton(true);
  }

  currentRecipient = recipient;
  try {
    let getRes = await fetch(
      `${SERVER_URL}/get_key/${encodeURIComponent(recipient)}`,
      {
        headers: authHeaders(),
      },
    );
    if (getRes.status === 401 && (await refreshAccessToken())) {
      getRes = await fetch(
        `${SERVER_URL}/get_key/${encodeURIComponent(recipient)}`,
        {
          headers: authHeaders(),
        },
      );
    }
    const data = await getRes.json();

    if (!data.success) {
      // Unregistered user — stop completely
      if (data.code === "user_not_found") {
        stopKeyRetries();
        showChatLoader(false);
        openNoticeModal(
          "User not registered",
          data.message ||
            `User "${recipient}" is not registered. Ask them to create an account first.`,
        );
        currentRecipient = null;
        sessionStorage.removeItem(storageKey("last_recipient"));
        showEmptyState();
        return;
      }

      const restored = await restoreAesFromPeer(recipient);
      if (restored) {
        enableChatUi(
          recipient,
          currentPeerPublicKeyHex ||
            sessionStorage.getItem(storageKey("peer_pub_" + recipient)),
        );
        if (!silent) showChatLoader(true, "Loading messages...");
        await loadHistory(recipient);
        if (!silent) {
          addSystemMessage(
            `${recipient} is offline or has not connected yet. ` +
              "You can still view previous messages.",
          );
        }
        stopKeyRetries();
        return;
      }

      // Registered but no key — limited retries only
      keyRetryCount += 1;
      if (keyRetryCount <= MAX_KEY_RETRIES) {
        if (!silent) {
          addSystemMessage(
            data.message ||
              `Waiting for ${recipient} to connect (${keyRetryCount}/${MAX_KEY_RETRIES})...`,
          );
        }
        stopKeyRetries();
        keyRetryTimer = setTimeout(() => {
          startKeyExchange(true, { silent: true });
        }, 4000);
      } else {
        stopKeyRetries();
        showChatErrorState(
          "Cannot start chat yet",
          data.message ||
            `${recipient} has not connected. Ask them to log in, then try again.`,
        );
      }
      return;
    }

    stopKeyRetries();
    keyRetryCount = 0;

    const recipientPublicKey = await window.crypto.subtle.importKey(
      "raw",
      hexToBuffer(data.public_key),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );

    aesKey = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: recipientPublicKey },
      myKeyPair.privateKey,
      { name: "AES-GCM", length: 256 },
      false, // non-extractable — never export raw AES to storage
      ["encrypt", "decrypt"],
    );

    rememberConversationKeyInMemory(recipient, data.public_key, aesKey);
    enableChatUi(recipient, data.public_key);
    if (!silent) showChatLoader(true, "Loading messages...");
    historyLoadedFor = null;
    await loadHistory(recipient);
  } catch (e) {
    console.error(e);
    stopKeyRetries();
    if (!silent) addSystemMessage("Key exchange failed: " + e.message);
  } finally {
    requestInFlight = false;
    if (!silent) setControlLoading(connectBtn, false);
    // Keep loaders hidden unless error state already replaced the UI
    if (!document.querySelector(".chat-error-state")) {
      clearLoaders();
    } else {
      clearLoaders();
    }
  }
}

async function restoreAesFromPeer(peer) {
  // Re-derive in memory from peer public key (never load AES from disk)
  if (conversationKeyRing[peer] && conversationKeyRing[peer].length) {
    aesKey = conversationKeyRing[peer][conversationKeyRing[peer].length - 1];
    currentPeerPublicKeyHex =
      sessionStorage.getItem(storageKey("peer_pub_" + peer)) ||
      currentPeerPublicKeyHex;
    return true;
  }
  const peerPub =
    sessionStorage.getItem(storageKey("peer_pub_" + peer)) || null;
  if (!peerPub || !myKeyPair) return false;
  try {
    const recipientPublicKey = await window.crypto.subtle.importKey(
      "raw",
      hexToBuffer(peerPub),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    aesKey = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: recipientPublicKey },
      myKeyPair.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    rememberConversationKeyInMemory(peer, peerPub, aesKey);
    return true;
  } catch (e) {
    return false;
  }
}

function enableChatUi(recipient, peerPublicKeyHex) {
  currentPeerPublicKeyHex = peerPublicKeyHex || currentPeerPublicKeyHex || "";
  fingerprintVerified = isPeerTrusted(recipient, currentPeerPublicKeyHex);

  const fingerprint = formatFingerprint(currentPeerPublicKeyHex);
  const fpBox = document.getElementById("fingerprint-display");
  fpBox.style.display = "block";

  if (fingerprintVerified) {
    fpBox.innerHTML = `Encrypted session with <b>${escapeHtml(recipient)}</b><br>
         Fingerprint: <code>${fingerprint}</code><br>
         <span class="fp-verified">Fingerprint verified — messaging enabled</span>`;
    setComposerEnabled(true);
  } else {
    fpBox.innerHTML = `Encrypted session with <b>${escapeHtml(recipient)}</b><br>
         Fingerprint: <code>${fingerprint}</code><br>
         <span class="fp-warn">Compare this fingerprint out-of-band, then confirm to enable messaging.</span><br>
         <button type="button" class="btn-primary small" id="verify-fp-btn"
                 onclick="confirmFingerprint()">I verified this fingerprint</button>`;
    setComposerEnabled(false);
  }
  document.getElementById("key-panel").style.background =
    "rgba(45,212,191,0.08)";
}

function confirmFingerprint() {
  if (!currentRecipient || !currentPeerPublicKeyHex) return;
  setPeerTrusted(currentRecipient, currentPeerPublicKeyHex);
  fingerprintVerified = true;
  enableChatUi(currentRecipient, currentPeerPublicKeyHex);
  addSystemMessage("Fingerprint verified. You can send encrypted messages.");
}

async function loadHistory(peer) {
  if (historyLoadedFor === peer) return;
  try {
    const res = await fetch(
      `/api/messages/${encodeURIComponent(peer)}?limit=100`,
      {
        headers: authHeaders(),
      },
    );
    const data = await res.json();
    if (!data.success) return;

    const area = document.getElementById("messages-area");
    area.querySelectorAll(".message-bubble").forEach((el) => el.remove());
    renderedMsgIds.clear();

    let lastPlain = "";
    for (const msg of data.messages || []) {
      try {
        const text = await decryptWithKeyRing(
          peer,
          msg.encrypted.nonce,
          msg.encrypted.ciphertext,
        );
        lastPlain = text;
        const type = msg.sender === CURRENT_USER ? "sent" : "received";
        const label = type === "sent" ? "You" : msg.sender;
        addMessage(
          label,
          text + (msg.edited ? " (edited)" : ""),
          type,
          msg.msg_id,
          msg.status,
        );
      } catch (e) {}
    }
    if (lastPlain) setLocalPreview(peer, lastPlain);
    historyLoadedFor = peer;
    renderChatList();
  } catch (e) {
    console.error("history load failed", e);
  }
}

function formatFingerprint(publicKeyHex) {
  const short = (publicKeyHex || "").substring(0, 32);
  if (!short) return "";
  return short.match(/.{1,4}/g).join(":");
}

async function encryptMessage(key, plaintext) {
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    encoded,
  );
  return {
    nonce: bufferToHex(nonce),
    ciphertext: bufferToHex(ciphertext),
  };
}

async function decryptMessage(key, nonceHex, ciphertextHex) {
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBuffer(nonceHex) },
    key,
    hexToBuffer(ciphertextHex),
  );
  return new TextDecoder().decode(decrypted);
}

function notifyTyping() {
  if (!socket || !currentRecipient) return;
  socket.emit("typing", { recipient: currentRecipient, is_typing: true });
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => {
    socket.emit("typing", { recipient: currentRecipient, is_typing: false });
  }, 1200);
}

async function sendMessage() {
  const input = document.getElementById("message-input");
  const sendBtn = document.getElementById("send-btn");
  const text = input.value.trim();
  if (!text || !socket || !socket.connected || !aesKey || !currentRecipient)
    return;
  if (!fingerprintVerified || !isPeerTrusted(currentRecipient, currentPeerPublicKeyHex)) {
    openNoticeModal(
      "Verify fingerprint first",
      "Compare the session fingerprint out-of-band with your contact, then click “I verified this fingerprint” before sending.",
    );
    return;
  }
  if (sendBtn.disabled && sendBtn.classList.contains("is-loading")) return;

  setControlLoading(sendBtn, true, "...");
  try {
    const encrypted = await encryptMessage(aesKey, text);
    const msgId = generateUUID();
    socket.emit("send_message", {
      msg_id: msgId,
      recipient: currentRecipient,
      encrypted: encrypted,
    });
    addMessage("You", text, "sent", msgId, "sent");
    upsertConversationLocal(currentRecipient, text);
    input.value = "";
    socket.emit("typing", { recipient: currentRecipient, is_typing: false });
  } catch (e) {
    addSystemMessage("Send failed: " + e.message);
  } finally {
    setControlLoading(sendBtn, false);
    const ready =
      !!aesKey &&
      fingerprintVerified &&
      isPeerTrusted(currentRecipient, currentPeerPublicKeyHex);
    sendBtn.disabled = !ready;
    input.disabled = !ready;
  }
}

function addMessage(sender, text, type, msgId, status) {
  if (msgId && renderedMsgIds.has(msgId)) return;
  if (msgId) renderedMsgIds.add(msgId);

  const area = document.getElementById("messages-area");
  const time = new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
  const div = document.createElement("div");
  div.className = `message-bubble ${type}`;
  if (msgId) div.setAttribute("data-msgid", msgId);
  const statusIcon =
    type === "sent"
      ? `<span class="msg-status">${status === "sent" ? "✓" : "✓✓"}</span>`
      : "";
  div.innerHTML = `
        <div class="msg-body">${escapeHtml(text)}</div>
        <div class="time">${time} ${statusIcon}</div>
    `;
  area.appendChild(div);
  area.scrollTop = area.scrollHeight;
}

function addSystemMessage(text) {
  const area = document.getElementById("messages-area");
  if (!area) return;
  const div = document.createElement("div");
  div.className = "system-msg";
  div.textContent = text;
  area.appendChild(div);
  area.scrollTop = area.scrollHeight;
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.appendChild(document.createTextNode(text || ""));
  return div.innerHTML;
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

function generateUUID() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  const bytes = window.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bufferToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function openNoticeModal(title, text) {
  const modal = document.getElementById("notice-modal");
  if (!modal) return;
  const titleEl = document.getElementById("notice-modal-title");
  const textEl = document.getElementById("notice-modal-text");
  if (titleEl) titleEl.textContent = title || "Notice";
  if (textEl) textEl.textContent = text || "";
  modal.hidden = false;
  document.getElementById("notice-ok-btn")?.focus();
}

function closeNoticeModal() {
  const modal = document.getElementById("notice-modal");
  if (!modal) return;
  modal.hidden = true;
}

async function openLogoutModal() {
  const modal = document.getElementById("logout-modal");
  if (!modal) return;
  modal.hidden = false;
  document.getElementById("logout-confirm-btn")?.focus();
}

function closeLogoutModal() {
  const modal = document.getElementById("logout-modal");
  if (!modal) return;
  modal.hidden = true;
  const btn = document.getElementById("logout-confirm-btn");
  if (btn) {
    btn.disabled = false;
    btn.classList.remove("is-loading");
    if (btn.dataset.originalText) {
      btn.textContent = btn.dataset.originalText;
      delete btn.dataset.originalText;
    } else {
      btn.textContent = "Log out";
    }
  }
}

async function confirmLogout() {
  const btn = document.getElementById("logout-confirm-btn");
  setControlLoading(btn, true, "Logging out...");
  try {
    await fetch("/api/logout", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        refresh_token: localStorage.getItem("refresh_token"),
      }),
    });
  } catch (e) {}
  stopKeyRetries();
  clearLegacyKeyStorage();
  try {
    await idbDelete(storageKey("ecdh"));
  } catch (e) {}
  sessionStorage.removeItem(storageKey("last_recipient"));
  sessionStorage.removeItem(storageKey("trusted_peers"));
  Object.keys(sessionStorage)
    .filter((k) => k.startsWith(storageKey("peer_pub_")))
    .forEach((k) => sessionStorage.removeItem(k));
  for (const k of Object.keys(conversationKeyRing)) {
    delete conversationKeyRing[k];
  }
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
  localStorage.removeItem("username");
  window.location.href = "/";
}

async function logout() {
  openLogoutModal();
}

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  closeLogoutModal();
  closeNoticeModal();
});

document.addEventListener("click", (e) => {
  const logoutModal = document.getElementById("logout-modal");
  if (logoutModal && !logoutModal.hidden && e.target === logoutModal) {
    closeLogoutModal();
  }
  const noticeModal = document.getElementById("notice-modal");
  if (noticeModal && !noticeModal.hidden && e.target === noticeModal) {
    closeNoticeModal();
  }
});

window.onload = async () => {
  showAppLoader(true);
  showSidebarSkeleton(true);
  if (!(await ensureAuth())) return;
  initSocket();
};
