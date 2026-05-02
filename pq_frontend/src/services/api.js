import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

const api = axios.create({
    baseURL: API_URL,
    headers: { 'Content-Type': 'application/json' },
    timeout: 15000,
});

/**
 * C6 fix — Axios request interceptor:
 * Attaches the session token (stored in localStorage after registration) as a
 * Bearer token on every API call that requires authentication.
 * The requireAuth middleware on the backend validates this token.
 */
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('pq_session_token');
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
});

// ============================================================
// Key / User Registry  (Member 2 — Backend routes)
// ============================================================

/**
 * Register a new user: sends both Dilithium + Kyber public keys.
 * Private keys are NEVER sent — they stay in the browser.
 * The server returns a session token which is stored for subsequent API calls.
 */
export const registerUser = async (username, dilithiumPublicKey, kyberPublicKey) => {
    const res = await api.post('/keys/register', { username, dilithiumPublicKey, kyberPublicKey });
    // C6: persist the session token so the interceptor can attach it to future requests
    if (res.data.sessionToken) {
        localStorage.setItem('pq_session_token', res.data.sessionToken);
    }
    return res.data;
};

/** Fetch a user's Dilithium + Kyber public keys from the server. */
export const getPublicKey = async (username) => {
    const res = await api.get(`/keys/publicKey/${username}`);
    return res.data;
};

/** Get the full list of registered users (for the contact directory). */
export const getUsers = async () => {
    const res = await api.get('/keys/users');
    return res.data;
};

// ============================================================
// Kyber KEM Handshake (Member 2 — Backend routes)
// ============================================================

/**
 * User A initiates a Kyber KEM handshake:
 * sends their encapsulated ciphertext + Dilithium signature to the server.
 */
export const initiateHandshake = async (initiator, recipient, kyberCiphertext, signature) => {
    const res = await api.post('/handshake/initiate', { initiator, recipient, kyberCiphertext, signature });
    return res.data;
};

/** User B polls for pending handshakes addressed to them. */
export const getPendingHandshakes = async (username) => {
    const res = await api.get(`/handshake/pending/${username}`);
    return res.data;
};

/** Mark a handshake as complete after User B decapsulates the shared secret. */
export const completeHandshake = async (handshakeId) => {
    const res = await api.patch(`/handshake/complete/${handshakeId}`);
    return res.data;
};

/** Check handshake status between two users. */
export const getHandshakeStatus = async (userA, userB) => {
    const res = await api.get(`/handshake/status/${userA}/${userB}`);
    return res.data;
};

// ============================================================
// Encrypted Messaging (Member 2 — Backend routes)
// ============================================================

/**
 * Send an AES-GCM encrypted message.
 * The server stores only ciphertext — plaintext is never transmitted.
 */
export const sendMessage = async (sender, recipient, encryptedContent, iv, signature) => {
    const res = await api.post('/messages/send', { sender, recipient, encryptedContent, iv, signature });
    return res.data;
};

/** Retrieve the full encrypted conversation between two users. */
export const getConversation = async (userA, userB) => {
    const res = await api.get(`/messages/conversation/${userA}/${userB}`);
    return res.data;
};

/**
 * M9 fix: mark messages as read via the explicit endpoint.
 * Called once when opening a chat, NOT on every poll.
 */
export const markMessagesRead = async (userA, userB) => {
    const res = await api.patch(`/messages/read/${userA}/${userB}`);
    return res.data;
};

/** Get unread message counts per sender (for notification badges). */
export const getUnreadCounts = async (username) => {
    const res = await api.get(`/messages/unread/${username}`);
    return res.data;
};