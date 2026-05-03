import axios from 'axios';

const API_URL = 'http://localhost:5000/api';

const api = axios.create({
    baseURL: API_URL,
    headers: { 'Content-Type': 'application/json' },
    timeout: 15000,
});

api.interceptors.request.use((config) => {
    const token = localStorage.getItem('pq_session_token');
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
});

export const registerUser = async (username, dilithiumPublicKey, kyberPublicKey) => {
    const res = await api.post('/keys/register', { username, dilithiumPublicKey, kyberPublicKey });
    if (res.data.sessionToken) {
        localStorage.setItem('pq_session_token', res.data.sessionToken);
    }
    return res.data;
};

export const getPublicKey = async (username) => {
    const res = await api.get(`/keys/publicKey/${username}`);
    return res.data;
};

export const getUsers = async () => {
    const res = await api.get('/keys/users');
    return res.data;
};

export const initiateHandshake = async (initiator, recipient, kyberCiphertext, signature) => {
    const res = await api.post('/handshake/initiate', { initiator, recipient, kyberCiphertext, signature });
    return res.data;
};

export const getPendingHandshakes = async (username) => {
    const res = await api.get(`/handshake/pending/${username}`);
    return res.data;
};

export const completeHandshake = async (handshakeId) => {
    const res = await api.patch(`/handshake/complete/${handshakeId}`);
    return res.data;
};

export const getHandshakeStatus = async (userA, userB) => {
    const res = await api.get(`/handshake/status/${userA}/${userB}`);
    return res.data;
};

export const sendMessage = async (sender, recipient, encryptedContent, iv, signature) => {
    const res = await api.post('/messages/send', { sender, recipient, encryptedContent, iv, signature });
    return res.data;
};

export const getConversation = async (userA, userB) => {
    const res = await api.get(`/messages/conversation/${userA}/${userB}`);
    return res.data;
};

export const markMessagesRead = async (userA, userB) => {
    const res = await api.patch(`/messages/read/${userA}/${userB}`);
    return res.data;
};

export const getUnreadCounts = async (username) => {
    const res = await api.get(`/messages/unread/${username}`);
    return res.data;
};
