import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const ML_KEM768_PK_LEN = 1184;
const ML_KEM768_SK_LEN = 2400;

const ML_DSA65_PK_LEN = 1952;
const ML_DSA65_SK_LEN = 4032;

export const toBase64 = (uint8Array) => {
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < uint8Array.length; i += chunkSize) {
        binary += String.fromCharCode(...uint8Array.subarray(i, i + chunkSize));
    }
    return btoa(binary);
};

const normalizeBase64 = (input) => {
    if (input == null || typeof input !== 'string') {
        throw new Error('Key material is missing or not a string (check API response and localStorage).');
    }
    let s = input.trim().replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4;
    if (pad) s += '='.repeat(4 - pad);
    return s;
};

export const fromBase64 = (base64) => {
    const s = normalizeBase64(base64);
    try {
        return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    } catch {
        throw new Error(
            'Invalid Base64 key data (atob failed). Often caused by truncated keys, copy/paste corruption, ' +
                'or non-Base64 text in the Kyber/Dilithium fields. Clear site data and register again, ' +
                'and ensure MongoDB stores full Base64 strings.'
        );
    }
};

export const generateIdentity = () => {
    const keys = ml_dsa65.keygen();
    return {
        publicKey: toBase64(keys.publicKey),
        privateKey: toBase64(keys.secretKey),
    };
};

export const signData = (message, privateKeyBase64) => {
    const msgBytes = new TextEncoder().encode(message);
    const skBytes = fromBase64(privateKeyBase64);
    if (skBytes.length !== ML_DSA65_SK_LEN) {
        throw new Error(
            `Invalid Dilithium private key: decoded ${skBytes.length} bytes (expected ${ML_DSA65_SK_LEN}). ` +
                'Your pq_dsa_private_key in localStorage is corrupt or truncated. Log out, clear site data for this origin, and register again.'
        );
    }
    // @noble/post-quantum: sign(message, secretKey) — not (secretKey, message)
    const signature = ml_dsa65.sign(msgBytes, skBytes);
    return toBase64(signature);
};

export const verifySignature = (message, signatureBase64, publicKeyBase64) => {
    try {
        const msgBytes = new TextEncoder().encode(message);
        const sigBytes = fromBase64(signatureBase64);
        const pkBytes = fromBase64(publicKeyBase64);
        if (pkBytes.length !== ML_DSA65_PK_LEN) return false;
        // @noble/post-quantum: verify(signature, message, publicKey)
        return ml_dsa65.verify(sigBytes, msgBytes, pkBytes);
    } catch {
        return false;
    }
};

export const generateKEMKeys = () => {
    const keys = ml_kem768.keygen();
    return {
        publicKey: toBase64(keys.publicKey),
        privateKey: toBase64(keys.secretKey),
    };
};

export const encapsulateSecret = (recipientPublicKeyBase64) => {
    const pkBytes = fromBase64(recipientPublicKeyBase64);
    if (pkBytes.length !== ML_KEM768_PK_LEN) {
        throw new Error(
            `Invalid Kyber public key: decoded ${pkBytes.length} bytes (expected ${ML_KEM768_PK_LEN} for ML-KEM-768). ` +
                'Common causes: contact registered before Kyber was required, Dilithium key mistakenly stored as Kyber in MongoDB, ' +
                'or truncated Base64. Fix: delete that user in DB or re-register with a new username, then retry handshake.'
        );
    }
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(pkBytes);
    return {
        ciphertext: toBase64(cipherText),
        sharedSecret: toBase64(sharedSecret),
    };
};

export const decapsulateSecret = (ciphertextBase64, privateKeyBase64) => {
    const cipherBytes = fromBase64(ciphertextBase64);
    const skBytes = fromBase64(privateKeyBase64);
    if (skBytes.length !== ML_KEM768_SK_LEN) {
        throw new Error(
            `Invalid Kyber private key: decoded ${skBytes.length} bytes (expected ${ML_KEM768_SK_LEN}). ` +
                'Your pq_kem_private_key in localStorage is corrupt or truncated. Log out, clear site data, and register again.'
        );
    }
    const sharedSecret = ml_kem768.decapsulate(cipherBytes, skBytes);
    return toBase64(sharedSecret);
};

const deriveAESKey = async (sharedSecretBase64, sender = '', recipient = '') => {
    const secretBytes = fromBase64(sharedSecretBase64);

    const hkdfKey = await crypto.subtle.importKey(
        'raw',
        secretBytes,
        { name: 'HKDF' },
        false,
        ['deriveKey']
    );

    const info = new TextEncoder().encode(
        `PQMSG-v1/aes-key/${sender}/${recipient}`
    );

    // RFC 5869 sec. 2.2: fixed salt when IKM is high-entropy (explicit 32 zero bytes for WebCrypto HKDF).
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(32),
            info
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
};

export const encryptMessage = async (plaintext, sharedSecretBase64, sender = '', recipient = '') => {
    const key = await deriveAESKey(sharedSecretBase64, sender, recipient);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintextBytes = new TextEncoder().encode(plaintext);

    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        plaintextBytes
    );

    return {
        encryptedContent: toBase64(new Uint8Array(ciphertextBuffer)),
        iv: toBase64(iv),
    };
};

export const decryptMessage = async (encryptedContentBase64, ivBase64, sharedSecretBase64, sender = '', recipient = '') => {
    const key = await deriveAESKey(sharedSecretBase64, sender, recipient);
    const ciphertextBytes = fromBase64(encryptedContentBase64);
    const iv = fromBase64(ivBase64);

    const plaintextBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertextBytes
    );

    return new TextDecoder().decode(plaintextBuffer);
};
