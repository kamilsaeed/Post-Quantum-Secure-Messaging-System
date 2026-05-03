import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

/** ML-KEM-768 (@noble/post-quantum): encapsulation key / decapsulation key sizes */
const ML_KEM768_PK_LEN = 1184;
const ML_KEM768_SK_LEN = 2400;

/** ML-DSA-65: verification key / signing key sizes (same as MetricsPanel expectations) */
const ML_DSA65_PK_LEN = 1952;
const ML_DSA65_SK_LEN = 4032;

// ============================================================
// Base64 <-> Uint8Array helpers (browser-native, no Buffer)
// ============================================================

/**
 * Convert a Uint8Array to a base64 string (browser-safe).
 * Handles large arrays by chunking to avoid call stack issues.
 */
export const toBase64 = (uint8Array) => {
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < uint8Array.length; i += chunkSize) {
        binary += String.fromCharCode(...uint8Array.subarray(i, i + chunkSize));
    }
    return btoa(binary);
};

/**
 * Normalize base64 from APIs / storage: trim, strip whitespace, URL-safe → standard, pad.
 */
const normalizeBase64 = (input) => {
    if (input == null || typeof input !== 'string') {
        throw new Error('Key material is missing or not a string (check API response and localStorage).');
    }
    let s = input.trim().replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4;
    if (pad) s += '='.repeat(4 - pad);
    return s;
};

/**
 * Convert a base64 string back to a Uint8Array.
 */
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

// ============================================================
// Member 3 (Frontend) — Phase 3
// ML-DSA-65 (Dilithium) — Identity & Digital Signatures
// ============================================================

/**
 * Generate a Dilithium key pair for user identity.
 * The private key NEVER leaves the browser — stored in localStorage.
 * The public key is uploaded to the server for signature verification.
 */
export const generateIdentity = () => {
    const keys = ml_dsa65.keygen();
    return {
        publicKey: toBase64(keys.publicKey),
        privateKey: toBase64(keys.secretKey),
    };
};

/**
 * Sign a message using the user's Dilithium private key.
 * Used to authenticate messages and handshake ciphertexts.
 * 
 * @param {string} message - The data to sign (string)
 * @param {string} privateKeyBase64 - Dilithium secret key (base64)
 * @returns {string} - Dilithium signature (base64)
 */
export const signData = (message, privateKeyBase64) => {
    const msgBytes = new TextEncoder().encode(message);
    const skBytes = fromBase64(privateKeyBase64);
    if (skBytes.length !== ML_DSA65_SK_LEN) {
        throw new Error(
            `Invalid Dilithium private key: decoded ${skBytes.length} bytes (expected ${ML_DSA65_SK_LEN}). ` +
                'Your pq_dsa_private_key in localStorage is corrupt or truncated. Log out, clear site data for this origin, and register again.'
        );
    }
    // @noble/post-quantum API: sign(message, secretKey) — not (secretKey, message)
    const signature = ml_dsa65.sign(msgBytes, skBytes);
    return toBase64(signature);
};

/**
 * Verify a Dilithium signature.
 * 
 * @param {string} message - The original data (string)
 * @param {string} signatureBase64 - The signature to verify (base64)
 * @param {string} publicKeyBase64 - Signer's Dilithium public key (base64)
 * @returns {boolean} - true if the signature is valid
 */
export const verifySignature = (message, signatureBase64, publicKeyBase64) => {
    try {
        const msgBytes = new TextEncoder().encode(message);
        const sigBytes = fromBase64(signatureBase64);
        const pkBytes = fromBase64(publicKeyBase64);
        if (pkBytes.length !== ML_DSA65_PK_LEN) return false;
        // @noble/post-quantum API: verify(signature, message, publicKey)
        return ml_dsa65.verify(sigBytes, msgBytes, pkBytes);
    } catch {
        return false;
    }
};

// ============================================================
// ML-KEM-768 (Kyber) — Post-Quantum Key Encapsulation
// ============================================================

/**
 * Generate a Kyber KEM key pair.
 * Used for the post-quantum secure key exchange handshake.
 * Private key stays in browser; public key uploaded to server.
 */
export const generateKEMKeys = () => {
    const keys = ml_kem768.keygen();
    return {
        publicKey: toBase64(keys.publicKey),
        privateKey: toBase64(keys.secretKey),
    };
};

/**
 * User A: Encapsulate a shared secret using User B's Kyber public key.
 * Returns the ciphertext (sent to B via server) and the shared secret (kept locally).
 * 
 * @param {string} recipientPublicKeyBase64 - Recipient's Kyber public key
 * @returns {{ ciphertext: string, sharedSecret: string }} both in base64
 */
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

/**
 * User B: Decapsulate the ciphertext using their Kyber private key.
 * Produces the EXACT same shared secret as User A generated.
 * 
 * @param {string} ciphertextBase64 - Kyber KEM ciphertext from User A
 * @param {string} privateKeyBase64 - Recipient's Kyber private key
 * @returns {string} sharedSecret in base64
 */
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

// ============================================================
// AES-256-GCM — Symmetric Encryption using WebCrypto API
// ============================================================

/**
 * Derive an AES-256 key from the Kyber shared secret using HKDF (RFC 5869).
 *
 * C7 fix: replaces the bare SHA-256 digest with HKDF-Extract + HKDF-Expand so that:
 *  - Domain separation is achieved via the `info` parameter
 *  - The key is bound to the conversation participants (sender + recipient)
 *  - A second key for a different purpose cannot accidentally collide
 *
 * @param {string} sharedSecretBase64 - Kyber-derived shared secret
 * @param {string} sender             - sender username (binds key to conversation)
 * @param {string} recipient          - recipient username (binds key to conversation)
 * @returns {Promise<CryptoKey>} AES-GCM key
 */
const deriveAESKey = async (sharedSecretBase64, sender = '', recipient = '') => {
    const secretBytes = fromBase64(sharedSecretBase64);

    // Import the raw shared secret as HKDF key material
    const hkdfKey = await crypto.subtle.importKey(
        'raw',
        secretBytes,
        { name: 'HKDF' },
        false,
        ['deriveKey']
    );

    // Domain-separated info string: binds the derived key to its purpose and participants
    const info = new TextEncoder().encode(
        `PQMSG-v1/aes-key/${sender}/${recipient}`
    );

    // No salt → HKDF uses a zero-filled salt of hash length (SHA-256 → 32 zero bytes)
    // This is standards-compliant per RFC 5869 §2.2.
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(32), // 32-byte zero salt
            info
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
};

/**
 * Encrypt a plaintext message with AES-256-GCM.
 *
 * @param {string} plaintext          - The message to encrypt
 * @param {string} sharedSecretBase64 - Kyber-derived shared secret
 * @param {string} sender             - sender username (for HKDF domain binding)
 * @param {string} recipient          - recipient username (for HKDF domain binding)
 * @returns {Promise<{ encryptedContent: string, iv: string }>} base64 encoded
 */
export const encryptMessage = async (plaintext, sharedSecretBase64, sender = '', recipient = '') => {
    const key = await deriveAESKey(sharedSecretBase64, sender, recipient);
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
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

/**
 * Decrypt an AES-256-GCM encrypted message.
 *
 * @param {string} encryptedContentBase64 - The ciphertext (base64)
 * @param {string} ivBase64               - The IV used during encryption (base64)
 * @param {string} sharedSecretBase64     - Kyber-derived shared secret
 * @param {string} sender                 - sender username (for HKDF domain binding)
 * @param {string} recipient              - recipient username (for HKDF domain binding)
 * @returns {Promise<string>} - Decrypted plaintext
 */
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