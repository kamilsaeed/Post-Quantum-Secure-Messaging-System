// Import the standardized NIST versions of Kyber (ML-KEM) and Dilithium (ML-DSA)
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');

// --- DILITHIUM (Signatures for Identity) ---
const generateSignatureKeys = () => {
    const keys = ml_dsa65.keygen();
    return {
        publicKey: Buffer.from(keys.publicKey).toString('base64'),
        privateKey: Buffer.from(keys.secretKey).toString('base64')
    };
};

// --- KYBER (Key Encapsulation for Secret Sharing) ---
const generateKEMKeys = () => {
    const keys = ml_kem768.keygen();
    return {
        publicKey: Buffer.from(keys.publicKey).toString('base64'),
        privateKey: Buffer.from(keys.secretKey).toString('base64')
    };
};

// User A encapsulates a shared secret using User B's public key
const encapsulateSecret = (recipientPublicKeyBase64) => {
    const pkBytes = Uint8Array.from(Buffer.from(recipientPublicKeyBase64, 'base64'));
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(pkBytes);
    return {
        ciphertext: Buffer.from(cipherText).toString('base64'),
        sharedSecret: Buffer.from(sharedSecret).toString('base64')
    };
};

// ADD THIS NEW FUNCTION: User B decapsulates the ciphertext to get the secret
const decapsulateSecret = (ciphertextBase64, privateKeyBase64) => {
    const cipherBytes = Uint8Array.from(Buffer.from(ciphertextBase64, 'base64'));
    const skBytes = Uint8Array.from(Buffer.from(privateKeyBase64, 'base64'));
    
    // Decapsulate to retrieve the exact same shared secret User A generated
    const sharedSecret = ml_kem768.decapsulate(cipherBytes, skBytes);
    return Buffer.from(sharedSecret).toString('base64');
};

// Export the new function
module.exports = {
    generateSignatureKeys,
    generateKEMKeys,
    encapsulateSecret,
    decapsulateSecret // <-- Don't forget this!
};