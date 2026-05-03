const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');

const generateSignatureKeys = () => {
    const keys = ml_dsa65.keygen();
    return {
        publicKey: Buffer.from(keys.publicKey).toString('base64'),
        privateKey: Buffer.from(keys.secretKey).toString('base64')
    };
};

const generateKEMKeys = () => {
    const keys = ml_kem768.keygen();
    return {
        publicKey: Buffer.from(keys.publicKey).toString('base64'),
        privateKey: Buffer.from(keys.secretKey).toString('base64')
    };
};

const encapsulateSecret = (recipientPublicKeyBase64) => {
    const pkBytes = Uint8Array.from(Buffer.from(recipientPublicKeyBase64, 'base64'));
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(pkBytes);
    return {
        ciphertext: Buffer.from(cipherText).toString('base64'),
        sharedSecret: Buffer.from(sharedSecret).toString('base64')
    };
};

const decapsulateSecret = (ciphertextBase64, privateKeyBase64) => {
    const cipherBytes = Uint8Array.from(Buffer.from(ciphertextBase64, 'base64'));
    const skBytes = Uint8Array.from(Buffer.from(privateKeyBase64, 'base64'));

    const sharedSecret = ml_kem768.decapsulate(cipherBytes, skBytes);
    return Buffer.from(sharedSecret).toString('base64');
};

module.exports = {
    generateSignatureKeys,
    generateKEMKeys,
    encapsulateSecret,
    decapsulateSecret
};
