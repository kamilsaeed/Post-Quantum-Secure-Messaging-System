const mongoose = require('mongoose');

// Stores the Kyber KEM handshake ciphertexts between users
// User A encapsulates a shared secret -> stores ciphertext here -> User B decapsulates
const HandshakeSchema = new mongoose.Schema({
    // Who initiated the handshake (User A)
    initiator: {
        type: String,
        required: true
    },
    // The target of the handshake (User B)
    recipient: {
        type: String,
        required: true
    },
    // Kyber KEM ciphertext (encapsulated shared secret) - base64
    kyberCiphertext: {
        type: String,
        required: true
    },
    // Dilithium signature over the kyberCiphertext, proving authenticity
    signature: {
        type: String,
        required: true
    },
    // Status: 'pending' -> User B has not yet decapsulated
    //         'completed' -> Both sides have the shared secret
    status: {
        type: String,
        enum: ['pending', 'completed'],
        default: 'pending'
    }
}, { timestamps: true });

// Unique constraint: only one active handshake per pair
HandshakeSchema.index({ initiator: 1, recipient: 1 }, { unique: true });

module.exports = mongoose.model('Handshake', HandshakeSchema);
