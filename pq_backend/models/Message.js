const mongoose = require('mongoose');

// Each message is encrypted with AES-GCM using the Kyber-derived shared secret
const MessageSchema = new mongoose.Schema({
    // The sender's username
    sender: {
        type: String,
        required: true,
        ref: 'User'
    },
    // The recipient's username  
    recipient: {
        type: String,
        required: true,
        ref: 'User'
    },
    // AES-GCM encrypted ciphertext (base64)
    encryptedContent: {
        type: String,
        required: true
    },
    // AES-GCM initialization vector (base64).
    // Unique index enforces replay protection (C3): an attacker replaying
    // an identical (ciphertext, iv, signature) triple will get a duplicate-key
    // error before the message is stored.
    iv: {
        type: String,
        required: true,
        unique: true
    },
    // Dilithium signature over the transcript-bound payload (C4):
    // "PQMSG-v1|<sender>|<recipient>|<iv>|<encryptedContent>"
    signature: {
        type: String,
        required: true
    },
    // Flag to show if the message has been read
    read: {
        type: Boolean,
        default: false
    }
}, { timestamps: true });

// Index for efficient conversation queries
MessageSchema.index({ sender: 1, recipient: 1, createdAt: -1 });

module.exports = mongoose.model('Message', MessageSchema);

