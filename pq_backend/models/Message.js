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
    // AES-GCM initialization vector (base64)
    iv: {
        type: String,
        required: true
    },
    // Dilithium digital signature over (encryptedContent + iv + timestamp) (base64)
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
