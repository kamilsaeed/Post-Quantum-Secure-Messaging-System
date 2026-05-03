const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
    sender: {
        type: String,
        required: true,
        ref: 'User'
    },
    recipient: {
        type: String,
        required: true,
        ref: 'User'
    },
    encryptedContent: {
        type: String,
        required: true
    },
    // Unique iv → duplicate insert fails on replay of same (ciphertext, iv, …) triple.
    iv: {
        type: String,
        required: true,
        unique: true
    },
    signature: {
        type: String,
        required: true
    },
    read: {
        type: Boolean,
        default: false
    }
}, { timestamps: true });

MessageSchema.index({ sender: 1, recipient: 1, createdAt: -1 });

module.exports = mongoose.model('Message', MessageSchema);
