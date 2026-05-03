const mongoose = require('mongoose');

const HandshakeSchema = new mongoose.Schema({
    initiator: {
        type: String,
        required: true
    },
    recipient: {
        type: String,
        required: true
    },
    kyberCiphertext: {
        type: String,
        required: true
    },
    signature: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'completed'],
        default: 'pending'
    }
}, { timestamps: true });

HandshakeSchema.index({ initiator: 1, recipient: 1 }, { unique: true });

module.exports = mongoose.model('Handshake', HandshakeSchema);
