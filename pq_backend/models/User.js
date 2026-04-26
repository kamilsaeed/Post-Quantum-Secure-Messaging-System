const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true,
        trim: true,
        lowercase: true
    },
    // Dilithium public key for verifying digital signatures
    dilithiumPublicKey: { 
        type: String, 
        required: true 
    },
    // Kyber public key for Key Encapsulation Mechanism (KEM)
    kyberPublicKey: {
        type: String,
        required: true
    },
    // Online status tracking
    isOnline: {
        type: Boolean,
        default: false
    },
    lastSeen: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);