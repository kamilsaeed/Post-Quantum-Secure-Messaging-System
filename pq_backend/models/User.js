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
    // Opaque session token issued at registration (C6 — API authentication)
    sessionToken: {
        type: String,
        required: true,
        unique: true
    }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);