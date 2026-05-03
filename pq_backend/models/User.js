const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    dilithiumPublicKey: {
        type: String,
        required: true
    },
    kyberPublicKey: {
        type: String,
        required: true
    },
    sessionToken: {
        type: String,
        required: true,
        unique: true
    }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
