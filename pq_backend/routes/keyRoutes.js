const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const User = require('../models/User');

/**
 * POST /api/keys/register
 *
 * Member 2 (Backend Developer) - Phase 2
 * Registers a new user and stores both their Dilithium (signature)
 * and Kyber (KEM) public keys in MongoDB.
 *
 * Fixes applied:
 *  - M8: username validated against /^[a-z0-9_]{3,32}$/ before storing
 *  - C6: generates and returns a session token so the client can
 *        authenticate subsequent API calls via the requireAuth middleware
 *
 * Private keys NEVER touch the server — they are generated and stored
 * exclusively on the client browser.
 */
router.post('/register', async (req, res) => {
    try {
        const { username, dilithiumPublicKey, kyberPublicKey } = req.body;

        if (!username || !dilithiumPublicKey || !kyberPublicKey) {
            return res.status(400).json({ message: 'Username, Dilithium public key, and Kyber public key are required.' });
        }

        // M8 — validate username format
        const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
        if (!USERNAME_RE.test(username.toLowerCase())) {
            return res.status(400).json({
                message: 'Username must be 3–32 characters and contain only lowercase letters, digits, or underscores.'
            });
        }

        // Check if username is already taken
        let user = await User.findOne({ username: username.toLowerCase() });
        if (user) {
            return res.status(400).json({ message: 'Username already taken. Please choose another.' });
        }

        // C6 — generate a cryptographically random session token
        const sessionToken = crypto.randomBytes(32).toString('hex');

        // Save user with both public keys and the session token
        user = new User({
            username: username.toLowerCase(),
            dilithiumPublicKey,
            kyberPublicKey,
            sessionToken
        });
        await user.save();

        res.status(201).json({
            message: 'Identity registered successfully. Public keys stored on server.',
            username: user.username,
            sessionToken   // returned once — client must persist this
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

/**
 * GET /api/keys/publicKey/:username
 *
 * Retrieves a user's public keys for:
 *   1. Verifying their Dilithium signatures
 *   2. Performing Kyber KEM encapsulation for key exchange
 */
router.get('/publicKey/:username', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username.toLowerCase() });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({
            username: user.username,
            dilithiumPublicKey: user.dilithiumPublicKey,
            kyberPublicKey: user.kyberPublicKey,
            registeredAt: user.createdAt
        });
    } catch (error) {
        console.error('Key retrieval error:', error);
        res.status(500).json({ error: 'Server error while retrieving public key.' });
    }
});

/**
 * GET /api/keys/users
 *
 * Returns a list of all registered users (username only) for the
 * contact list / user directory UI.
 */
router.get('/users', async (req, res) => {
    try {
        const users = await User.find({}, 'username createdAt').sort({ username: 1 });
        res.status(200).json({ users });
    } catch (error) {
        console.error('User list error:', error);
        res.status(500).json({ error: 'Server error retrieving user list.' });
    }
});

module.exports = router;