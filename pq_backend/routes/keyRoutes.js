const express = require('express');
const router = express.Router();
const User = require('../models/User');

/**
 * POST /api/keys/register
 * 
 * Member 2 (Backend Developer) - Phase 2
 * Registers a new user and stores both their Dilithium (signature) 
 * and Kyber (KEM) public keys in MongoDB.
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

        // Check if username is already taken
        let user = await User.findOne({ username: username.toLowerCase() });
        if (user) {
            return res.status(400).json({ message: 'Username already taken. Please choose another.' });
        }

        // Save user with both public keys — private keys never leave the client
        user = new User({ 
            username: username.toLowerCase(), 
            dilithiumPublicKey,
            kyberPublicKey
        });
        await user.save();

        res.status(201).json({ 
            message: 'Identity registered successfully. Public keys stored on server.',
            username: user.username
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