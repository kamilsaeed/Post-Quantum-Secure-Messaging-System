const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const User = require('../models/User');

router.post('/register', async (req, res) => {
    try {
        const { username, dilithiumPublicKey, kyberPublicKey } = req.body;

        if (!username || !dilithiumPublicKey || !kyberPublicKey) {
            return res.status(400).json({ message: 'Username, Dilithium public key, and Kyber public key are required.' });
        }

        const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
        if (!USERNAME_RE.test(username.toLowerCase())) {
            return res.status(400).json({
                message: 'Username must be 3–32 characters and contain only lowercase letters, digits, or underscores.'
            });
        }

        let user = await User.findOne({ username: username.toLowerCase() });
        if (user) {
            return res.status(400).json({ message: 'Username already taken. Please choose another.' });
        }

        const sessionToken = crypto.randomBytes(32).toString('hex');

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
            sessionToken
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

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
