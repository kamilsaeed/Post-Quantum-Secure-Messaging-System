const express = require('express');
const router = express.Router();
const Handshake = require('../models/Handshake');
const User = require('../models/User');

/**
 * POST /api/handshake/initiate
 * 
 * Member 2 (Backend Developer) — Kyber KEM Handshake Initiation
 * 
 * User A has:
 *   1. Fetched User B's Kyber public key
 *   2. Ran ml_kem768.encapsulate(B_kyber_pk) -> { ciphertext, sharedSecret }
 *   3. Signed the ciphertext with their Dilithium private key
 *   4. Kept the sharedSecret locally (never sent to server)
 *   5. Sent the ciphertext + signature here for B to retrieve
 */
router.post('/initiate', async (req, res) => {
    try {
        const { initiator, recipient, kyberCiphertext, signature } = req.body;

        if (!initiator || !recipient || !kyberCiphertext || !signature) {
            return res.status(400).json({ message: 'Missing required handshake fields.' });
        }

        // Verify both users exist
        const [initiatorUser, recipientUser] = await Promise.all([
            User.findOne({ username: initiator.toLowerCase() }),
            User.findOne({ username: recipient.toLowerCase() })
        ]);

        if (!initiatorUser) return res.status(404).json({ message: `User '${initiator}' not found.` });
        if (!recipientUser) return res.status(404).json({ message: `User '${recipient}' not found.` });

        // Upsert: replace existing handshake if one already exists (re-keying)
        const handshake = await Handshake.findOneAndUpdate(
            { initiator: initiator.toLowerCase(), recipient: recipient.toLowerCase() },
            { kyberCiphertext, signature, status: 'pending' },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        res.status(201).json({ 
            message: 'Handshake initiated. Ciphertext stored for recipient to retrieve.',
            handshakeId: handshake._id
        });
    } catch (error) {
        console.error('Handshake initiation error:', error);
        res.status(500).json({ error: 'Server error during handshake initiation.' });
    }
});

/**
 * GET /api/handshake/pending/:username
 * 
 * User B polls this to see if someone has sent them a Kyber KEM ciphertext.
 * Returns all pending handshakes where this user is the recipient.
 * Also returns the initiator's Dilithium public key so B can verify the signature.
 */
router.get('/pending/:username', async (req, res) => {
    try {
        const username = req.params.username.toLowerCase();
        
        const handshakes = await Handshake.find({ 
            recipient: username, 
            status: 'pending' 
        });

        // Attach the initiator's public key for signature verification
        const enriched = await Promise.all(handshakes.map(async (h) => {
            const initiatorUser = await User.findOne({ username: h.initiator }, 'dilithiumPublicKey kyberPublicKey');
            return {
                _id: h._id,
                initiator: h.initiator,
                recipient: h.recipient,
                kyberCiphertext: h.kyberCiphertext,
                signature: h.signature,
                initiatorDilithiumPublicKey: initiatorUser?.dilithiumPublicKey,
                createdAt: h.createdAt
            };
        }));

        res.status(200).json({ handshakes: enriched });
    } catch (error) {
        console.error('Pending handshakes error:', error);
        res.status(500).json({ error: 'Server error retrieving pending handshakes.' });
    }
});

/**
 * PATCH /api/handshake/complete/:handshakeId
 * 
 * User B marks the handshake as complete after successfully decapsulating.
 * This is a status update only — the shared secret is never sent to the server.
 */
router.patch('/complete/:handshakeId', async (req, res) => {
    try {
        const handshake = await Handshake.findByIdAndUpdate(
            req.params.handshakeId,
            { status: 'completed' },
            { new: true }
        );

        if (!handshake) {
            return res.status(404).json({ message: 'Handshake not found.' });
        }

        res.status(200).json({ 
            message: 'Handshake completed. Both parties now share a post-quantum secure secret.',
            handshake 
        });
    } catch (error) {
        console.error('Handshake completion error:', error);
        res.status(500).json({ error: 'Server error completing handshake.' });
    }
});

/**
 * GET /api/handshake/status/:userA/:userB
 * 
 * Checks handshake status between two users (either direction).
 */
router.get('/status/:userA/:userB', async (req, res) => {
    try {
        const { userA, userB } = req.params;
        
        const handshake = await Handshake.findOne({
            $or: [
                { initiator: userA.toLowerCase(), recipient: userB.toLowerCase() },
                { initiator: userB.toLowerCase(), recipient: userA.toLowerCase() }
            ]
        });

        if (!handshake) {
            return res.status(200).json({ status: 'none' });
        }

        res.status(200).json({ 
            status: handshake.status,
            initiator: handshake.initiator,
            handshakeId: handshake._id
        });
    } catch (error) {
        console.error('Handshake status error:', error);
        res.status(500).json({ error: 'Server error checking handshake status.' });
    }
});

module.exports = router;
