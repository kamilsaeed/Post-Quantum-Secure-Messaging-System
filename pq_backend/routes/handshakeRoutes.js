const express = require('express');
const router = express.Router();
const Handshake = require('../models/Handshake');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');

/**
 * POST /api/handshake/initiate
 *
 * Member 2 (Backend Developer) — Kyber KEM Handshake Initiation
 *
 * User A has:
 *   1. Fetched User B's Kyber public key
 *   2. Ran ml_kem768.encapsulate(B_kyber_pk) -> { ciphertext, sharedSecret }
 *   3. Signed the transcript-bound payload with their Dilithium private key
 *   4. Kept the sharedSecret locally (never sent to server)
 *   5. Sent the ciphertext + signature here for B to retrieve
 *
 * C6 fix: requireAuth + initiator must match the authenticated user.
 */
router.post('/initiate', requireAuth, async (req, res) => {
    try {
        const { initiator, recipient, kyberCiphertext, signature } = req.body;

        if (!initiator || !recipient || !kyberCiphertext || !signature) {
            return res.status(400).json({ message: 'Missing required handshake fields.' });
        }

        // C6 — the authenticated user must be the declared initiator
        if (req.authenticatedUser !== initiator.toLowerCase()) {
            return res.status(403).json({ message: 'Initiator does not match authenticated user.' });
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
 *
 * M3 fix: uses MongoDB $lookup aggregation instead of N individual User.findOne calls.
 * C6 fix: requireAuth + caller must be the username they are querying.
 *
 * C5 note: the initiatorDilithiumPublicKey is fetched from the same server, so this
 * is a TOFU (Trust-On-First-Use) model. Users should verify Safety Numbers out-of-band.
 */
router.get('/pending/:username', requireAuth, async (req, res) => {
    try {
        const username = req.params.username.toLowerCase();

        // C6 — user may only poll their own pending handshakes
        if (req.authenticatedUser !== username) {
            return res.status(403).json({ message: 'You can only query your own pending handshakes.' });
        }

        // M3 — single aggregation query with $lookup instead of N+1 round-trips
        const enriched = await Handshake.aggregate([
            { $match: { recipient: username, status: 'pending' } },
            {
                $lookup: {
                    from: 'users',
                    localField: 'initiator',
                    foreignField: 'username',
                    as: 'initiatorData'
                }
            },
            {
                $project: {
                    _id: 1,
                    initiator: 1,
                    recipient: 1,
                    kyberCiphertext: 1,
                    signature: 1,
                    createdAt: 1,
                    // C5: surfaced so client can display Safety Number for out-of-band verification
                    initiatorDilithiumPublicKey: { $arrayElemAt: ['$initiatorData.dilithiumPublicKey', 0] }
                }
            }
        ]);

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
 *
 * C6 fix: requireAuth + ownership check (caller must be the recipient of this handshake).
 */
router.patch('/complete/:handshakeId', requireAuth, async (req, res) => {
    try {
        const handshake = await Handshake.findById(req.params.handshakeId);

        if (!handshake) {
            return res.status(404).json({ message: 'Handshake not found.' });
        }

        // C6 — only the intended recipient may complete this handshake
        if (req.authenticatedUser !== handshake.recipient) {
            return res.status(403).json({ message: 'Only the handshake recipient may mark it as complete.' });
        }

        handshake.status = 'completed';
        await handshake.save();

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
 * C6: caller must be one of the two participants.
 */
router.get('/status/:userA/:userB', requireAuth, async (req, res) => {
    try {
        const { userA, userB } = req.params;
        const uA = userA.toLowerCase();
        const uB = userB.toLowerCase();

        if (req.authenticatedUser !== uA && req.authenticatedUser !== uB) {
            return res.status(403).json({ message: 'You are not a participant in this handshake.' });
        }

        const handshake = await Handshake.findOne({
            $or: [
                { initiator: uA, recipient: uB },
                { initiator: uB, recipient: uA }
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
