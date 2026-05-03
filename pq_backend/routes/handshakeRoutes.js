const express = require('express');
const router = express.Router();
const Handshake = require('../models/Handshake');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');

router.post('/initiate', requireAuth, async (req, res) => {
    try {
        const { initiator, recipient, kyberCiphertext, signature } = req.body;

        if (!initiator || !recipient || !kyberCiphertext || !signature) {
            return res.status(400).json({ message: 'Missing required handshake fields.' });
        }

        if (req.authenticatedUser !== initiator.toLowerCase()) {
            return res.status(403).json({ message: 'Initiator does not match authenticated user.' });
        }

        const [initiatorUser, recipientUser] = await Promise.all([
            User.findOne({ username: initiator.toLowerCase() }),
            User.findOne({ username: recipient.toLowerCase() })
        ]);

        if (!initiatorUser) return res.status(404).json({ message: `User '${initiator}' not found.` });
        if (!recipientUser) return res.status(404).json({ message: `User '${recipient}' not found.` });

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

router.get('/pending/:username', requireAuth, async (req, res) => {
    try {
        const username = req.params.username.toLowerCase();

        if (req.authenticatedUser !== username) {
            return res.status(403).json({ message: 'You can only query your own pending handshakes.' });
        }

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

router.patch('/complete/:handshakeId', requireAuth, async (req, res) => {
    try {
        const handshake = await Handshake.findById(req.params.handshakeId);

        if (!handshake) {
            return res.status(404).json({ message: 'Handshake not found.' });
        }

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
