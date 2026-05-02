const express = require('express');
const router = express.Router();
const Message = require('../models/Message');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');

/**
 * POST /api/messages/send
 *
 * Member 2 (Backend Developer) — Encrypted Message Storage
 *
 * Stores an AES-GCM encrypted message. The server NEVER sees the plaintext.
 * The message is encrypted client-side using the Kyber-derived shared secret.
 * The Dilithium signature allows the recipient to verify authenticity.
 *
 * Fixes applied:
 *  - C3: unique IV index on the Message model rejects exact replays at the DB layer
 *  - C6: requireAuth ensures the caller is the declared sender (token → username binding)
 *  - M7: conversation fetch uses .limit(100) to prevent unbounded loads
 *  - M9: read-receipts moved to a dedicated PATCH endpoint (see below)
 *
 * Body: {
 *   sender: string,
 *   recipient: string,
 *   encryptedContent: string (base64 AES-GCM ciphertext),
 *   iv: string (base64 AES-GCM IV — must be unique across all messages),
 *   signature: string (Dilithium signature over transcript-bound payload)
 * }
 */
router.post('/send', requireAuth, async (req, res) => {
    try {
        const { sender, recipient, encryptedContent, iv, signature } = req.body;

        if (!sender || !recipient || !encryptedContent || !iv || !signature) {
            return res.status(400).json({ message: 'Missing required message fields.' });
        }

        // C6 — enforce that the authenticated user is the declared sender
        if (req.authenticatedUser !== sender.toLowerCase()) {
            return res.status(403).json({ message: 'Sender does not match authenticated user.' });
        }

        // Verify recipient exists
        const recipientUser = await User.findOne({ username: recipient.toLowerCase() });
        if (!recipientUser) return res.status(404).json({ message: `Recipient '${recipient}' not found.` });

        const message = new Message({
            sender: sender.toLowerCase(),
            recipient: recipient.toLowerCase(),
            encryptedContent,
            iv,
            signature
        });

        try {
            await message.save();
        } catch (dbErr) {
            // Catch duplicate-key error from the unique IV index (C3 replay protection)
            if (dbErr.code === 11000) {
                return res.status(409).json({ message: 'Duplicate IV — possible replay attack rejected.' });
            }
            throw dbErr;
        }

        res.status(201).json({
            message: 'Encrypted message stored successfully.',
            messageId: message._id,
            timestamp: message.createdAt
        });
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ error: 'Server error storing message.' });
    }
});

/**
 * GET /api/messages/conversation/:userA/:userB
 *
 * Retrieves encrypted messages between two users (both directions),
 * ordered by creation time. Also returns each sender's Dilithium public key
 * so the recipient can verify each message's signature.
 *
 * Fixes applied:
 *  - C6: requireAuth; only the authenticated user may fetch their own conversations
 *  - M7: .limit(100) added — fetch latest 100 messages maximum
 *  - M9: read-receipt write removed from this polling endpoint (moved to PATCH /read)
 */
router.get('/conversation/:userA/:userB', requireAuth, async (req, res) => {
    try {
        const { userA, userB } = req.params;
        const uA = userA.toLowerCase();
        const uB = userB.toLowerCase();

        // C6 — ensure the caller is one of the two participants
        if (req.authenticatedUser !== uA && req.authenticatedUser !== uB) {
            return res.status(403).json({ message: 'You are not a participant in this conversation.' });
        }

        // M7 — limit to the most recent 100 messages to prevent unbounded loads
        const messages = await Message.find({
            $or: [
                { sender: uA, recipient: uB },
                { sender: uB, recipient: uA }
            ]
        })
            .sort({ createdAt: 1 })
            .limit(100);

        // Attach Dilithium public keys for signature verification
        const [userAData, userBData] = await Promise.all([
            User.findOne({ username: uA }, 'dilithiumPublicKey'),
            User.findOne({ username: uB }, 'dilithiumPublicKey')
        ]);

        const publicKeys = {
            [uA]: userAData?.dilithiumPublicKey,
            [uB]: userBData?.dilithiumPublicKey
        };

        res.status(200).json({
            messages,
            publicKeys // For client-side signature verification
        });
    } catch (error) {
        console.error('Get conversation error:', error);
        res.status(500).json({ error: 'Server error retrieving conversation.' });
    }
});

/**
 * PATCH /api/messages/read/:userA/:userB
 *
 * M9 fix: explicit read-receipt endpoint, called once when a chat is opened
 * rather than on every 5-second poll.
 * Marks all unread messages from userB → userA as read.
 * C6: caller must be userA (the reader).
 */
router.patch('/read/:userA/:userB', requireAuth, async (req, res) => {
    try {
        const uA = req.params.userA.toLowerCase();
        const uB = req.params.userB.toLowerCase();

        if (req.authenticatedUser !== uA) {
            return res.status(403).json({ message: 'You can only mark your own messages as read.' });
        }

        await Message.updateMany(
            { sender: uB, recipient: uA, read: false },
            { read: true }
        );

        res.status(200).json({ message: 'Messages marked as read.' });
    } catch (error) {
        console.error('Read-receipt error:', error);
        res.status(500).json({ error: 'Server error marking messages as read.' });
    }
});

/**
 * GET /api/messages/unread/:username
 *
 * Returns count of unread messages per sender for notification badges.
 * C6: caller must be the username they are querying.
 */
router.get('/unread/:username', requireAuth, async (req, res) => {
    try {
        const username = req.params.username.toLowerCase();

        if (req.authenticatedUser !== username) {
            return res.status(403).json({ message: 'You can only query your own unread counts.' });
        }

        const unreadCounts = await Message.aggregate([
            { $match: { recipient: username, read: false } },
            { $group: { _id: '$sender', count: { $sum: 1 } } }
        ]);

        const result = {};
        unreadCounts.forEach(item => { result[item._id] = item.count; });

        res.status(200).json({ unread: result });
    } catch (error) {
        console.error('Unread count error:', error);
        res.status(500).json({ error: 'Server error retrieving unread counts.' });
    }
});

module.exports = router;
