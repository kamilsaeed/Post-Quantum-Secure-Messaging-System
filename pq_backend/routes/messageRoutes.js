const express = require('express');
const router = express.Router();
const Message = require('../models/Message');
const User = require('../models/User');

/**
 * POST /api/messages/send
 * 
 * Member 2 (Backend Developer) — Encrypted Message Storage
 * 
 * Stores an AES-GCM encrypted message. The server NEVER sees the plaintext.
 * The message is encrypted client-side using the Kyber-derived shared secret.
 * The Dilithium signature allows the recipient to verify authenticity.
 * 
 * Body: {
 *   sender: string,
 *   recipient: string,
 *   encryptedContent: string (base64 AES-GCM ciphertext),
 *   iv: string (base64 AES-GCM IV),
 *   signature: string (Dilithium signature over encryptedContent+iv)
 * }
 */
router.post('/send', async (req, res) => {
    try {
        const { sender, recipient, encryptedContent, iv, signature } = req.body;

        if (!sender || !recipient || !encryptedContent || !iv || !signature) {
            return res.status(400).json({ message: 'Missing required message fields.' });
        }

        // Verify both users exist
        const [senderUser, recipientUser] = await Promise.all([
            User.findOne({ username: sender.toLowerCase() }),
            User.findOne({ username: recipient.toLowerCase() })
        ]);

        if (!senderUser) return res.status(404).json({ message: `Sender '${sender}' not found.` });
        if (!recipientUser) return res.status(404).json({ message: `Recipient '${recipient}' not found.` });

        const message = new Message({
            sender: sender.toLowerCase(),
            recipient: recipient.toLowerCase(),
            encryptedContent,
            iv,
            signature
        });
        await message.save();

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
 * Retrieves all encrypted messages between two users (both directions),
 * ordered by creation time. Also returns the sender's Dilithium public key
 * so the recipient can verify each message's signature.
 */
router.get('/conversation/:userA/:userB', async (req, res) => {
    try {
        const { userA, userB } = req.params;
        const uA = userA.toLowerCase();
        const uB = userB.toLowerCase();

        const messages = await Message.find({
            $or: [
                { sender: uA, recipient: uB },
                { sender: uB, recipient: uA }
            ]
        }).sort({ createdAt: 1 }); // Chronological order

        // Attach Dilithium public keys for signature verification
        const [userAData, userBData] = await Promise.all([
            User.findOne({ username: uA }, 'dilithiumPublicKey'),
            User.findOne({ username: uB }, 'dilithiumPublicKey')
        ]);

        const publicKeys = {
            [uA]: userAData?.dilithiumPublicKey,
            [uB]: userBData?.dilithiumPublicKey
        };

        // Mark messages as read
        await Message.updateMany(
            { sender: uB, recipient: uA, read: false },
            { read: true }
        );

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
 * GET /api/messages/unread/:username
 * 
 * Returns count of unread messages per sender for notification badges.
 */
router.get('/unread/:username', async (req, res) => {
    try {
        const username = req.params.username.toLowerCase();
        
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
