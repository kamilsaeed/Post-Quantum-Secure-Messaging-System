const express = require('express');
const router = express.Router();
const Message = require('../models/Message');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');

router.post('/send', requireAuth, async (req, res) => {
    try {
        const { sender, recipient, encryptedContent, iv, signature } = req.body;

        if (!sender || !recipient || !encryptedContent || !iv || !signature) {
            return res.status(400).json({ message: 'Missing required message fields.' });
        }

        if (req.authenticatedUser !== sender.toLowerCase()) {
            return res.status(403).json({ message: 'Sender does not match authenticated user.' });
        }

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

router.get('/conversation/:userA/:userB', requireAuth, async (req, res) => {
    try {
        const { userA, userB } = req.params;
        const uA = userA.toLowerCase();
        const uB = userB.toLowerCase();

        if (req.authenticatedUser !== uA && req.authenticatedUser !== uB) {
            return res.status(403).json({ message: 'You are not a participant in this conversation.' });
        }

        const messages = await Message.find({
            $or: [
                { sender: uA, recipient: uB },
                { sender: uB, recipient: uA }
            ]
        })
            .sort({ createdAt: 1 })
            .limit(100);

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
            publicKeys
        });
    } catch (error) {
        console.error('Get conversation error:', error);
        res.status(500).json({ error: 'Server error retrieving conversation.' });
    }
});

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
