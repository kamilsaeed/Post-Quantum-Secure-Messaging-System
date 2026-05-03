const User = require('../models/User');

const requireAuth = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Missing or malformed Authorization header.' });
    }

    const token = authHeader.slice(7);
    if (!token) {
        return res.status(401).json({ message: 'Session token is empty.' });
    }

    try {
        const user = await User.findOne({ sessionToken: token });
        if (!user) {
            return res.status(401).json({ message: 'Invalid or expired session token.' });
        }
        req.authenticatedUser = user.username;
        next();
    } catch (err) {
        console.error('Auth middleware error:', err);
        res.status(500).json({ error: 'Server error during authentication.' });
    }
};

module.exports = { requireAuth };
