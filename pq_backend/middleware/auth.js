const User = require('../models/User');

/**
 * Session-token authentication middleware (C6 fix).
 *
 * Every protected route must include:
 *   Authorization: Bearer <sessionToken>
 *
 * The middleware:
 *  1. Extracts the token from the Authorization header.
 *  2. Looks up the User by sessionToken.
 *  3. Attaches req.authenticatedUser for downstream use.
 *
 * This prevents anonymous submissions — the caller must have obtained
 * a valid session token by registering (POST /api/keys/register).
 */
const requireAuth = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Missing or malformed Authorization header.' });
    }

    const token = authHeader.slice(7); // strip "Bearer "
    if (!token) {
        return res.status(401).json({ message: 'Session token is empty.' });
    }

    try {
        const user = await User.findOne({ sessionToken: token });
        if (!user) {
            return res.status(401).json({ message: 'Invalid or expired session token.' });
        }
        req.authenticatedUser = user.username; // available to all route handlers
        next();
    } catch (err) {
        console.error('Auth middleware error:', err);
        res.status(500).json({ error: 'Server error during authentication.' });
    }
};

module.exports = { requireAuth };
