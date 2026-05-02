require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');

// Import route modules
const keyRoutes = require('./routes/keyRoutes');
const handshakeRoutes = require('./routes/handshakeRoutes');
const messageRoutes = require('./routes/messageRoutes');

// Initialize Express App
const app = express();

// Connect to MongoDB Atlas
connectDB();

// ============================================================
// Security Middleware
// ============================================================

// helmet — sets sensible HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
app.use(helmet());

// M8 — rate limiting: max 20 requests per minute per IP on /api
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,   // 1 minute window
    max: 120,              // max 120 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
});

// Stricter limiter on registration to prevent username-spray
const registerLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'Too many registration attempts. Please wait before trying again.' }
});

app.use('/api', apiLimiter);

app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:3000'],
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' })); // Large limit for base64 key payloads

// ============================================================
// API Routes
// ============================================================

// Phase 2 — Key management & user registry (Member 2)
app.use('/api/keys/register', registerLimiter); // stricter rate limit on registration
app.use('/api/keys', keyRoutes);

// Phase 2 — Kyber KEM handshake protocol (Member 2)
app.use('/api/handshake', handshakeRoutes);

// Phase 2 — Encrypted message storage & retrieval (Member 2)
app.use('/api/messages', messageRoutes);

// ============================================================
// Health Check
// ============================================================
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'Post-Quantum Secure Communication API',
        version: '1.0.0',
        algorithms: {
            kem: 'ML-KEM-768 (Kyber)',
            signatures: 'ML-DSA-65 (Dilithium)',
            symmetric: 'AES-256-GCM'
        },
        endpoints: {
            keys: '/api/keys',
            handshake: '/api/handshake',
            messages: '/api/messages'
        }
    });
});

// ============================================================
// Global Error Handler
// ============================================================
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error.' });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`\nPost-Quantum Secure Chat Server running on port ${PORT}`);
    console.log(`Algorithms: ML-KEM-768 (Kyber) + ML-DSA-65 (Dilithium) + AES-256-GCM`);
    console.log(`API Health: http://localhost:${PORT}/\n`);
});