require('dotenv').config();
const express = require('express');
const cors = require('cors');
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
// Middleware
// ============================================================
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
    console.log(`\n🚀 Post-Quantum Secure Chat Server running on port ${PORT}`);
    console.log(`📡 Algorithms: ML-KEM-768 (Kyber) + ML-DSA-65 (Dilithium) + AES-256-GCM`);
    console.log(`🌐 API Health: http://localhost:${PORT}/\n`);
});