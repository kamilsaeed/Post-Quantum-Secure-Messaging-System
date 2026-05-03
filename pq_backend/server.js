require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');

const keyRoutes = require('./routes/keyRoutes');
const handshakeRoutes = require('./routes/handshakeRoutes');
const messageRoutes = require('./routes/messageRoutes');

const app = express();

connectDB();

app.use(helmet());

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
});

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
app.use(express.json({ limit: '10mb' }));

app.use('/api/keys/register', registerLimiter);
app.use('/api/keys', keyRoutes);

app.use('/api/handshake', handshakeRoutes);

app.use('/api/messages', messageRoutes);

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

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error.' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`\nPost-Quantum Secure Chat Server running on port ${PORT}`);
    console.log(`Algorithms: ML-KEM-768 (Kyber) + ML-DSA-65 (Dilithium) + AES-256-GCM`);
    console.log(`API Health: http://localhost:${PORT}/\n`);
});
