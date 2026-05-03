import { useState } from 'react';
import { generateIdentity, generateKEMKeys } from '../utils/crypto';
import { registerUser } from '../services/api';
import './Register.css';

export default function Register({ onRegisterSuccess }) {
    const [username, setUsername] = useState('');
    const [status, setStatus] = useState(null);
    const [loading, setLoading] = useState(false);
    const [generatedKeys, setGeneratedKeys] = useState(null);

    const handleRegister = async (e) => {
        e.preventDefault();
        if (!username.trim()) return;
        
        setLoading(true);
        setGeneratedKeys(null);
        setStatus({ type: 'info', text: '🔑 Generating ML-DSA-65 (Dilithium) key pair...' });

        try {
            const identityKeys = generateIdentity();
            setStatus({ type: 'info', text: '🔐 Generating ML-KEM-768 (Kyber) key pair...' });
            await new Promise(r => setTimeout(r, 200));

            const kemKeys = generateKEMKeys();
            setStatus({ type: 'info', text: '💾 Storing private keys securely in browser...' });
            await new Promise(r => setTimeout(r, 200));

            localStorage.setItem('pq_username', username.toLowerCase());
            localStorage.setItem('pq_dsa_private_key', identityKeys.privateKey);
            localStorage.setItem('pq_dsa_public_key', identityKeys.publicKey);
            localStorage.setItem('pq_kem_private_key', kemKeys.privateKey);
            localStorage.setItem('pq_kem_public_key', kemKeys.publicKey);

            setStatus({ type: 'info', text: '📡 Uploading public keys to server...' });

            await registerUser(
                username.toLowerCase(),
                identityKeys.publicKey,
                kemKeys.publicKey
            );

            setGeneratedKeys({
                dilithiumPubKey: identityKeys.publicKey.substring(0, 64) + '...',
                kyberPubKey: kemKeys.publicKey.substring(0, 64) + '...',
            });

            setStatus({ type: 'success', text: '✅ Identity registered! Quantum-resistant keys active.' });
            setTimeout(() => onRegisterSuccess(username.toLowerCase()), 1500);

        } catch (error) {
            console.error('Registration error:', error);
            let msg = 'Registration failed. Username may already be taken.';
            if (error.code === 'ERR_NETWORK') {
                msg = 'Cannot connect to backend server. Is it running on port 5000?';
            } else if (error.response?.status === 500) {
                msg = 'Backend server error. Check database connection (MongoDB IP whitelist).';
            } else if (error.response?.data?.message) {
                msg = error.response.data.message;
            }
            setStatus({ type: 'error', text: `❌ ${msg}` });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="register-wrapper">
            <div className="register-glow register-glow-1" />
            <div className="register-glow register-glow-2" />

            <div className="register-container animate-fade-in">
                <div className="register-header">
                    <div className="register-logo">
                        <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
                            <rect width="40" height="40" rx="12" fill="url(#grad)" />
                            <path d="M20 8L28 13V22L20 27L12 22V13L20 8Z" stroke="white" strokeWidth="2" fill="none" />
                            <circle cx="20" cy="19" r="3" fill="white" />
                            <defs>
                                <linearGradient id="grad" x1="0" y1="0" x2="40" y2="40">
                                    <stop offset="0%" stopColor="#7c3aed" />
                                    <stop offset="100%" stopColor="#06b6d4" />
                                </linearGradient>
                            </defs>
                        </svg>
                    </div>
                    <div>
                        <h1 className="register-title">QuantumShield</h1>
                        <p className="register-subtitle">Post-Quantum Secure Communications</p>
                    </div>
                </div>

                <div className="register-badges">
                    <span className="badge badge-purple">ML-KEM-768</span>
                    <span className="badge badge-cyan">ML-DSA-65</span>
                    <span className="badge badge-green">AES-256-GCM</span>
                </div>

                <p className="register-description">
                    Your identity uses <strong>lattice-based cryptography</strong> resistant to quantum computers.
                    Private keys are generated locally and never leave your device.
                </p>

                <form onSubmit={handleRegister} className="register-form">
                    <div className="form-group">
                        <label className="form-label">Username</label>
                        <input
                            id="register-username-input"
                            type="text"
                            className="input-field"
                            placeholder="Choose a unique identity (e.g. alice)"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            disabled={loading}
                            required
                            autoComplete="off"
                        />
                    </div>

                    <button
                        id="register-submit-btn"
                        type="submit"
                        className="btn btn-primary"
                        style={{ width: '100%' }}
                        disabled={loading || !username.trim()}
                    >
                        {loading ? (
                            <>
                                <span className="loading-spinner" />
                                Processing...
                            </>
                        ) : (
                            <>
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                </svg>
                                Generate Keys &amp; Register
                            </>
                        )}
                    </button>
                </form>

                {status && (
                    <div className={`register-status register-status-${status.type} animate-fade-in`}>
                        {status.text}
                    </div>
                )}

                {generatedKeys && (
                    <div className="key-preview animate-fade-in">
                        <div className="key-preview-title">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
                            </svg>
                            Generated Key Preview (public keys only)
                        </div>
                        <div className="key-preview-item">
                            <span className="key-preview-label">Dilithium PK:</span>
                            <code className="key-preview-value">{generatedKeys.dilithiumPubKey}</code>
                        </div>
                        <div className="key-preview-item">
                            <span className="key-preview-label">Kyber PK:</span>
                            <code className="key-preview-value">{generatedKeys.kyberPubKey}</code>
                        </div>
                    </div>
                )}

                <div className="register-threat-note">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                    <span>Protected against Dolev-Yao adversaries &amp; quantum-equipped attackers (Shor's Algorithm)</span>
                </div>
            </div>
        </div>
    );
}