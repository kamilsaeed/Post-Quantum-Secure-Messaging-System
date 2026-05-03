import { useState, useEffect } from 'react';
import Register from './components/Register';
import Chat from './components/Chat';
import ThreatModel from './components/ThreatModel';
import MetricsPanel from './components/MetricsPanel';
import './App.css';

export default function App() {
    const [currentUser, setCurrentUser] = useState(null);
    const [showThreatModel, setShowThreatModel] = useState(false);
    const [showMetrics, setShowMetrics] = useState(false);
    const [appReady, setAppReady] = useState(false);

    useEffect(() => {
        const saved = localStorage.getItem('pq_username');
        if (saved) {
            const hasDSAKey = !!localStorage.getItem('pq_dsa_private_key');
            const hasKEMKey = !!localStorage.getItem('pq_kem_private_key');
            if (hasDSAKey && hasKEMKey) {
                setCurrentUser(saved);
            } else {
                for (const key of Object.keys(localStorage)) {
                    if (key.startsWith('pq_')) localStorage.removeItem(key);
                }
            }
        }
        setAppReady(true);
    }, []);

    const handleLogout = () => {
        for (const key of Object.keys(localStorage)) {
            if (key.startsWith('pq_')) localStorage.removeItem(key);
        }
        setCurrentUser(null);
    };

    const handleRegisterSuccess = (username) => {
        setCurrentUser(username);
    };

    if (!appReady) {
        return (
            <div className="app-loading">
                <div className="loading-spinner" style={{ width: 32, height: 32 }} />
                <span>Initializing cryptographic context...</span>
            </div>
        );
    }

    return (
        <div className="app-root">
            {currentUser && (
                <nav className="app-nav">
                    <div className="app-nav-left">
                        <div className="app-nav-logo">
                            <svg width="24" height="24" viewBox="0 0 40 40" fill="none">
                                <rect width="40" height="40" rx="10" fill="url(#navGrad)" />
                                <path d="M20 8L28 13V22L20 27L12 22V13L20 8Z" stroke="white" strokeWidth="2" fill="none" />
                                <circle cx="20" cy="19" r="3" fill="white" />
                                <defs>
                                    <linearGradient id="navGrad" x1="0" y1="0" x2="40" y2="40">
                                        <stop offset="0%" stopColor="#7c3aed" />
                                        <stop offset="100%" stopColor="#06b6d4" />
                                    </linearGradient>
                                </defs>
                            </svg>
                            <span className="app-nav-title">QuantumShield</span>
                        </div>
                        <span className="badge badge-green" style={{ fontSize: 11 }}>
                            <span className="pulse-dot" style={{ width: 6, height: 6 }} />
                            PQ-Secure
                        </span>
                    </div>
                    <div className="app-nav-right">
                        <button
                            id="threat-model-nav-btn"
                            className="btn btn-ghost btn-sm"
                            onClick={() => setShowThreatModel(true)}
                            title="View Formal Threat Model"
                        >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                            Threat Model
                        </button>

                        <button
                            id="metrics-nav-btn"
                            className="btn btn-ghost btn-sm"
                            onClick={() => setShowMetrics(true)}
                            title="View QA Metrics & Benchmarks"
                        >
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <polyline points="22,12 18,12 15,21 9,3 6,12 2,12" />
                            </svg>
                            QA Metrics
                        </button>
                    </div>
                </nav>
            )}

            <main className="app-content">
                {!currentUser ? (
                    <Register onRegisterSuccess={handleRegisterSuccess} />
                ) : (
                    <Chat
                        currentUser={currentUser}
                        onLogout={handleLogout}
                    />
                )}
            </main>

            {showThreatModel && (
                <ThreatModel onClose={() => setShowThreatModel(false)} />
            )}
            {showMetrics && (
                <MetricsPanel onClose={() => setShowMetrics(false)} />
            )}
        </div>
    );
}