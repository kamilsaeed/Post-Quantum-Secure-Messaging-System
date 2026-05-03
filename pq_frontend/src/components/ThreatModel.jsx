import './ThreatModel.css';

export default function ThreatModel({ onClose }) {
    const threats = [
        {
            id: 'T1',
            category: 'Network Eavesdropping (Dolev-Yao)',
            adversaryCapability: 'Intercepts all ciphertext in transit',
            classicalMitigation: 'TLS / AES-256',
            pqMitigation: 'ML-KEM-768 ensures shared secret is indistinguishable from random. AES-256-GCM ciphertext is semantically secure.',
            severity: 'critical',
            status: 'mitigated',
        },
        {
            id: 'T2',
            category: "Shor's Algorithm (Quantum Key Break)",
            adversaryCapability: 'Quantum computer breaks RSA/ECC in polynomial time',
            classicalMitigation: 'RSA-4096 / ECDH — VULNERABLE',
            pqMitigation: 'ML-KEM-768 is based on Module-LWE (lattice hardness). No known quantum algorithm breaks LWE efficiently.',
            severity: 'critical',
            status: 'mitigated',
        },
        {
            id: 'T3',
            category: "Grover's Algorithm (Symmetric Key Speed-up)",
            adversaryCapability: 'Quadratic speed-up in brute-forcing symmetric keys',
            classicalMitigation: 'AES-128 reduced to 64-bit effective security',
            pqMitigation: "AES-256-GCM used. Grover's reduces to 128-bit effective security — still infeasible.",
            severity: 'high',
            status: 'mitigated',
        },
        {
            id: 'T4',
            category: 'Man-in-the-Middle (Identity Spoofing)',
            adversaryCapability: 'Replaces public keys during transit, impersonates users',
            classicalMitigation: 'PKI certificates — depends on CA trust',
            pqMitigation: 'ML-DSA-65 (Dilithium) signs all handshake ciphertexts with transcript binding (sender|recipient|ciphertext). Recipient verifies identity before decapsulating. Limitation: pubkey↔username mapping is TOFU — verify Safety Numbers out-of-band.',
            severity: 'critical',
            status: 'partial',
        },
        {
            id: 'T5',
            category: 'Replay Attack',
            adversaryCapability: 'Re-sends old encrypted messages to impersonate user',
            classicalMitigation: 'Timestamps / sequence numbers',
            pqMitigation: 'AES-GCM with fresh random IV per message (96-bit). Unique IV index on the database rejects exact-replay of any (ciphertext, IV, signature) triple. Signatures are transcript-bound (sender|recipient|IV|ciphertext), preventing cross-conversation replay.',
            severity: 'medium',
            status: 'mitigated',
        },
        {
            id: 'T6',
            category: 'Key Exfiltration (Server Compromise)',
            adversaryCapability: 'Attacker compromises the server and steals keys',
            classicalMitigation: 'HSMs / secure enclaves',
            pqMitigation: 'Private keys NEVER sent to server. Server stores only public keys + ciphertexts. Zero-knowledge server architecture.',
            severity: 'critical',
            status: 'mitigated',
        },
        {
            id: 'T7',
            category: 'Harvest Now, Decrypt Later (HNDL)',
            adversaryCapability: 'Adversary stores classical ciphertext to decrypt when quantum computers mature',
            classicalMitigation: 'None — classical systems are retroactively vulnerable',
            pqMitigation: 'ML-KEM-768 ciphertexts are quantum-resistant (LWE hardness). Stored ciphertexts cannot be broken by future quantum computers. Limitation: this system uses a static per-contact shared secret (not ephemeral per-session), so it does not provide perfect forward secrecy — compromise of the stored secret exposes all past messages.',
            severity: 'high',
            status: 'partial',
        },
        {
            id: 'T8',
            category: 'Message Tampering (Integrity Attack)',
            adversaryCapability: 'Modifies ciphertext bits in transit',
            classicalMitigation: 'HMAC / digital signatures',
            pqMitigation: 'AES-GCM provides authenticated encryption (GCM tag). Additionally, ML-DSA-65 signature on ciphertext.',
            severity: 'high',
            status: 'mitigated',
        },
    ];

    const assumptions = [
        'The browser environment is trusted (client-side code integrity is assumed)',
        'MongoDB Atlas transport is TLS-protected (defense-in-depth)',
        'localStorage is used to store private keys (base64, unencrypted). This is an explicit academic scope limitation — a production system would wrap keys with Argon2id + AES-GCM derived from a user passphrase.',
        'The @noble/post-quantum library correctly implements NIST FIPS 203/204 specifications',
        'The adversary has unlimited classical computational power and a quantum computer with sufficient qubits',
        'Public key ↔ username mapping is TOFU (Trust-On-First-Use). Users should verify Safety Numbers out-of-band to detect a compromised server.',
    ];

    const severityColor = { critical: 'red', high: 'amber', medium: 'cyan', low: 'green' };

    return (
        <div className="threat-overlay">
            <div className="threat-modal animate-fade-in">
                <div className="threat-modal-header">
                    <div>
                        <h2 className="threat-title">
                            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                            Formal Threat Model
                        </h2>
                        <p className="threat-subtitle">
                            Dolev-Yao + Quantum Adversary Analysis</p>
                    </div>
                    <button className="btn btn-ghost btn-icon" onClick={onClose}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                        </svg>
                    </button>
                </div>

                <div className="threat-modal-body">
                    <section className="threat-section">
                        <h3 className="threat-section-title">Adversary Capabilities (Combined Model)</h3>
                        <div className="threat-assumption-grid">
                            <div className="threat-capability">
                                <div className="threat-cap-title">
                                    <span className="badge badge-red">Classical Dolev-Yao</span>
                                </div>
                                <ul className="threat-cap-list">
                                    <li>Intercepts, modifies, and replays all network messages</li>
                                    <li>Has access to all public keys and ciphertexts</li>
                                    <li>Can impersonate any user or server</li>
                                    <li>Has unlimited classical computing resources</li>
                                </ul>
                            </div>
                            <div className="threat-capability">
                                <div className="threat-cap-title">
                                    <span className="badge badge-purple">Quantum Adversary</span>
                                </div>
                                <ul className="threat-cap-list">
                                    <li>Runs Shor's Algorithm to break RSA/ECC/DH</li>
                                    <li>Runs Grover's Algorithm to speed up brute force (√N)</li>
                                    <li>Can perform HNDL (harvest now, decrypt later) attacks</li>
                                    <li>Future access to cryptographically-relevant quantum computer (CRQC)</li>
                                </ul>
                            </div>
                        </div>
                    </section>

                    <section className="threat-section">
                        <h3 className="threat-section-title">Threat Catalog &amp; Mitigations</h3>
                        <div className="threat-table-wrapper">
                            <table className="threat-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Threat Category</th>
                                        <th>Adversary Capability</th>
                                        <th>Classical Defense</th>
                                        <th>PQ Mitigation</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {threats.map(t => (
                                        <tr key={t.id}>
                                            <td><code>{t.id}</code></td>
                                            <td>
                                                <span className={`badge badge-${severityColor[t.severity]}`}>{t.severity.toUpperCase()}</span>
                                                <div className="threat-category-name">{t.category}</div>
                                            </td>
                                            <td className="threat-cell-text">{t.adversaryCapability}</td>
                                            <td className="threat-cell-text threat-classical">{t.classicalMitigation}</td>
                                            <td className="threat-cell-text threat-pq">{t.pqMitigation}</td>
                                            <td>
                                                {t.status === 'mitigated'
                                                    ? <span className="badge badge-green">✓ Mitigated</span>
                                                    : <span className="badge badge-amber">⚠ Partial</span>
                                                }
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </section>

                    <section className="threat-section">
                        <h3 className="threat-section-title">Security Assumptions</h3>
                        <ul className="assumption-list">
                            {assumptions.map((a, i) => (
                                <li key={i} className="assumption-item">
                                    <span className="assumption-num">{i + 1}</span>
                                    <span>{a}</span>
                                </li>
                            ))}
                        </ul>
                    </section>

                    <section className="threat-section">
                        <h3 className="threat-section-title">Security Boundary Analysis</h3>
                        <div className="dataflow-grid">
                            {[
                                { zone: 'Client Browser', trust: 'HIGH', items: ['Private keys (Dilithium + Kyber)', 'Shared secrets (Kyber-derived)', 'Plaintext messages', 'AES-256-GCM encryption/decryption'] },
                                { zone: 'Network / API', trust: 'ZERO', items: ['Kyber KEM ciphertext (opaque)', 'AES-GCM ciphertext (opaque)', 'Dilithium signatures (verifiable)', 'Public keys (non-secret)'] },
                                { zone: 'MongoDB Server', trust: 'UNTRUSTED', items: ['Dilithium public keys', 'Kyber public keys', 'Encrypted messages (ciphertext only)', 'Handshake ciphertexts'] },
                            ].map(zone => (
                                <div key={zone.zone} className={`dataflow-zone zone-${zone.trust.toLowerCase()}`}>
                                    <div className="dataflow-zone-header">
                                        <span className="dataflow-zone-name">{zone.zone}</span>
                                        <span className={`badge badge-${zone.trust === 'HIGH' ? 'green' : zone.trust === 'ZERO' ? 'amber' : 'red'}`}>
                                            {zone.trust} TRUST
                                        </span>
                                    </div>
                                    <ul className="dataflow-items">
                                        {zone.items.map((item, i) => <li key={i}>{item}</li>)}
                                    </ul>
                                </div>
                            ))}
                        </div>
                    </section>
                </div>
            </div>
        </div>
    );
}
