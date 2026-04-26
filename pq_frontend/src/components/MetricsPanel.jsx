import { useState, useEffect } from 'react';
import './MetricsPanel.css';

/**
 * Member 4 (QA & Integration Engineer) — Phase 4 & 5
 * Security Metrics & Performance Dashboard
 *
 * Runs live benchmarks of:
 * - ML-KEM-768 (Kyber) key generation, encapsulation, decapsulation
 * - ML-DSA-65 (Dilithium) key generation, sign, verify
 * - AES-256-GCM encrypt / decrypt
 *
 * Also evaluates Security vs. Usability trade-offs and
 * displays key size comparisons (classical vs. post-quantum).
 */
export default function MetricsPanel({ onClose }) {
    const [benchmarks, setBenchmarks] = useState(null);
    const [running, setRunning] = useState(false);
    const [progress, setProgress] = useState('');

    const runBenchmarks = async () => {
        setRunning(true);
        setBenchmarks(null);
        const results = {};

        try {
            // Dynamically import to avoid blocking render
            const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
            const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

            const toBase64 = (u8) => {
                let bin = '';
                const chunk = 8192;
                for (let i = 0; i < u8.length; i += chunk)
                    bin += String.fromCharCode(...u8.subarray(i, i + chunk));
                return btoa(bin);
            };
            const fromBase64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

            const ROUNDS = 5;

            // ── ML-KEM-768 Benchmarks ──────────────────────────────
            setProgress('Benchmarking ML-KEM-768 (Kyber)...');
            await new Promise(r => setTimeout(r, 50));

            let t0, t1, kemKeys, encap;

            // KEM KeyGen
            const kemKeygenTimes = [];
            for (let i = 0; i < ROUNDS; i++) {
                t0 = performance.now();
                kemKeys = ml_kem768.keygen();
                t1 = performance.now();
                kemKeygenTimes.push(t1 - t0);
            }
            results.kemKeygen = avg(kemKeygenTimes);

            // KEM Encapsulate
            const kemEncapTimes = [];
            for (let i = 0; i < ROUNDS; i++) {
                t0 = performance.now();
                encap = ml_kem768.encapsulate(kemKeys.publicKey);
                t1 = performance.now();
                kemEncapTimes.push(t1 - t0);
            }
            results.kemEncap = avg(kemEncapTimes);

            // KEM Decapsulate
            const kemDecapTimes = [];
            for (let i = 0; i < ROUNDS; i++) {
                t0 = performance.now();
                ml_kem768.decapsulate(encap.cipherText, kemKeys.secretKey);
                t1 = performance.now();
                kemDecapTimes.push(t1 - t0);
            }
            results.kemDecap = avg(kemDecapTimes);

            // Key sizes
            results.kemPubKeyBytes = kemKeys.publicKey.length;
            results.kemPrivKeyBytes = kemKeys.secretKey.length;
            results.kemCiphertextBytes = encap.cipherText.length;
            results.kemSharedSecretBytes = encap.sharedSecret.length;

            // ── ML-DSA-65 Benchmarks ───────────────────────────────
            setProgress('Benchmarking ML-DSA-65 (Dilithium)...');
            await new Promise(r => setTimeout(r, 50));

            let dsaKeys, sig;
            const msg = new TextEncoder().encode('QuantumShield benchmark message for signing test.');

            // DSA KeyGen
            const dsaKeygenTimes = [];
            for (let i = 0; i < ROUNDS; i++) {
                t0 = performance.now();
                dsaKeys = ml_dsa65.keygen();
                t1 = performance.now();
                dsaKeygenTimes.push(t1 - t0);
            }
            results.dsaKeygen = avg(dsaKeygenTimes);

            // DSA Sign
            const dsaSignTimes = [];
            for (let i = 0; i < ROUNDS; i++) {
                t0 = performance.now();
                sig = ml_dsa65.sign(dsaKeys.secretKey, msg);
                t1 = performance.now();
                dsaSignTimes.push(t1 - t0);
            }
            results.dsaSign = avg(dsaSignTimes);

            // DSA Verify
            const dsaVerifyTimes = [];
            for (let i = 0; i < ROUNDS; i++) {
                t0 = performance.now();
                ml_dsa65.verify(dsaKeys.publicKey, msg, sig);
                t1 = performance.now();
                dsaVerifyTimes.push(t1 - t0);
            }
            results.dsaVerify = avg(dsaVerifyTimes);

            results.dsaPubKeyBytes = dsaKeys.publicKey.length;
            results.dsaPrivKeyBytes = dsaKeys.secretKey.length;
            results.dsaSigBytes = sig.length;

            // ── AES-256-GCM Benchmarks ─────────────────────────────
            setProgress('Benchmarking AES-256-GCM...');
            await new Promise(r => setTimeout(r, 50));

            const rawKey = crypto.getRandomValues(new Uint8Array(32));
            const aesKey = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
            const plaintext = new TextEncoder().encode('Hello, post-quantum world! This is a test message for AES benchmarking.');
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const aesEncTimes = [];
            let cipherBuf;
            for (let i = 0; i < ROUNDS; i++) {
                t0 = performance.now();
                cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
                t1 = performance.now();
                aesEncTimes.push(t1 - t0);
            }
            results.aesEncrypt = avg(aesEncTimes);

            const aesDecTimes = [];
            for (let i = 0; i < ROUNDS; i++) {
                t0 = performance.now();
                await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipherBuf);
                t1 = performance.now();
                aesDecTimes.push(t1 - t0);
            }
            results.aesDecrypt = avg(aesDecTimes);

            results.aesKeyBytes = 32;
            results.aesIvBytes = 12;

            // ── Correctness Verification ───────────────────────────
            setProgress('Verifying correctness...');
            await new Promise(r => setTimeout(r, 50));

            const kemKeys2 = ml_kem768.keygen();
            const { cipherText, sharedSecret: ss1 } = ml_kem768.encapsulate(kemKeys2.publicKey);
            const ss2 = ml_kem768.decapsulate(cipherText, kemKeys2.secretKey);
            results.kemCorrect = toBase64(ss1) === toBase64(ss2);

            const dsaKeys2 = ml_dsa65.keygen();
            const testMsg = new TextEncoder().encode('correctness-test');
            const testSig = ml_dsa65.sign(dsaKeys2.secretKey, testMsg);
            results.dsaCorrect = ml_dsa65.verify(dsaKeys2.publicKey, testMsg, testSig);

            setProgress('Done!');
            setBenchmarks(results);
        } catch (err) {
            console.error('Benchmark error:', err);
            setProgress(`Error: ${err.message}`);
        } finally {
            setRunning(false);
        }
    };

    const avg = (arr) => (arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(2);
    const fmt = (ms) => ms < 1 ? `${(parseFloat(ms) * 1000).toFixed(0)} µs` : `${parseFloat(ms).toFixed(1)} ms`;

    const keySizeComparisons = [
        { algo: 'RSA-2048', type: 'Classical (VULNERABLE)', pubKey: '256 B', privKey: '1,232 B', sig: '256 B', quantum: false },
        { algo: 'ECDSA P-256', type: 'Classical (VULNERABLE)', pubKey: '64 B', privKey: '32 B', sig: '64 B', quantum: false },
        { algo: 'ML-KEM-768', type: 'Post-Quantum ✓', pubKey: benchmarks ? `${benchmarks.kemPubKeyBytes} B` : '1,184 B', privKey: benchmarks ? `${benchmarks.kemPrivKeyBytes} B` : '2,400 B', sig: `CT: ${benchmarks ? benchmarks.kemCiphertextBytes : 1088} B`, quantum: true },
        { algo: 'ML-DSA-65', type: 'Post-Quantum ✓', pubKey: benchmarks ? `${benchmarks.dsaPubKeyBytes} B` : '1,952 B', privKey: benchmarks ? `${benchmarks.dsaPrivKeyBytes} B` : '4,032 B', sig: benchmarks ? `${benchmarks.dsaSigBytes} B` : '3,309 B', quantum: true },
    ];

    const tradeoffs = [
        { aspect: 'Key Generation Speed', classical: 'RSA: ~2ms', pq: `KEM: ${benchmarks ? fmt(benchmarks.kemKeygen) : '~8ms'} · DSA: ${benchmarks ? fmt(benchmarks.dsaKeygen) : '~15ms'}`, verdict: 'acceptable' },
        { aspect: 'Key Sizes', classical: 'RSA PK: 256 B', pq: `KEM PK: ${benchmarks ? benchmarks.kemPubKeyBytes : 1184} B (~4.6×)`, verdict: 'tradeoff' },
        { aspect: 'Signature Size', classical: 'ECDSA: 64 B', pq: `Dilithium: ${benchmarks ? benchmarks.dsaSigBytes : 3309} B (~52×)`, verdict: 'tradeoff' },
        { aspect: 'Quantum Resistance', classical: 'None — Shor breaks RSA/ECDH', pq: 'Full — LWE hardness (no quantum algorithm known)', verdict: 'win' },
        { aspect: 'NIST Standardization', classical: 'Yes (FIPS 186-4)', pq: 'Yes — FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA)', verdict: 'win' },
        { aspect: 'Performance Overhead', classical: 'Baseline', pq: 'Total handshake < 50ms on modern hardware', verdict: 'acceptable' },
        { aspect: 'Library Maturity', classical: 'Decades-old, heavily audited', pq: '@noble/post-quantum — audited pure JS implementation', verdict: 'acceptable' },
    ];

    const verdictStyle = { win: 'green', acceptable: 'cyan', tradeoff: 'amber' };
    const verdictLabel = { win: '✓ PQ Wins', acceptable: '≈ Acceptable', tradeoff: '⚖ Trade-off' };

    return (
        <div className="metrics-overlay">
            <div className="metrics-modal animate-fade-in">
                <div className="metrics-modal-header">
                    <div>
                        <h2 className="metrics-title">
                            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <polyline points="22,12 18,12 15,21 9,3 6,12 2,12" />
                            </svg>
                            QA Metrics &amp; Security Evaluation
                        </h2>
                        <p className="metrics-subtitle">Member 4 — Performance Benchmarks &amp; Security/Usability Trade-off Analysis</p>
                    </div>
                    <button className="btn btn-ghost btn-icon" onClick={onClose}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                        </svg>
                    </button>
                </div>

                <div className="metrics-modal-body">
                    {/* Run Benchmarks */}
                    <div className="metrics-bench-header">
                        <div>
                            <h3 className="metrics-section-title">Live Browser Benchmarks</h3>
                            <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                                Runs {5} iterations of each operation using @noble/post-quantum in your browser. Results may vary by device.
                            </p>
                        </div>
                        <button
                            id="run-benchmarks-btn"
                            className="btn btn-primary"
                            onClick={runBenchmarks}
                            disabled={running}
                        >
                            {running ? <><span className="loading-spinner" /> {progress}</> : '▶ Run Benchmarks'}
                        </button>
                    </div>

                    {benchmarks && (
                        <div className="metrics-bench-grid">
                            {/* ML-KEM-768 Card */}
                            <div className="metrics-card">
                                <div className="metrics-card-header">
                                    <span className="badge badge-purple">ML-KEM-768 (Kyber)</span>
                                    {benchmarks.kemCorrect
                                        ? <span className="badge badge-green">✓ Correct</span>
                                        : <span className="badge badge-red">✗ Failed</span>
                                    }
                                </div>
                                <div className="metrics-rows">
                                    <div className="metrics-row">
                                        <span>Key Generation</span>
                                        <span className="metrics-val">{fmt(benchmarks.kemKeygen)}</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Encapsulate</span>
                                        <span className="metrics-val">{fmt(benchmarks.kemEncap)}</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Decapsulate</span>
                                        <span className="metrics-val">{fmt(benchmarks.kemDecap)}</span>
                                    </div>
                                    <div className="metrics-divider" />
                                    <div className="metrics-row">
                                        <span>Public Key Size</span>
                                        <span className="metrics-val metrics-size">{benchmarks.kemPubKeyBytes} B</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Private Key Size</span>
                                        <span className="metrics-val metrics-size">{benchmarks.kemPrivKeyBytes} B</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Ciphertext Size</span>
                                        <span className="metrics-val metrics-size">{benchmarks.kemCiphertextBytes} B</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Shared Secret</span>
                                        <span className="metrics-val metrics-size">{benchmarks.kemSharedSecretBytes} B (256-bit)</span>
                                    </div>
                                </div>
                            </div>

                            {/* ML-DSA-65 Card */}
                            <div className="metrics-card">
                                <div className="metrics-card-header">
                                    <span className="badge badge-cyan">ML-DSA-65 (Dilithium)</span>
                                    {benchmarks.dsaCorrect
                                        ? <span className="badge badge-green">✓ Correct</span>
                                        : <span className="badge badge-red">✗ Failed</span>
                                    }
                                </div>
                                <div className="metrics-rows">
                                    <div className="metrics-row">
                                        <span>Key Generation</span>
                                        <span className="metrics-val">{fmt(benchmarks.dsaKeygen)}</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Sign</span>
                                        <span className="metrics-val">{fmt(benchmarks.dsaSign)}</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Verify</span>
                                        <span className="metrics-val">{fmt(benchmarks.dsaVerify)}</span>
                                    </div>
                                    <div className="metrics-divider" />
                                    <div className="metrics-row">
                                        <span>Public Key Size</span>
                                        <span className="metrics-val metrics-size">{benchmarks.dsaPubKeyBytes} B</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Private Key Size</span>
                                        <span className="metrics-val metrics-size">{benchmarks.dsaPrivKeyBytes} B</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Signature Size</span>
                                        <span className="metrics-val metrics-size">{benchmarks.dsaSigBytes} B</span>
                                    </div>
                                </div>
                            </div>

                            {/* AES-256-GCM Card */}
                            <div className="metrics-card">
                                <div className="metrics-card-header">
                                    <span className="badge badge-green">AES-256-GCM</span>
                                    <span className="badge badge-green">✓ WebCrypto</span>
                                </div>
                                <div className="metrics-rows">
                                    <div className="metrics-row">
                                        <span>Encrypt (70B message)</span>
                                        <span className="metrics-val">{fmt(benchmarks.aesEncrypt)}</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Decrypt</span>
                                        <span className="metrics-val">{fmt(benchmarks.aesDecrypt)}</span>
                                    </div>
                                    <div className="metrics-divider" />
                                    <div className="metrics-row">
                                        <span>Key Size</span>
                                        <span className="metrics-val metrics-size">{benchmarks.aesKeyBytes * 8}-bit</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>IV Size</span>
                                        <span className="metrics-val metrics-size">{benchmarks.aesIvBytes * 8}-bit (GCM)</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Effective PQ Security</span>
                                        <span className="metrics-val" style={{ color: 'var(--green)' }}>128-bit (Grover)</span>
                                    </div>
                                    <div className="metrics-row">
                                        <span>Implementation</span>
                                        <span className="metrics-val" style={{ color: 'var(--cyan)' }}>WebCrypto API</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Key Size Comparison */}
                    <section>
                        <h3 className="metrics-section-title">Key Size Comparison: Classical vs. Post-Quantum</h3>
                        <div className="metrics-table-wrapper">
                            <table className="metrics-table">
                                <thead>
                                    <tr>
                                        <th>Algorithm</th>
                                        <th>Type</th>
                                        <th>Public Key</th>
                                        <th>Private Key</th>
                                        <th>Sig / CT</th>
                                        <th>Quantum-Safe?</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {keySizeComparisons.map(row => (
                                        <tr key={row.algo} className={row.quantum ? 'metrics-row-pq' : 'metrics-row-classical'}>
                                            <td><code>{row.algo}</code></td>
                                            <td>
                                                <span className={`badge badge-${row.quantum ? 'green' : 'red'}`}>
                                                    {row.type}
                                                </span>
                                            </td>
                                            <td>{row.pubKey}</td>
                                            <td>{row.privKey}</td>
                                            <td>{row.sig}</td>
                                            <td>{row.quantum ? '✅ Yes' : '❌ No'}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </section>

                    {/* Security vs. Usability Trade-offs */}
                    <section>
                        <h3 className="metrics-section-title">Security vs. Usability Trade-off Analysis</h3>
                        <div className="tradeoff-table-wrapper">
                            <table className="metrics-table">
                                <thead>
                                    <tr>
                                        <th>Aspect</th>
                                        <th>Classical Baseline</th>
                                        <th>Post-Quantum (This System)</th>
                                        <th>Assessment</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {tradeoffs.map(row => (
                                        <tr key={row.aspect}>
                                            <td style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 13 }}>{row.aspect}</td>
                                            <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{row.classical}</td>
                                            <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{row.pq}</td>
                                            <td>
                                                <span className={`badge badge-${verdictStyle[row.verdict]}`}>
                                                    {verdictLabel[row.verdict]}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </section>

                    {/* NIST Standards Reference */}
                    <section className="metrics-standards">
                        <h3 className="metrics-section-title">NIST Post-Quantum Standards Reference</h3>
                        <div className="standards-grid">
                            {[
                                { std: 'FIPS 203', title: 'Module-Lattice-Based Key-Encapsulation Mechanism', algo: 'ML-KEM (Kyber)', status: 'Final — Aug 2024', color: 'purple' },
                                { std: 'FIPS 204', title: 'Module-Lattice-Based Digital Signature Standard', algo: 'ML-DSA (Dilithium)', status: 'Final — Aug 2024', color: 'cyan' },
                                { std: 'FIPS 197', title: 'Advanced Encryption Standard', algo: 'AES-256-GCM', status: 'Active (2001)', color: 'green' },
                            ].map(s => (
                                <div key={s.std} className="standard-card">
                                    <div className="standard-card-header">
                                        <span className={`badge badge-${s.color}`}>{s.std}</span>
                                        <span className="standard-status">{s.status}</span>
                                    </div>
                                    <div className="standard-algo">{s.algo}</div>
                                    <div className="standard-title">{s.title}</div>
                                </div>
                            ))}
                        </div>
                    </section>
                </div>
            </div>
        </div>
    );
}
