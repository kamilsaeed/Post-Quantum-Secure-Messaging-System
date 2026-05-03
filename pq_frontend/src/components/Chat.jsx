import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
    encapsulateSecret,
    decapsulateSecret,
    signData,
    verifySignature,
    encryptMessage,
    decryptMessage,
} from '../utils/crypto';
import {
    getPublicKey,
    getUsers,
    initiateHandshake,
    getPendingHandshakes,
    completeHandshake,
    sendMessage,
    getConversation,
    getUnreadCounts,
    markMessagesRead,
} from '../services/api';
import './Chat.css';

export default function Chat({ currentUser, onLogout }) {
    const [users, setUsers] = useState([]);
    const [selectedContact, setSelectedContact] = useState(null);
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState('');
    const [handshakeStatus, setHandshakeStatus] = useState({});
    const [sharedSecrets, setSharedSecrets] = useState(() => {
        const secrets = {};
        for (const key of Object.keys(localStorage)) {
            if (key.startsWith('pq_secret_')) {
                const contact = key.replace('pq_secret_', '');
                secrets[contact] = localStorage.getItem(key);
            }
        }
        return secrets;
    });
    const [decryptedMessages, setDecryptedMessages] = useState({});
    const [verificationStatus, setVerificationStatus] = useState({});
    const [unreadCounts, setUnreadCounts] = useState({});
    const [cryptoLog, setCryptoLog] = useState([]);
    const [showCryptoPanel, setShowCryptoPanel] = useState(false);
    const [sendingMessage, setSendingMessage] = useState(false);
    const [handshaking, setHandshaking] = useState(false);
    const [loadingMessages, setLoadingMessages] = useState(false);
    const [safetyNumber, setSafetyNumber] = useState(null);
    const [showSafetyNumber, setShowSafetyNumber] = useState(false);
    const messagesEndRef = useRef(null);

    const myDSAPrivKey = localStorage.getItem('pq_dsa_private_key');
    const myKEMPrivKey = localStorage.getItem('pq_kem_private_key');
    const myDSAPubKey  = localStorage.getItem('pq_dsa_public_key');

    const addLog = useCallback((type, message) => {
        const entry = { id: Date.now() + Math.random(), type, message, time: new Date().toLocaleTimeString() };
        setCryptoLog(prev => [entry, ...prev].slice(0, 50));
    }, []);

    const loadUsers = useCallback(async () => {
        try {
            const data = await getUsers();
            setUsers(data.users.filter(u => u.username !== currentUser));
        } catch (err) {
            console.error('Failed to load users:', err);
        }
    }, [currentUser]);

    const loadUnreadCounts = useCallback(async () => {
        try {
            const data = await getUnreadCounts(currentUser);
            setUnreadCounts(data.unread || {});
        } catch (err) {
            console.error('Failed to load unread counts:', err);
        }
    }, [currentUser]);

    const loadPendingHandshakes = useCallback(async () => {
        try {
            const data = await getPendingHandshakes(currentUser);
            for (const hs of data.handshakes) {
                const contact = hs.initiator;
                const transcriptPayload = `PQMSG-v1|handshake|${contact}|${currentUser}|${hs.kyberCiphertext}`;
                const sigValid = verifySignature(transcriptPayload, hs.signature, hs.initiatorDilithiumPublicKey);

                if (!sigValid) {
                    addLog('error', `Handshake from ${contact}: INVALID Dilithium signature! Rejected.`);
                    continue;
                }
                addLog('verify', `Handshake from ${contact}: Dilithium signature verified.`);

                const sharedSecret = decapsulateSecret(hs.kyberCiphertext, myKEMPrivKey);
                localStorage.setItem(`pq_secret_${contact}`, sharedSecret);
                setSharedSecrets(prev => ({ ...prev, [contact]: sharedSecret }));
                setHandshakeStatus(prev => ({ ...prev, [contact]: 'completed' }));
                addLog('kem', `Kyber KEM: Shared secret established with ${contact}.`);
                await completeHandshake(hs._id);
            }
        } catch (err) {
            console.error('Handshake poll error:', err);
        }
    }, [addLog, currentUser, myKEMPrivKey]);

    const selectContact = async (contact) => {
        setSelectedContact(contact);
        setMessages([]);
        setDecryptedMessages({});
        setSafetyNumber(null);
        setShowSafetyNumber(false);

        const secret = localStorage.getItem(`pq_secret_${contact}`);
        if (secret) setHandshakeStatus(prev => ({ ...prev, [contact]: 'completed' }));
        setUnreadCounts(prev => ({ ...prev, [contact]: 0 }));

        await loadMessages(contact, { markRead: true, showLoader: true });
    };

    const loadMessages = useCallback(async (contact, options = {}) => {
        if (!contact) return;
        const { markRead = false, showLoader = false } =
            typeof options === 'boolean' ? { markRead: options, showLoader: true } : options;

        if (showLoader) setLoadingMessages(true);
        try {
            const data = await getConversation(currentUser, contact);
            setMessages(data.messages || []);

            if (markRead) {
                markMessagesRead(currentUser, contact).catch(() => {});
                setUnreadCounts(prev => ({ ...prev, [contact]: 0 }));
            }

            const secret = localStorage.getItem(`pq_secret_${contact}`);
            if (secret && data.messages.length > 0) {
                const newDecrypted = {};
                const newVerification = {};

                for (const msg of data.messages) {
                    const senderPubKey = data.publicKeys[msg.sender];
                    const transcriptPayload = `PQMSG-v1|${msg.sender}|${msg.recipient}|${msg.iv}|${msg.encryptedContent}`;
                    const isValid = senderPubKey
                        ? verifySignature(transcriptPayload, msg.signature, senderPubKey)
                        : false;
                    newVerification[msg._id] = isValid;

                    const hkdfSender = msg.sender;
                    const hkdfRecipient = msg.recipient;
                    try {
                        const plaintext = await decryptMessage(msg.encryptedContent, msg.iv, secret, hkdfSender, hkdfRecipient);
                        newDecrypted[msg._id] = plaintext;
                    } catch {
                        newDecrypted[msg._id] = '[Decryption failed — wrong shared secret]';
                    }
                }

                setDecryptedMessages(newDecrypted);
                setVerificationStatus(newVerification);
            }
        } catch (err) {
            console.error('Load messages error:', err);
        } finally {
            if (showLoader) setLoadingMessages(false);
        }
    }, [currentUser]);

    useEffect(() => {
        let isActive = true;

        const refreshChatState = () => {
            if (!isActive) return;
            loadPendingHandshakes();
            loadUnreadCounts();
            if (selectedContact) loadMessages(selectedContact, { markRead: true, showLoader: false });
        };

        const initialTimer = setTimeout(() => {
            if (!isActive) return;
            loadUsers();
            refreshChatState();
        }, 0);

        const interval = setInterval(() => {
            refreshChatState();
        }, 5000);

        return () => {
            isActive = false;
            clearTimeout(initialTimer);
            clearInterval(interval);
        };
    }, [loadMessages, loadPendingHandshakes, loadUnreadCounts, loadUsers, selectedContact]);

    const initiateKyberHandshake = async (contact) => {
        setHandshaking(true);
        addLog('kem', `Initiating Kyber KEM handshake with ${contact}...`);

        try {
            const recipientKeys = await getPublicKey(contact);
            addLog('kem', `Fetched ${contact}'s Kyber public key from key server.`);

            const { ciphertext, sharedSecret } = encapsulateSecret(recipientKeys.kyberPublicKey);
            addLog('kem', `ML-KEM-768: Encapsulated shared secret.`);

            const transcriptPayload = `PQMSG-v1|handshake|${currentUser}|${contact}|${ciphertext}`;
            const signature = signData(transcriptPayload, myDSAPrivKey);
            addLog('sign', `ML-DSA-65: Signed transcript-bound handshake payload.`);

            localStorage.setItem(`pq_secret_${contact}`, sharedSecret);
            setSharedSecrets(prev => ({ ...prev, [contact]: sharedSecret }));

            await initiateHandshake(currentUser, contact, ciphertext, signature);
            setHandshakeStatus(prev => ({ ...prev, [contact]: 'pending' }));
            addLog('kem', `Ciphertext stored on server. Waiting for ${contact} to decapsulate...`);
        } catch (err) {
            console.error('Handshake error:', err);
            addLog('error', `Handshake failed: ${err.message}`);
        } finally {
            setHandshaking(false);
        }
    };

    const handleSendMessage = async (e) => {
        e.preventDefault();
        if (!newMessage.trim() || !selectedContact) return;

        const secret = sharedSecrets[selectedContact];
        if (!secret) {
            addLog('error', 'No shared secret. Initiate a handshake first.');
            return;
        }

        setSendingMessage(true);
        const plaintext = newMessage.trim();
        setNewMessage('');

        try {
            const { encryptedContent, iv } = await encryptMessage(plaintext, secret, currentUser, selectedContact);
            addLog('encrypt', `AES-256-GCM: Message encrypted.`);

            const transcriptPayload = `PQMSG-v1|${currentUser}|${selectedContact}|${iv}|${encryptedContent}`;
            const signature = signData(transcriptPayload, myDSAPrivKey);
            addLog('sign', `ML-DSA-65: Signed transcript-bound message payload.`);

            await sendMessage(currentUser, selectedContact, encryptedContent, iv, signature);
            addLog('info', `Encrypted message sent. Server cannot read it.`);

            await loadMessages(selectedContact, { showLoader: false });
        } catch (err) {
            console.error('Send message error:', err);
            addLog('error', `Send failed: ${err.message}`);
            setNewMessage(plaintext);
        } finally {
            setSendingMessage(false);
        }
    };

    const computeSafetyNumber = async (contact) => {
        try {
            const contactKeys = await getPublicKey(contact);
            const myPub = myDSAPubKey || '';
            const theirPub = contactKeys.dilithiumPublicKey || '';

            const [first, second] = [currentUser, contact].sort();
            const firstPub  = first  === currentUser ? myPub   : theirPub;
            const secondPub = second === currentUser ? myPub   : theirPub;

            const combined = new TextEncoder().encode(firstPub + secondPub);
            const hashBuf  = await crypto.subtle.digest('SHA-256', combined);
            const hashHex  = Array.from(new Uint8Array(hashBuf))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');

            const groups = hashHex.match(/.{8}/g) || [];
            setSafetyNumber(groups.join(' '));
            setShowSafetyNumber(true);
        } catch (err) {
            console.error('Safety number error:', err);
        }
    };

    const getHandshakeStatusForContact = (contact) => {
        if (sharedSecrets[contact]) return 'completed';
        return handshakeStatus[contact] || 'none';
    };

    const formatTime = (dateStr) =>
        new Date(dateStr).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const sortedUsers = useMemo(() => {
        return users
            .map((user, index) => ({ ...user, index }))
            .sort((a, b) => {
                const unreadDiff = (unreadCounts[b.username] || 0) - (unreadCounts[a.username] || 0);
                if (unreadDiff !== 0) return unreadDiff;
                return a.index - b.index;
            });
    }, [users, unreadCounts]);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }, [messages.length, selectedContact]);

    const logTypeColor = {
        kem: 'var(--accent-primary)', sign: 'var(--cyan)',
        encrypt: 'var(--green)', verify: 'var(--green)',
        info: 'var(--text-muted)', error: 'var(--red)',
    };

    return (
        <div className="chat-layout">
            <aside className="chat-sidebar">
                <div className="sidebar-header">
                    <div className="sidebar-logo">
                        <svg width="28" height="28" viewBox="0 0 40 40" fill="none">
                            <rect width="40" height="40" rx="10" fill="url(#grad2)" />
                            <path d="M20 8L28 13V22L20 27L12 22V13L20 8Z" stroke="white" strokeWidth="2" fill="none" />
                            <circle cx="20" cy="19" r="3" fill="white" />
                            <defs>
                                <linearGradient id="grad2" x1="0" y1="0" x2="40" y2="40">
                                    <stop offset="0%" stopColor="#7c3aed" />
                                    <stop offset="100%" stopColor="#06b6d4" />
                                </linearGradient>
                            </defs>
                        </svg>
                        <span className="sidebar-app-name gradient-text">QuantumShield</span>
                    </div>

                    <div className="sidebar-user-info">
                        <div className="sidebar-avatar">{currentUser[0].toUpperCase()}</div>
                        <div className="sidebar-user-details">
                            <div className="sidebar-username">{currentUser}</div>
                            <div className="sidebar-status">
                                <span className="pulse-dot" />
                                <span>PQ-Secure Identity Active</span>
                            </div>
                        </div>
                    </div>

                    <div className="sidebar-alg-badges">
                        <span className="badge badge-purple" title="Key Encapsulation">KEM-768</span>
                        <span className="badge badge-cyan" title="Digital Signatures">DSA-65</span>
                    </div>
                </div>

                <div className="sidebar-section-title">Registered Users</div>

                <div className="contact-list">
                    {users.length === 0 ? (
                        <div className="contact-empty">
                            No other users registered yet.
                            <br /><small>Open another browser tab to register.</small>
                        </div>
                    ) : (
                        sortedUsers.map(user => {
                            const hsStatus = getHandshakeStatusForContact(user.username);
                            const unread = unreadCounts[user.username] || 0;
                            return (
                                <div
                                    key={user.username}
                                    id={`contact-${user.username}`}
                                    className={`contact-item ${selectedContact === user.username ? 'contact-item-active' : ''} ${unread > 0 ? 'contact-item-unread' : ''}`}
                                    onClick={() => selectContact(user.username)}
                                >
                                    <div className="contact-avatar">
                                        {user.username[0].toUpperCase()}
                                        {hsStatus === 'completed' && (
                                            <span className="contact-secure-dot" title="E2E Encrypted" />
                                        )}
                                    </div>
                                    <div className="contact-info">
                                        <div className="contact-name">{user.username}</div>
                                        <div className="contact-hs-status">
                                            {hsStatus === 'none' && <span className="hs-badge hs-none">No Key Exchange</span>}
                                            {hsStatus === 'pending' && <span className="hs-badge hs-pending">Handshake Pending...</span>}
                                            {hsStatus === 'completed' && <span className="hs-badge hs-done">🔒 E2E Encrypted</span>}
                                        </div>
                                    </div>
                                    {unread > 0 && <div className="unread-badge">{unread}</div>}
                                </div>
                            );
                        })
                    )}
                </div>

                <div className="sidebar-footer">
                    <button id="toggle-crypto-panel-btn" className="btn btn-ghost btn-sm"
                        style={{ width: '100%', justifyContent: 'flex-start' }}
                        onClick={() => setShowCryptoPanel(p => !p)}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
                        </svg>
                        Crypto Activity Log
                    </button>
                    <button id="logout-btn" className="btn btn-danger btn-sm"
                        style={{ width: '100%', justifyContent: 'flex-start' }}
                        onClick={onLogout}>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16,17 21,12 16,7"/><line x1="21" y1="12" x2="9" y2="12"/>
                        </svg>
                        Logout &amp; Clear Keys
                    </button>
                </div>
            </aside>

            <main className="chat-main">
                {!selectedContact ? (
                    <div className="chat-empty-state">
                        <div className="chat-empty-icon">
                            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                        </div>
                        <h2>Post-Quantum Secure Chat</h2>
                        <p>Select a contact to start a quantum-resistant conversation.</p>
                        <p>Each conversation uses Kyber KEM for key exchange and AES-256-GCM for encryption.</p>
                        <div className="chat-empty-badges">
                            <span className="badge badge-purple">ML-KEM-768 (Kyber)</span>
                            <span className="badge badge-cyan">ML-DSA-65 (Dilithium)</span>
                            <span className="badge badge-green">AES-256-GCM</span>
                        </div>
                    </div>
                ) : (
                    <>
                        <div className="chat-header">
                            <div className="chat-header-contact">
                                <div className="chat-header-avatar">{selectedContact[0].toUpperCase()}</div>
                                <div>
                                    <div className="chat-header-name">{selectedContact}</div>
                                    <div className="chat-header-status">
                                        {getHandshakeStatusForContact(selectedContact) === 'completed'
                                            ? <><span className="pulse-dot" style={{ background: 'var(--green)' }} /> End-to-end encrypted</>
                                            : <><span className="pulse-dot" style={{ background: 'var(--amber)' }} /> No shared key — initiate handshake</>
                                        }
                                    </div>
                                </div>
                            </div>
                            <div className="chat-header-actions">
                                {getHandshakeStatusForContact(selectedContact) === 'none' && (
                                    <button id={`handshake-btn-${selectedContact}`} className="btn btn-primary btn-sm"
                                        onClick={() => initiateKyberHandshake(selectedContact)} disabled={handshaking}>
                                        {handshaking ? <><span className="loading-spinner" /> Handshaking...</> : <>🤝 Kyber Handshake</>}
                                    </button>
                                )}
                                {getHandshakeStatusForContact(selectedContact) === 'pending' && (
                                    <span className="badge badge-amber">⏳ Waiting for {selectedContact}...</span>
                                )}
                                {getHandshakeStatusForContact(selectedContact) === 'completed' && (
                                    <>
                                        <span className="badge badge-green">🔒 PQ-Secure Channel</span>
                                        <button id={`safety-number-btn-${selectedContact}`}
                                            className="btn btn-ghost btn-sm"
                                            onClick={() => computeSafetyNumber(selectedContact)}
                                            title="Verify identity out-of-band (Safety Number)">
                                            🔑 Safety Number
                                        </button>
                                    </>
                                )}
                            </div>
                        </div>

                        {showSafetyNumber && safetyNumber && (
                            <div className="safety-number-panel animate-fade-in">
                                <div className="safety-number-header">
                                    <strong>Safety Number with {selectedContact}</strong>
                                    <button className="btn btn-ghost btn-icon btn-sm" onClick={() => setShowSafetyNumber(false)}>✕</button>
                                </div>
                                <code className="safety-number-code">{safetyNumber}</code>
                                <p className="safety-number-hint">
                                    Compare this number with {selectedContact} via a separate channel (call, in-person).
                                    If it matches, your connection has not been intercepted. (TOFU identity verification)
                                </p>
                            </div>
                        )}

                        <div className="messages-container" id="messages-container">
                            {loadingMessages && (
                                <div className="messages-loading">
                                    <span className="loading-spinner" /> Loading encrypted messages...
                                </div>
                            )}
                            {!loadingMessages && messages.length === 0 && (
                                <div className="messages-empty">
                                    {getHandshakeStatusForContact(selectedContact) === 'completed'
                                        ? 'Channel is secure. Send your first encrypted message!'
                                        : 'Initiate a Kyber KEM handshake to establish a shared secret before messaging.'
                                    }
                                </div>
                            )}
                            {messages.map((msg) => {
                                const isMine = msg.sender === currentUser;
                                const plaintext = decryptedMessages[msg._id];
                                const sigValid = verificationStatus[msg._id];
                                return (
                                    <div key={msg._id} className={`message-row ${isMine ? 'message-row-mine' : 'message-row-theirs'}`}>
                                        <div className={`message-bubble ${isMine ? 'message-bubble-mine' : 'message-bubble-theirs'}`}>
                                            <div className="message-text">
                                                {plaintext !== undefined
                                                    ? plaintext
                                                    : <span className="message-encrypted">🔒 [Encrypted — no shared secret]</span>
                                                }
                                            </div>
                                            <div className="message-meta">
                                                <span className="message-time">{formatTime(msg.createdAt)}</span>
                                                {sigValid !== undefined && (
                                                    <span className={`message-sig ${sigValid ? 'sig-valid' : 'sig-invalid'}`}
                                                        title={sigValid ? 'Dilithium signature verified (transcript-bound)' : 'Signature verification FAILED'}>
                                                        {sigValid ? '✓ Signed' : '✗ Tampered'}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                            <div ref={messagesEndRef} />
                        </div>

                        <form className="message-input-area" onSubmit={handleSendMessage}>
                            <div className="message-input-wrapper">
                                <input id="message-input" type="text" className="input-field message-input"
                                    placeholder={getHandshakeStatusForContact(selectedContact) === 'completed'
                                        ? 'Type a message... (will be AES-256-GCM encrypted)'
                                        : 'Initiate Kyber handshake to unlock messaging'}
                                    value={newMessage}
                                    onChange={(e) => setNewMessage(e.target.value)}
                                    disabled={getHandshakeStatusForContact(selectedContact) !== 'completed' || sendingMessage}
                                />
                                <button id="send-message-btn" type="submit" className="btn btn-primary btn-icon send-btn"
                                    disabled={!newMessage.trim() || getHandshakeStatusForContact(selectedContact) !== 'completed' || sendingMessage}>
                                    {sendingMessage
                                        ? <span className="loading-spinner" />
                                        : <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                            <line x1="22" y1="2" x2="11" y2="13" /><polygon points="22,2 15,22 11,13 2,9" />
                                          </svg>
                                    }
                                </button>
                            </div>
                            <div className="message-input-hint">
                                {getHandshakeStatusForContact(selectedContact) === 'completed' && (
                                    <span>🔒 AES-256-GCM · ML-DSA-65 (transcript-bound) · ML-KEM-768</span>
                                )}
                            </div>
                        </form>
                    </>
                )}
            </main>

            {showCryptoPanel && (
                <aside className="crypto-panel animate-slide-in-right">
                    <div className="crypto-panel-header">
                        <h3>Crypto Activity Log</h3>
                        <span className="badge badge-cyan">Live</span>
                        <button className="btn btn-ghost btn-icon" onClick={() => setShowCryptoPanel(false)}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                            </svg>
                        </button>
                    </div>
                    <div className="crypto-panel-subtitle">Real-time cryptographic operation trace</div>
                    <div className="crypto-log">
                        {cryptoLog.length === 0
                            ? <div className="crypto-log-empty">Crypto operations will appear here as you interact.</div>
                            : cryptoLog.map(entry => (
                                <div key={entry.id} className="crypto-log-entry animate-fade-in">
                                    <span className="crypto-log-time">{entry.time}</span>
                                    <span className="crypto-log-msg" style={{ color: logTypeColor[entry.type] || 'var(--text-secondary)' }}>
                                        {entry.message}
                                    </span>
                                </div>
                            ))
                        }
                    </div>
                </aside>
            )}
        </div>
    );
}
