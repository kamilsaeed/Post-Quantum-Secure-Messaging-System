# Technical Documentation

## 1. Project Overview

**Project name:** Post-Quantum Secure Messaging System (QuantumShield)  
**Architecture:** MERN-style split (React frontend + Node/Express backend + MongoDB)  
**Goal:** Provide end-to-end encrypted messaging that is resilient against both classical and quantum-enabled adversaries.

### Core Cryptographic Stack

- **ML-KEM-768 (Kyber)** for post-quantum key encapsulation.
- **ML-DSA-65 (Dilithium)** for post-quantum digital signatures.
- **AES-256-GCM** for symmetric message confidentiality and integrity.
- **HKDF-SHA-256** for conversation-bound symmetric key derivation from KEM shared secret.

### Security Model (High-level)

- Private keys are generated in-browser and never uploaded to the server.
- Server stores only public keys, encrypted messages, signatures, and metadata.
- All sensitive message operations (encrypt/decrypt/sign/verify/decapsulate) are client-side.
- API endpoints that mutate/fetch private user state are protected via bearer session tokens.

## 2. Repository Structure

```text
Project/
  pq_backend/           # Express API + MongoDB models + middleware
  pq_frontend/          # React/Vite client
  install.bat           # Installs backend and frontend dependencies
  start.bat             # Starts backend and frontend in separate windows
  README.md
  TECHNICAL_DOCUMENTATION.md
```

## 3. Technology Stack

### Backend (`pq_backend`)

- Node.js (CommonJS)
- Express 5
- Mongoose
- dotenv
- helmet
- express-rate-limit
- cors
- `@noble/post-quantum` (supporting test/crypto utilities)

### Frontend (`pq_frontend`)

- React + Vite
- Axios
- WebCrypto API (`crypto.subtle`)
- `@noble/post-quantum`

## 4. Setup and Execution

## 4.1 Prerequisites

- Node.js (v18+ recommended)
- npm
- MongoDB instance (local or hosted)

## 4.2 Environment Variables

Create `pq_backend/.env`:

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/pq_messaging
```

`MONGODB_URI` is required by backend database configuration.

## 4.3 Install Dependencies

### Option A: Batch installer

```bash
install.bat
```

### Option B: Manual

```bash
cd pq_backend
npm install
cd ../pq_frontend
npm install
```

## 4.4 Run Application

### Option A: Batch starter

```bash
start.bat
```

### Option B: Manual

```bash
cd pq_backend
npm start
```

```bash
cd pq_frontend
npm run dev
```

### Default URLs

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:5000`
- Backend health: `http://localhost:5000/`

## 5. System Architecture

## 5.1 Components

1. **Register UI**  
   Generates Dilithium and Kyber keypairs in browser, stores private keys locally, registers public keys server-side.

2. **Chat UI**  
   Handles handshake initiation/completion, encrypted messaging, signature verification, unread tracking, and safety number verification.

3. **Backend API**  
   Stores identities, handshake payloads, and encrypted messages; enforces authorization and request limits.

4. **MongoDB**  
   Persists users, handshakes, messages with indexes for uniqueness and retrieval performance.

## 5.2 Trust Boundaries

- **Trusted client boundary (assumed in scope):** browser runtime and localStorage.
- **Untrusted transport/storage boundary:** network path and backend DB treated as potentially observed.
- **Identity caveat:** public-key mapping is TOFU (Trust On First Use) unless users manually verify safety numbers out-of-band.

## 6. Cryptographic Workflow

## 6.1 Registration

1. Client generates:
   - Dilithium keypair (`generateIdentity`)
   - Kyber keypair (`generateKEMKeys`)
2. Client stores private/public material in localStorage under `pq_*` keys.
3. Client sends only public keys to `POST /api/keys/register`.
4. Backend creates user and returns one-time `sessionToken`.
5. Frontend stores `pq_session_token`; Axios interceptor attaches `Authorization: Bearer <token>` to future requests.

## 6.2 Handshake (Key Establishment)

1. Initiator fetches recipient Kyber public key.
2. Initiator encapsulates shared secret using ML-KEM-768.
3. Initiator signs transcript-bound handshake payload:
   - `PQMSG-v1|handshake|<initiator>|<recipient>|<ciphertext>`
4. Backend stores handshake ciphertext/signature as pending.
5. Recipient polls pending handshakes, verifies signature with initiator public key.
6. Recipient decapsulates ciphertext to derive identical shared secret.
7. Recipient marks handshake complete.

## 6.3 Message Exchange

1. Sender derives AES-256 key from shared secret via HKDF:
   - info string: `PQMSG-v1/aes-key/<sender>/<recipient>`
2. Sender encrypts plaintext using AES-GCM with fresh 96-bit IV.
3. Sender signs transcript-bound message payload:
   - `PQMSG-v1|<sender>|<recipient>|<iv>|<ciphertext>`
4. Backend stores ciphertext, IV, signature, metadata.
5. Recipient fetches conversation, verifies signatures, decrypts using local shared secret.

## 6.4 Safety Number Verification

- Chat computes SHA-256 fingerprint over both users' Dilithium public keys in deterministic order.
- Displayed as grouped hex code for human comparison.
- Users should verify safety numbers via out-of-band channel (call/in-person).

## 7. Backend Design

## 7.1 Security Middleware

- `helmet()` for hardened HTTP headers.
- Global API rate limiter on `/api`.
- Stricter rate limiter for `/api/keys/register`.
- CORS restricted to local frontend origins.
- JSON payload limit set to `10mb` (base64 key/ciphertext payloads).

## 7.2 Authentication

Protected routes use `requireAuth` middleware:

- Expects `Authorization: Bearer <sessionToken>`.
- Resolves token to `User.sessionToken`.
- Adds `req.authenticatedUser`.
- Route handlers enforce participant ownership checks.

## 7.3 Data Models

### `User`

- `username` (unique, lowercase)
- `dilithiumPublicKey`
- `kyberPublicKey`
- `sessionToken` (unique)
- timestamps

### `Handshake`

- `initiator`
- `recipient`
- `kyberCiphertext`
- `signature`
- `status` (`pending` | `completed`)
- unique compound index: `{ initiator, recipient }`
- timestamps

### `Message`

- `sender`
- `recipient`
- `encryptedContent`
- `iv` (unique; replay-defense aid)
- `signature`
- `read` (boolean)
- index: `{ sender, recipient, createdAt }`
- timestamps

## 7.4 API Endpoints

### Health

- `GET /`
  - Returns service status + algorithm summary.

### Keys / Identity

- `POST /api/keys/register`
  - Public: yes (rate-limited)
  - Body: `username`, `dilithiumPublicKey`, `kyberPublicKey`
  - Output: `username`, `sessionToken`
- `GET /api/keys/publicKey/:username`
  - Public: yes
  - Output: public keys and registration timestamp
- `GET /api/keys/users`
  - Public: yes
  - Output: list of usernames

### Handshake

- `POST /api/handshake/initiate`
  - Auth: required
  - Initiator in body must equal authenticated user
- `GET /api/handshake/pending/:username`
  - Auth: required
  - Username param must equal authenticated user
- `PATCH /api/handshake/complete/:handshakeId`
  - Auth: required
  - Only recipient can complete
- `GET /api/handshake/status/:userA/:userB`
  - Auth: required
  - Caller must be one of participants

### Messages

- `POST /api/messages/send`
  - Auth: required
  - Sender in body must equal authenticated user
  - Duplicate `iv` returns conflict (replay rejection path)
- `GET /api/messages/conversation/:userA/:userB`
  - Auth: required
  - Caller must be one of participants
  - Returns up to latest 100 messages + sender verification keys
- `PATCH /api/messages/read/:userA/:userB`
  - Auth: required
  - Caller must be `userA`
- `GET /api/messages/unread/:username`
  - Auth: required
  - Caller must match queried username

## 8. Frontend Design

## 8.1 Major Components

- `App.jsx`
  - Session bootstrapping and global modal orchestration.
- `Register.jsx`
  - Key generation + registration flow.
- `Chat.jsx`
  - Contacts, handshake lifecycle, message sending/receiving, decryption/verification, unread badges, safety number UI.
- `ThreatModel.jsx`
  - Security assumptions and threat coverage view.
- `MetricsPanel.jsx`
  - Runtime cryptographic benchmark panel.

## 8.2 Local Storage Contract

Common keys:

- `pq_username`
- `pq_dsa_private_key`
- `pq_dsa_public_key`
- `pq_kem_private_key`
- `pq_kem_public_key`
- `pq_session_token`
- `pq_secret_<contact>` (per-contact shared secret)

Logout/session recovery removes only `pq_*` keys (not all browser localStorage).

## 8.3 API Integration

- Axios instance points to `http://localhost:5000/api`.
- Request interceptor injects bearer token if present.
- Chat polling interval: 5 seconds for pending handshakes/unread/messages.
- Read receipts are sent once when opening conversation (`markMessagesRead`).

## 9. Security Controls and Limitations

## 9.1 Implemented Controls

- Post-quantum KEM and signature primitives.
- Transcript-bound signatures for handshake and messages.
- HKDF-based key derivation with domain separation.
- Authenticated route access with token-user binding.
- Replay-defense mechanisms (unique IV constraint + signature context).
- Rate limiting and hardened HTTP headers.

## 9.2 Explicit Limitations

- **TOFU identity mapping:** server-provided public keys are trusted until safety-number verification.
- **Private keys in localStorage:** acceptable for academic/demo scope; not HSM/secure-enclave level.
- **Session token lifecycle:** no explicit expiration/rotation/revocation endpoint yet.
- **No perfect forward secrecy rotation policy:** per-contact secret persistence can expose historical ciphertext if endpoint compromise occurs.

## 10. Testing and Validation

## 10.1 Backend Test Script

Run:

```bash
cd pq_backend
npm test
```

This executes `testFlow.js`, simulating key generation, registration, encapsulation, decapsulation, and shared-secret equivalence checks.

## 10.2 Manual QA Checklist

- Register two users successfully.
- Confirm both users appear in contact lists.
- Initiate handshake from user A to B.
- Confirm pending handshake appears and completes for B.
- Send encrypted message and verify recipient decryption.
- Confirm signature status appears valid in chat UI.
- Verify unread badge increments/decrements correctly.
- Compare safety number out-of-band between clients.

## 11. Troubleshooting

- **Cannot register / network error:** ensure backend is running at `localhost:5000`.
- **500 on backend routes:** verify `MONGODB_URI` and database availability.
- **Unauthorized (401/403):** ensure `pq_session_token` exists and maps to correct user.
- **Decryption failed message:** shared secret mismatch; re-run handshake between contacts.
- **No contacts displayed:** only registered users other than current user appear.

## 12. Suggested Future Improvements

- Session token expiry, refresh, and revocation support.
- Optional passphrase-based local key wrapping (e.g., Argon2id + AES-GCM).
- Automatic key/secret rotation strategy per session or epoch.
- Delivery acknowledgments and stronger anti-replay sequence counters.
- Production deployment profile (HTTPS, secret manager, centralized logs, CI tests).

