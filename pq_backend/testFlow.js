const {
    generateSignatureKeys,
    generateKEMKeys,
    encapsulateSecret,
    decapsulateSecret
} = require('./utils/cryptoUtils');

async function runTest() {
    console.log("=== Starting Post-Quantum Handshake Simulation ===\n");

    console.log("[User B] Generating Dilithium (Identity) and Kyber (KEM) keys...");
    const userBDilithium = generateSignatureKeys();
    const userBKyber = generateKEMKeys();

    console.log("[User B] Registering Dilithium public key on the server (POST /api/keys/register)...");
    try {
        const registerRes = await fetch('http://localhost:5000/api/keys/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: `test_user_${Date.now()}`,
                dilithiumPublicKey: userBDilithium.publicKey,
                kyberPublicKey: userBKyber.publicKey
            })
        });
        const registerData = await registerRes.json();
        console.log("         Server Response:", registerData.message || registerData.error);
    } catch (e) {
        console.log("❌ ERROR: Could not connect to API. Is 'node server.js' running?");
        return;
    }

    console.log("\n[User A] Fetching User B's public identity key from server (GET /api/keys/publicKey)...");

    console.log("\n[Network] User B sends their Kyber Public Key to User A.");
    console.log("[User A] Encapsulating a shared secret using User B's Kyber Public Key...");

    const encapsulation = encapsulateSecret(userBKyber.publicKey);

    console.log(`         [User A] Generated Shared Secret: ${encapsulation.sharedSecret.substring(0, 40)}...`);
    console.log(`         [User A] Generated Ciphertext:    ${encapsulation.ciphertext.substring(0, 40)}...`);

    console.log("\n[User B] Receiving ciphertext and decapsulating using private Kyber key...");
    const recoveredSecret = decapsulateSecret(encapsulation.ciphertext, userBKyber.privateKey);
    console.log(`         [User B] Recovered Shared Secret: ${recoveredSecret.substring(0, 40)}...`);

    if (encapsulation.sharedSecret === recoveredSecret) {
        console.log("\n✅ SUCCESS: Both users now share the exact same post-quantum secure secret!");
        console.log("   (This secret will now be plugged into AES-GCM for standard messaging).");
    } else {
        console.log("\n❌ ERROR: Shared secrets do not match.");
    }
}

runTest();
