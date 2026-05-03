# Post-Quantum Secure Messaging System

This is a MERN-stack communication system that is secure against quantum-computer adversaries using lattice-based cryptography. It integrates ML-KEM-768 (Kyber) for post-quantum key exchange, ML-DSA-65 (Dilithium) for digital signatures, and AES-256-GCM for symmetric messaging.

## Full Technical Documentation

For complete architecture, API reference, cryptographic workflow, security controls, and testing guidance, see:

- [Technical Documentation](./TECHNICAL_DOCUMENTATION.md)

## Requirements

You must have **Node.js** and **npm** installed on your system to run this project.

- Node.js (v18 or higher recommended)
- MongoDB (running locally or a connection string in the `.env` file)

## Installation

This project is separated into a frontend (React/Vite) and a backend (Node.js/Express). The `package.json` files in each directory act as the "requirements file" for all dependencies.

For convenience, you can just run the `install.bat` file which will automatically install all the dependencies for both the frontend and backend.

Alternatively, you can manually install the dependencies:

1. **Backend**:
   ```bash
   cd pq_backend
   npm install
   ```

2. **Frontend**:
   ```bash
   cd pq_frontend
   npm install
   ```

## Running the Application

For convenience, you can simply run the `start.bat` file to start both the frontend and backend simultaneously.

Alternatively, you can manually start them:

1. **Backend**:
   ```bash
   cd pq_backend
   npm start
   ```

2. **Frontend**:
   ```bash
   cd pq_frontend
   npm run dev
   ```

## Environment Variables

Make sure to set up your `.env` file in the `pq_backend` directory (do NOT commit this file to GitHub, as it contains secrets).
Example `.env`:
```
PORT=5000
MONGODB_URI=mongodb://localhost:27017/pq_messaging
```
