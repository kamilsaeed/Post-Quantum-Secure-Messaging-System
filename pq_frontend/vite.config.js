import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Required for @noble/post-quantum — it uses BigInt extensively
  optimizeDeps: {
    include: ['@noble/post-quantum/ml-kem.js', '@noble/post-quantum/ml-dsa.js'],
  },
  build: {
    target: 'esnext', // Required for BigInt support in build output
  },
  server: {
    port: 5173,
    // Proxy API requests to the Express backend during development
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },
})
