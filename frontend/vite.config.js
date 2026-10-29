import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // The shared MFA panel lives outside this app; keep it on this React runtime.
  resolve: {
    dedupe: ['react', 'react-dom'],
  },
  server: {
    host: '127.0.0.1',
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET || 'http://127.0.0.1:8080',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyRequest, request) => {
            const clientAddress = request.socket?.remoteAddress;
            if (clientAddress) proxyRequest.setHeader('X-Forwarded-For', clientAddress);
          });
        },
      },
    },
  },
});
