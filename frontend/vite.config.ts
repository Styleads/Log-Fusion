import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const STORAGE_API_TARGET = process.env.STORAGE_API_URL || 'http://localhost:8000';
const ENGINE_API_TARGET = process.env.ENGINE_API_URL || 'http://localhost:8001';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    open: false,
    proxy: {
      '/api': {
        target: STORAGE_API_TARGET,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, ''),
        configure: (proxy) => {
          proxy.on('error', (_err, _req, res) => {
            if (res && !res.headersSent) {
              res.writeHead(503, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ status: 'offline', detail: 'Storage API offline' }));
            }
          });
        }
      },
      '/engine-api': {
        target: ENGINE_API_TARGET,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/engine-api/, ''),
        configure: (proxy) => {
          proxy.on('error', (_err, _req, res) => {
            if (res && !res.headersSent) {
              res.writeHead(503, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ status: 'offline', detail: 'Engine API offline' }));
            }
          });
        }
      }
    }
  }
});
