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
      },
      '/engine-api': {
        target: ENGINE_API_TARGET,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/engine-api/, ''),
      }
    }
  }
});

