import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';
import path from 'path';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

// https://vitejs.dev/config/
export default defineConfig({
  base: '/class/cs355/',
  plugins: [react(), wasm(), topLevelAwait()],
  server: {
    port: 3000, // Set the desired port
    proxy: {
      '/class/cs355/cgi-bin': {
        target: 'http://localhost:8000', // If using CGI-based API, proxy to php server
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/class\/cs355\/cgi-bin/, ''),
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
