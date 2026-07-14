import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// base: './' so the built assets load with relative paths when the SPA is
// served from the FastAPI process at the site root.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: { outDir: 'dist' },
  server: {
    // For local dev only: proxy /api to a reachable backend.
    proxy: {
      '/api': { target: 'http://127.0.0.1:8090', changeOrigin: true },
    },
  },
})
