import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Override to develop against another panel: DNSJOS_PANEL=http://host:port pnpm dev
const panel = process.env.DNSJOS_PANEL ?? 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, './src') } },
  build: { outDir: 'dist', emptyOutDir: true, chunkSizeWarningLimit: 800 },
  server: {
    proxy: Object.fromEntries(['/api', '/agent', '/install.sh', '/dl', '/healthz'].map((p) => [p, panel])),
  },
})
