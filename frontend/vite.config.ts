import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // patronus-dashboard (crates/patronus-dashboard/src/main.rs) serves
    // static/index.html and static/assets/* directly, and
    // docker-compose.ha.yml bind-mounts repo-root ./static into each
    // dashboard container read-only. Build straight there so
    // build-frontend.sh needs no separate copy step.
    outDir: '../static',
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8443',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8443',
        ws: true,
      },
    },
  },
})
