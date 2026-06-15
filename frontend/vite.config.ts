import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// During dev the control-plane runs on :8080. Proxy the API + SSE stream
// there so the browser talks to one origin (no CORS) — same as prod, where
// control-plane serves the built assets itself.
const controlPlane = 'http://127.0.0.1:8080'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/alerts': controlPlane,
      '/agents': controlPlane,
      '/healthz': controlPlane,
      // SSE — disable buffering so events arrive as they're pushed
      '/api': { target: controlPlane, changeOrigin: true },
    },
  },
})
