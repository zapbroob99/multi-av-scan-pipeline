import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwind from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'MASP_')
  const target = env.MASP_BACKEND_URL || 'http://127.0.0.1:8000'
  return {
    base: '/console/', plugins: [react(), tailwind()],
    resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
    server: {
      strictPort: true,
      // Former legacy paths (/, /login, /scans/{id}...) redirect to /console on the backend.
      // Vite and its assets live entirely under /console/.
      proxy: { '^/(?!console(?:/|$))': { target, changeOrigin: false } },
    },
    build: { sourcemap: false, chunkSizeWarningLimit: 350 },
  }
})
