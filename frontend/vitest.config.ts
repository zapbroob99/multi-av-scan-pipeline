import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({ plugins: [react()], test: {
  // Timestamps render in the browser's zone; pin it so results never depend on the machine.
  environment: 'jsdom', globals: true, setupFiles: ['./src/test-setup.ts'], env: { TZ: 'UTC' },
  include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
} })
