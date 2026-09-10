import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e', outputDir: '../artifacts/console-e2e', workers: 1,
  use: { baseURL: 'http://127.0.0.1:5175/console/',
    channel: process.platform === 'win32' ? 'msedge' : undefined, headless: true, trace: 'retain-on-failure' },
  webServer: [
    { command: 'python ../tools/serve_console_fixture.py', url: 'http://127.0.0.1:18765/openapi.json', reuseExistingServer: false, timeout: 30000 },
    { command: 'npm run dev -- --port 5175', url: 'http://127.0.0.1:5175/console/', reuseExistingServer: false,
      env: { MASP_BACKEND_URL: 'http://127.0.0.1:18765' }, timeout: 30000 },
  ],
})
