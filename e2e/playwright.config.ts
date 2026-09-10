import { defineConfig, devices } from '@playwright/test';

const operatorTokenFile = process.env.KEYMELD_OPERATOR_TOKEN_FILE;
if (!operatorTokenFile) {
  throw new Error('Set KEYMELD_OPERATOR_TOKEN_FILE to the gateway operator token file, or use just test-ui-e2e.');
}

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? 'github' : 'html',
  timeout: 30000,

  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:8090',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Don't start a web server - we expect services to already be running
  // via `just start` or `just quickstart`
});
