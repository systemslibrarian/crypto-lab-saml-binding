import { defineConfig, devices } from '@playwright/test';

const PORT = 4675;
const BASE = '/crypto-lab-saml-binding/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // Zero retries, deliberately. Every run in this lab is deterministic: no
  // network, fixed fixtures, a frozen clock. A retry would hide a real
  // nondeterminism rather than tolerate an unavoidable one.
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // Build before serving: `vite preview` serves whatever is already in dist/,
    // so without this a failing build leaves the previous good bundle in place
    // and the suite passes green against code that no longer compiles.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    port: PORT,
    reuseExistingServer: !process.env.CI,
    timeout: 180000,
  },
});
