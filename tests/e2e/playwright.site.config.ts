// =============================================================================
// SealKeeper — Playwright configuration for the static website (design/)
// =============================================================================
// Separate from playwright.config.ts because the website is not served by the
// SealKeeper binary: site/serve.mjs serves design/ and applies design/_headers
// the way Cloudflare Workers static assets does. Set SITE_BASE_URL to run the
// same spec against another server instead (e.g. `wrangler dev --assets
// ../../design`, or a preview deployment).
//
//   npx playwright test -c playwright.site.config.ts
// =============================================================================

import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.SITE_PORT ?? 19180);
const external = process.env.SITE_BASE_URL;
const BASE_URL = external ?? `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: "./site",
  outputDir: "./test-results/site",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  forbidOnly: !!process.env.CI,
  reporter: [["list"]],
  use: { baseURL: BASE_URL },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: external
    ? undefined
    : {
        command: "node site/serve.mjs",
        url: `${BASE_URL}/`,
        timeout: 30_000,
        reuseExistingServer: !process.env.CI,
        env: { ...process.env, SITE_PORT: String(PORT) },
      },
});
