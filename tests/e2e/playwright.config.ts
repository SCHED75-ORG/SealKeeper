// =============================================================================
// SealKeeper — Playwright configuration
// =============================================================================
// PRD: FR-L.19 (TypeScript), FR-L.27 (Chromium + Firefox + WebKit), FR-L.29
// (eval mode with SMTP capture), FR-L.30 (artifacts on failure), FR-L.47
// (CI on PR runs the @happy-path subset on Chromium only).
//
// The SealKeeper binary is launched by Playwright's `webServer`. CI sets
// SEALKEEPER_BIN to the pre-built artifact; locally we fall back to `go run`.
// =============================================================================

import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..");

const PORT = Number(process.env.SK_PORT ?? 8443);
const BASE_URL = process.env.SK_BASE_URL ?? `http://127.0.0.1:${PORT}`;

const sealkeeperBin = process.env.SEALKEEPER_BIN;
const serverCommand = sealkeeperBin
  ? `"${sealkeeperBin}" serve`
  : `go run ./cmd/sealkeeper serve`;

export default defineConfig({
  testDir: "./tests",
  outputDir: "./test-results",

  // Higher per-test timeout: the first run pays for the binary boot cost.
  timeout: 30_000,
  expect: { timeout: 5_000 },

  fullyParallel: false, // single backend instance shared by tests
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,

  reporter: process.env.CI
    ? [
        ["github"],
        ["html", { open: "never", outputFolder: "playwright-report" }],
        ["junit", { outputFile: "playwright-report/junit.xml" }],
      ]
    : [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],

  use: {
    baseURL: BASE_URL,
    trace: process.env.CI ? "retain-on-failure" : "on-first-retry",
    screenshot: "only-on-failure",
    video: process.env.CI ? "retain-on-failure" : "off",
    ignoreHTTPSErrors: true,
    actionTimeout: 10_000,
  },

  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],

  webServer: {
    command: serverCommand,
    // Always start from REPO_ROOT so the binary can autodetect web/dist via a
    // relative path regardless of which path Playwright is invoked from.
    cwd: REPO_ROOT,
    url: `${BASE_URL}/healthz`,
    timeout: 60_000,
    reuseExistingServer: !process.env.CI,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...process.env,
      SK_MODE: "eval",
      SK_HTTP_LISTEN: `:${PORT}`,
      SK_BASE_URL: BASE_URL,
      // Force an in-memory SQLite so the suite is hermetic on every OS and
      // the run leaves no artefacts behind. Real persistence is exercised
      // by internal/storage tests against a temp file. SK_E2E_DATABASE_URL
      // points the suite at a real Postgres instead (dialect parity check).
      SK_DATABASE_URL: process.env.SK_E2E_DATABASE_URL ?? "sqlite://:memory:",
      // Pin the JS bundle path explicitly so the reveal-page tests can load
      // /static/sealkeeper-generation.umd.js even when the binary's cwd
      // resolution differs across OSes.
      SK_WEB_DIR: path.join(REPO_ROOT, "web", "dist"),
      SK_LOG_FORMAT: "json",
      SK_LOG_LEVEL: "info",
    },
  },
});
