// =============================================================================
// Screenshot capture — feeds design/screenshots/*.png used by user-guide and
// docs. Not part of the CI gate; runs manually:
//
//   SK_BOOTSTRAP_ADMIN_PASSWORD=screenshot-admin-passw0rd \
//     npx playwright test screenshots --project=chromium --grep=@screenshots
//
// The script:
//   1. Hits the public flow: landing page, request, reveal ready, reveal
//      consumed.
//   2. Walks through the admin bootstrap (password change + TOTP enrol)
//      using a fresh secret computed inline from the value the setup page
//      hands back.
//   3. Captures the main admin surfaces (dashboard, domains, policies,
//      libraries, templates, integrations, branding, audit, security).
//
// PNGs land in design/screenshots/. The capture is deterministic enough
// for the file diff to be reviewable.
// =============================================================================

import { expect, test } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { totp } from "./totp";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCREENSHOTS_DIR = path.resolve(
  __dirname,
  "..",
  "..",
  "..",
  "design",
  "screenshots",
);
const ADMIN_EMAIL = "admin@localhost";
const ADMIN_PASSWORD = process.env.SK_BOOTSTRAP_ADMIN_PASSWORD ?? "";
const NEW_ADMIN_PASSWORD = "Demo-Admin-2026-Strong!";

// ---- spec -------------------------------------------------------------------

test.describe.configure({ mode: "serial" });

test.describe("@screenshots design assets", () => {
  test.beforeAll(async () => {
    if (!ADMIN_PASSWORD) {
      throw new Error(
        "SK_BOOTSTRAP_ADMIN_PASSWORD must be set so the binary boots with a known admin password.",
      );
    }
    await fs.mkdir(SCREENSHOTS_DIR, { recursive: true });
  });

  test.use({
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 1.5,
  });

  async function snap(page: import("@playwright/test").Page, name: string) {
    await page.screenshot({
      path: path.join(SCREENSHOTS_DIR, name),
      fullPage: false,
    });
  }

  test("public landing page", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("h1, h2").first()).toBeVisible();
    await snap(page, "public-landing.png");
  });

  test("reveal page (ready then consumed)", async ({ page, request }) => {
    // Mint a token via the public API so we land on a real reveal URL.
    const email = `screenshots+${Date.now()}@example.test`;
    const accept = await request.post("/api/v1/request", {
      data: { email, domain: "example.test", subject: "screenshots" },
      headers: { "Content-Type": "application/json" },
    });
    expect(accept.status()).toBe(202);
    const accepted = await accept.json();
    // Eval mode surfaces the URL under `debug_reveal_url` (see
    // handleRequest in internal/httpserver/server.go).
    const revealURL: string = accepted.debug_reveal_url ?? accepted.reveal_url;
    expect(typeof revealURL).toBe("string");

    await page.goto(revealURL);
    await expect(page.locator("body")).toBeVisible();
    await snap(page, "reveal-ready.png");

    // Click the decode button (label is FR by default — match it loosely).
    const decode = page
      .getByRole("button", { name: /d[eé]code|reveal|voir/i })
      .first();
    if (await decode.count()) {
      await decode.click();
      // Give the JS bundle a beat to render proposals.
      await page.waitForTimeout(800);
    }
    await snap(page, "reveal-consumed.png");
  });

  // One serial test walks the admin flow so the session cookie set on
  // /admin/login is reused across every page capture below.
  test("admin console — bootstrap + every nav surface", async ({ page }) => {
    await page.goto("/admin/login");
    await snap(page, "admin-login.png");

    await page.locator("#email").fill(ADMIN_EMAIL);
    await page.locator("#password").fill(ADMIN_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();

    await page.waitForURL(/\/admin\/setup/);
    const secret = await page
      .locator('[data-testid="totp-secret"]')
      .textContent();
    expect(secret).toBeTruthy();
    await snap(page, "admin-setup.png");

    await page.locator("#np").fill(NEW_ADMIN_PASSWORD);
    await page.locator("#np2").fill(NEW_ADMIN_PASSWORD);
    await page.locator("#tc").fill(totp(secret!.trim()));
    await page.getByRole("button", { name: /save and continue/i }).click();
    await page.waitForURL(/\/admin\/dashboard/);
    await expect(page.locator("h2")).toContainText(/welcome/i);
    await snap(page, "admin-dashboard.png");

    // Seed one domain + one policy so the screenshots show non-empty
    // states. CSRF token is read from the cookie that the session
    // handshake set, then echoed in each form post.
    const csrf =
      (await page.evaluate(() => {
        const m = document.cookie.match(/sk_admin_csrf=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : "";
      })) || "";

    await page.request.post("/admin/domains/add", {
      form: {
        csrf_token: csrf,
        name: "example.com",
        description: "Demo domain",
        active: "on",
      },
    });

    const adminPages: { path: string; file: string }[] = [
      { path: "/admin/domains", file: "admin-domains.png" },
      { path: "/admin/policies", file: "admin-policies.png" },
      { path: "/admin/elevations", file: "admin-elevations.png" },
      { path: "/admin/libraries", file: "admin-libraries.png" },
      { path: "/admin/templates", file: "admin-templates.png" },
      { path: "/admin/integrations", file: "admin-integrations.png" },
      { path: "/admin/branding", file: "admin-branding.png" },
      { path: "/admin/security", file: "admin-security.png" },
      { path: "/admin/admins", file: "admin-admins.png" },
      { path: "/admin/account", file: "admin-account.png" },
      { path: "/admin/audit", file: "admin-audit.png" },
    ];
    for (const { path: route, file } of adminPages) {
      await page.goto(route);
      await expect(page.locator("h2").first()).toBeVisible();
      // Pause briefly so async widgets (entropy preview, JS hydration)
      // have time to render before the capture.
      await page.waitForTimeout(400);
      await snap(page, file);
    }
  });
});
