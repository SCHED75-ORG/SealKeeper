// =============================================================================
// Content-Security-Policy regression — no page may trip the CSP
// =============================================================================
// Every response carries a strict CSP (script-src 'self' + per-response
// nonce, no 'unsafe-inline'). An inline <script> without the nonce or an
// inline on*= handler silently stops working under that policy, so this spec
// walks the public flow and every admin surface and fails on any CSP
// violation or uncaught page error.
//
// Needs SK_BOOTSTRAP_ADMIN_PASSWORD (as for screenshots.spec.ts).
// =============================================================================

import { expect, test, type Page } from "@playwright/test";

import { totp } from "./totp";

const ADMIN_PASSWORD = process.env.SK_BOOTSTRAP_ADMIN_PASSWORD ?? "";

function watch(page: Page): string[] {
  const problems: string[] = [];
  page.on("console", (m) => {
    if (
      /Content Security Policy|Refused to (execute|load|apply)/i.test(m.text())
    ) {
      problems.push(`${page.url()}: ${m.text()}`);
    }
  });
  page.on("pageerror", (e) => problems.push(`${page.url()}: ${e.message}`));
  return problems;
}

test.describe("@csp", () => {
  test("public pages and reveal flow run under the CSP", async ({
    page,
    request,
  }) => {
    const problems = watch(page);
    const res = await page.goto("/");
    expect(res?.headers()["content-security-policy"]).toContain(
      "script-src 'self' 'nonce-",
    );
    expect(res?.headers()["referrer-policy"]).toBe("no-referrer");
    await page
      .locator('input[type="email"]')
      .fill(`csp+${Date.now()}@example.test`);
    await page.getByRole("button", { name: /generate/i }).click();
    await expect(page.locator("#ack")).toContainText(/on its way/i);

    const accept = await request.post("/api/v1/request", {
      data: { email: `csp-reveal+${Date.now()}@example.test` },
    });
    const { debug_reveal_url: url } = (await accept.json()) as {
      debug_reveal_url: string;
    };
    await page.goto(url);
    await page.getByRole("button", { name: /Décoder/i }).click();
    await expect(
      page.locator('[data-testid="proposal"]').first(),
    ).toBeVisible();
    expect(problems).toEqual([]);
  });

  test("admin console runs under the CSP", async ({ page }) => {
    test.skip(!ADMIN_PASSWORD, "SK_BOOTSTRAP_ADMIN_PASSWORD not set");
    const problems = watch(page);
    await page.goto("/admin/login");
    await page.locator("#email").fill("admin@localhost");
    await page.locator("#password").fill(ADMIN_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    await page.waitForURL(/\/admin\/setup/);
    const secret = (await page
      .locator('[data-testid="totp-secret"]')
      .textContent())!.trim();
    await page.locator("#np").fill("Csp-Admin-2026-Strong!");
    await page.locator("#np2").fill("Csp-Admin-2026-Strong!");
    await page.locator("#tc").fill(totp(secret));
    await page.getByRole("button", { name: /save and continue/i }).click();
    await page.waitForURL(/\/admin\/dashboard/);

    for (const route of [
      "/admin/dashboard",
      "/admin/domains",
      "/admin/policies",
      "/admin/elevations",
      "/admin/libraries",
      "/admin/templates",
      "/admin/templates/edit?kind=reveal_link&language=fr",
      "/admin/integrations",
      "/admin/smtp",
      "/admin/branding",
      "/admin/security",
      "/admin/admins",
      "/admin/account",
      "/admin/audit",
      "/admin/captured-mail",
    ]) {
      await page.goto(route);
      await expect(page.locator("h2").first()).toBeVisible();
      await page.waitForTimeout(300);
    }

    // A new admin's one-time password is shown on the POST response only,
    // never carried in a redirect URL.
    await page.goto("/admin/admins");
    await page.locator("#add-email").fill(`second+${Date.now()}@example.test`);
    await page.getByRole("button", { name: /create admin/i }).click();
    await expect(
      page.locator('[data-testid="bootstrap-password"]'),
    ).toBeVisible();
    expect(page.url()).not.toContain("bootstrap_password");

    // Credential changes require the current password (step-up).
    await page.goto("/admin/account");
    await page.locator("#cp-password").fill("not-the-password");
    await page.locator("#np").fill("Another-Csp-Admin-2026!");
    await page.locator("#np2").fill("Another-Csp-Admin-2026!");
    await page.getByRole("button", { name: /update password/i }).click();
    await expect(page).toHaveURL(/err=current_password/);

    // Logout carries the session CSRF token and works.
    await page.getByRole("button", { name: /logout/i }).click();
    await expect(page).toHaveURL(/\/admin\/login/);
    expect(problems).toEqual([]);
  });
});
