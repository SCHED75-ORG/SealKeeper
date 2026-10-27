// =============================================================================
// Website (design/) — security headers, CSP cleanliness, security.txt
// =============================================================================
// Every page of the static site must render under the CSP shipped in
// design/_headers with zero CSP violations, zero console errors and zero page
// errors — governance pages included, where marked renders the repository's
// Markdown and mermaid turns its ```mermaid blocks into SVG.
//
// Third-party origins are stubbed (fonts, badges) or answered from the
// working tree (raw.githubusercontent.com) so the run is hermetic. Chromium
// enforces the CSP before a request reaches page.route, so stubbing does not
// hide violations; the "CSP is enforced" test guards that assumption.
//
//   cd tests/e2e && npx playwright test -c playwright.site.config.ts
// =============================================================================

import { expect, test, type Page } from "@playwright/test";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..", "..");
const SITE = path.resolve(
  process.env.SITE_ROOT ?? path.join(REPO_ROOT, "design"),
);
const PAGES = readdirSync(SITE).filter((f) => f.endsWith(".html"));
const RAW_PREFIX = "https://raw.githubusercontent.com/SCHED75-ORG/SealKeeper/main/";

const STUB_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="20"></svg>';

async function stubThirdParties(page: Page): Promise<void> {
  await page.route("https://fonts.bunny.net/**", (r) =>
    r.fulfill({ contentType: "text/css", body: "/* stub */" }),
  );
  await page.route("https://img.shields.io/**", (r) =>
    r.fulfill({ contentType: "image/svg+xml", body: STUB_SVG }),
  );
  await page.route(`${RAW_PREFIX}**`, (r) => {
    const file = r.request().url().slice(RAW_PREFIX.length);
    return r.fulfill({
      contentType: "text/plain; charset=utf-8",
      headers: { "access-control-allow-origin": "*" },
      body: readFileSync(path.join(REPO_ROOT, file), "utf8"),
    });
  });
}

type Watch = { problems: string[]; violations: () => Promise<string[]> };

async function watch(page: Page): Promise<Watch> {
  const problems: string[] = [];
  await page.addInitScript(() => {
    const w = window as unknown as { __csp: string[] };
    w.__csp = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      w.__csp.push(`${e.effectiveDirective} blocked ${e.blockedURI}`);
    });
  });
  page.on("console", (m) => {
    const text = m.text();
    if (
      m.type() === "error" ||
      /Content Security Policy|Permissions-Policy|Mermaid render error|Failed to load Markdown/i.test(
        text,
      )
    ) {
      problems.push(`console.${m.type()}: ${text}`);
    }
  });
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  return {
    problems,
    violations: () =>
      page.evaluate(() => (window as unknown as { __csp: string[] }).__csp),
  };
}

function mermaidBlocks(mdFile: string): number {
  const src = readFileSync(path.join(REPO_ROOT, mdFile), "utf8");
  return (src.match(/^```mermaid\s*$/gm) ?? []).length;
}

test.describe("@site", () => {
  test("every page sends the hardened headers", async ({ request }) => {
    for (const p of PAGES) {
      const res = await request.get(`/${p}`);
      expect(res.status(), p).toBe(200);
      const h = res.headers();
      const csp = h["content-security-policy"] ?? "";
      const scriptSrc = /script-src ([^;]*)/.exec(csp)?.[1] ?? "";
      expect(scriptSrc.trim(), p).toBe("'self'");
      expect(csp, p).toContain("default-src 'none'");
      expect(csp, p).toContain("frame-ancestors 'none'");
      expect(csp, p).toContain("object-src 'none'");
      expect(csp, p).toContain("base-uri 'none'");
      expect(h["strict-transport-security"], p).toMatch(/max-age=\d{7,}/);
      expect(h["x-content-type-options"], p).toBe("nosniff");
      expect(h["referrer-policy"], p).toBe("strict-origin-when-cross-origin");
      expect(h["permissions-policy"], p).toContain("camera=()");
      expect(h["x-frame-options"], p).toBe("DENY");
    }
    expect((await request.get("/_headers")).status()).toBe(404);
  });

  test("no inline or third-party script, no Cloudflare email artefact", async () => {
    for (const p of PAGES) {
      const html = readFileSync(path.join(SITE, p), "utf8");
      expect(html, p).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/i);
      for (const [, src] of html.matchAll(/<script[^>]*\bsrc="([^"]+)"/gi)) {
        expect(src, p).toMatch(/^\/(site\.js|vendor\/[\w.-]+\.js)$/);
      }
      expect(html, p).not.toMatch(/\son[a-z]+\s*=/i);
      expect(html, p).not.toMatch(/cdn-cgi|__cf_email__|data-cfemail/);
    }
  });

  test("CSP is enforced (guards the stubbing assumption)", async ({ page }) => {
    await stubThirdParties(page);
    const w = await watch(page);
    await page.goto("/index.html");
    await page.route("https://example.org/**", (r) =>
      r.fulfill({ body: "{}" }),
    );
    await page.evaluate(() =>
      fetch("https://example.org/x").catch(() => undefined),
    );
    await expect
      .poll(w.violations)
      .toContain("connect-src blocked https://example.org/x");
  });

  for (const p of PAGES) {
    test(`${p} renders with no CSP violation or console error`, async ({
      page,
    }) => {
      await stubThirdParties(page);
      const w = await watch(page);
      await page.goto(`/${p}`);
      await page.waitForLoadState("load");

      const mdSource = await page
        .locator("body")
        .getAttribute("data-md-source");
      if (mdSource) {
        const mdFile = mdSource.slice(RAW_PREFIX.length);
        await expect(page.locator("#md-loading")).toHaveCount(0);
        await expect(page.locator("#md-error")).toBeHidden();
        await expect(page.locator("#md-content h2").first()).toBeVisible();
        const diagrams = mermaidBlocks(mdFile);
        expect(diagrams, mdFile).toBeGreaterThan(0);
        await expect(page.locator("#md-content .mermaid svg")).toHaveCount(
          diagrams,
        );
        await expect(
          page.locator("#md-content .mermaid", { hasText: /Syntax error/i }),
        ).toHaveCount(0);
      }

      // site.js is live: the theme toggle flips data-theme.
      const before = await page.locator("html").getAttribute("data-theme");
      await page.locator("#theme-toggle").click();
      await expect(page.locator("html")).not.toHaveAttribute(
        "data-theme",
        before ?? "",
      );

      expect(await w.violations()).toEqual([]);
      expect(w.problems).toEqual([]);
    });
  }

  test("security.txt follows RFC 9116", async ({ request }) => {
    const res = await request.get("/.well-known/security.txt");
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toMatch(/^text\/plain/);
    const fields = new Map<string, string[]>();
    for (const line of (await res.text()).split(/\r?\n/)) {
      if (line === "" || line.startsWith("#")) continue;
      const m = /^([A-Za-z-]+): (.+)$/.exec(line);
      expect(m, line).not.toBeNull();
      const key = m![1].toLowerCase();
      fields.set(key, [...(fields.get(key) ?? []), m![2]]);
    }
    expect(fields.get("contact")).toEqual([
      "mailto:security@sealkeeper.eu",
      "https://github.com/SCHED75-ORG/SealKeeper/security/advisories/new",
    ]);
    expect(fields.get("expires")).toHaveLength(1);
    const days =
      (Date.parse(fields.get("expires")![0]) - Date.now()) / 86_400_000;
    expect(days, "Expires must be renewed").toBeGreaterThan(30);
    expect(days, "RFC 9116 §2.5.5: less than a year ahead").toBeLessThanOrEqual(
      366,
    );
    expect(fields.get("encryption")).toEqual([
      "https://sealkeeper.eu/.well-known/pgp-key.asc",
    ]);
    expect(fields.get("policy")).toEqual(["https://sealkeeper.eu/security"]);
    expect(fields.get("acknowledgments")).toEqual([
      "https://sealkeeper.eu/hall-of-thanks",
    ]);
    expect(fields.get("preferred-languages")).toEqual(["en, fr"]);
    expect(fields.get("canonical")).toEqual([
      "https://sealkeeper.eu/.well-known/security.txt",
    ]);
  });

  test("self-hosted vendor bundles match their recorded SHA-256", async () => {
    const { createHash } = await import("node:crypto");
    const sums = readFileSync(path.join(SITE, "vendor", "SHA256SUMS"), "utf8");
    const lines = sums.trim().split(/\r?\n/);
    expect(lines.length).toBe(2);
    for (const line of lines) {
      const [sum, file] = line.split(/\s+/);
      const body = readFileSync(path.join(SITE, "vendor", file));
      expect(createHash("sha256").update(body).digest("hex"), file).toBe(sum);
    }
  });
});
