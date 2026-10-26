// =============================================================================
// Happy path — the only @happy-path-tagged spec
// =============================================================================
// PRD: FR-L.20 (happy path: user requests, opens mail, reveals password).
//
// This subset of the full flow is what ci.yml runs on every PR (FR-L.47).
// The remaining five canonical scenarios are tagged @nightly and live next to
// this file; they fill in as the reveal page lands.
//
// We exercise SealKeeper through its public HTTP surface plus the eval-only
// /__captured_mail endpoint that backs FR-H.17.
// =============================================================================

import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test";

// stubbedRevealURL returns a reveal link for tests that stub the policy
// endpoint: the token is never consumed, so one link serves them all and
// the suite stays under the eval per-IP request limit.
let stubbedURL: string | undefined;
async function stubbedRevealURL(request: APIRequestContext): Promise<string> {
  if (stubbedURL) return stubbedURL;
  const accept = await request.post("/api/v1/request", {
    data: { email: `stubbed+${Date.now()}@example.test` },
    headers: { "Content-Type": "application/json" },
  });
  expect(accept.status()).toBe(202);
  const { debug_reveal_url: url } = (await accept.json()) as {
    debug_reveal_url: string;
  };
  expect(typeof url).toBe("string");
  stubbedURL = url;
  return url;
}

// stubPolicy answers the token consumption with a small G3 policy so the
// tests need no admin setup.
async function stubPolicy(page: Page, extra: Record<string, unknown>) {
  // The reveal page consumes the token with POST {"token":…}.
  await page.route("**/api/v1/policy", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        policy: {
          generator: "G3",
          proposalCount: 2,
          anssiLevel: "B3",
          parameters: { length: 24 },
          ...extra,
        },
      }),
    }),
  );
}

test.describe("@happy-path public flow", () => {
  test("landing page advertises the available routes in eval mode", async ({
    page,
  }) => {
    const response = await page.goto("/");
    expect(response?.status()).toBe(200);
    await expect(page).toHaveTitle(/SealKeeper/);

    // FR-H.13 — eval mode shows an unmistakable banner.
    await expect(page.getByText(/Evaluation mode/i)).toBeVisible();

    // Operator-facing endpoints are linked from the stub landing page,
    // tucked under a <details> disclosure widget. Expand it first.
    const opsDetails = page.locator("details");
    await opsDetails.evaluate((el: HTMLDetailsElement) => (el.open = true));
    for (const path of [
      "/healthz",
      "/readyz",
      "/metrics",
      "/api/v1/policy",
      "/version",
    ]) {
      await expect(page.locator(`a[href="${path}"]`)).toBeVisible();
    }
  });

  test("policy endpoint returns the v0.1 default JSON", async ({ request }) => {
    const r = await request.get("/api/v1/policy");
    expect(r.status()).toBe(200);
    expect(r.headers()["content-type"]).toMatch(/application\/json/);

    const body = await r.json();
    expect(body).toMatchObject({
      version: 1,
      generators: expect.arrayContaining(["G1", "G2", "G3"]),
      min_entropy_bits: 80,
      levels: expect.arrayContaining(["standard", "high", "very_high"]),
      transforms: expect.arrayContaining([
        "T01",
        "T02",
        "T03",
        "T04",
        "T05",
        "T06",
        "T07",
        "T08",
        "T09",
      ]),
    });
  });

  test("user request is accepted and the mail is captured in eval mode", async ({
    request,
  }) => {
    const email = `happy+${Date.now()}@example.test`;
    const accept = await request.post("/api/v1/request", {
      data: { email, domain: "example.test", subject: "smoke" },
      headers: { "Content-Type": "application/json" },
    });
    expect(accept.status()).toBe(202);

    const accepted = await accept.json();
    expect(accepted).toMatchObject({ status: "accepted" });
    expect(typeof accepted.capture).toBe("string");
    // Eval mode also hands back the reveal URL for tests / smoke flows.
    expect(typeof accepted.debug_reveal_url).toBe("string");
    expect(accepted.debug_reveal_url).toMatch(/\/reveal\/[A-Za-z0-9_-]+$/);

    // The eval-only mail capture endpoint MUST surface the new entry.
    const mailbox = await request.get("/__captured_mail");
    expect(mailbox.status()).toBe(200);
    const { items } = (await mailbox.json()) as {
      items: Array<{ to: string; subject: string }>;
    };
    expect(items.some((m) => m.to === email)).toBe(true);
  });

  test("end-to-end reveal: token → reveal page → JS generates proposals", async ({
    page,
    request,
  }) => {
    // 1. Request a fresh token via the public API.
    const email = `reveal+${Date.now()}@example.test`;
    const accept = await request.post("/api/v1/request", {
      data: { email },
      headers: { "Content-Type": "application/json" },
    });
    expect(accept.status()).toBe(202);
    const { debug_reveal_url: revealURL } = (await accept.json()) as {
      debug_reveal_url: string;
    };

    // 2. Open the reveal page; it must show the "Décoder" CTA.
    await page.goto(revealURL);
    const decode = page.getByRole("button", { name: /Décoder/i });
    await expect(decode).toBeVisible();

    // 3. Clicking "Décoder" consumes the token via POST /api/v1/policy
    //    (token in the JSON body, never the URL) and runs
    //    window.SealKeeper.Generation.generate() in the page.
    const consumed = page.waitForRequest(
      (req) => req.url().endsWith("/api/v1/policy") && req.method() === "POST",
    );
    await decode.click();
    const consumeReq = await consumed;
    expect(consumeReq.url()).not.toContain("token=");
    expect(consumeReq.postDataJSON()).toEqual({
      token: revealURL.split("/").pop(),
    });

    // 4. Wait for the proposals to render. We expect at least 1 card with a
    //    visible password and an ANSSI badge.
    const firstProposal = page.locator('[data-testid="proposal"]').first();
    await expect(firstProposal).toBeVisible({ timeout: 5_000 });
    await expect(
      firstProposal.locator('[data-testid="password"]').first(),
    ).toContainText(/.+/);
    await expect(
      firstProposal.locator('[data-testid="anssi"]').first(),
    ).toContainText(/B[123]/);
  });

  // Regression: the reveal page used to discard the resolved admin policy
  // and always generate 5 default G2 proposals. The policy response is
  // stubbed so the test needs no admin login / policy setup.
  test("reveal page honours the resolved admin policy", async ({
    page,
    request,
  }) => {
    const revealURL = await stubbedRevealURL(request);

    await page.route("**/api/v1/policy", (route) => {
      expect(route.request().method()).toBe("POST");
      expect(route.request().url()).not.toContain("token=");
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          policy: {
            generator: "G3",
            proposalCount: 2,
            anssiLevel: "B3",
            parameters: { length: 32, blockSize: 8, blockSeparator: "." },
          },
        }),
      });
    });

    await page.goto(revealURL);
    await page.getByRole("button", { name: /Décoder/i }).click();

    const passwords = page.locator('[data-testid="password"]');
    await expect(passwords).toHaveCount(2, { timeout: 5_000 });
    for (const text of await passwords.allTextContents()) {
      expect(text).toMatch(/^[A-Za-z0-9]{8}(\.[A-Za-z0-9]{8}){3}$/);
    }
    await expect(page.locator('[data-testid="anssi"]').first()).toContainText(
      "B3",
    );
  });

  // FR-B.27..29: the reveal page used to ignore sessionTTLSec and
  // regenerateLimit — proposals stayed on screen forever and there was no
  // way to regenerate. Time is faked so the TTL elapses instantly.
  test("reveal session: countdown, bounded regeneration, expiry", async ({
    page,
    request,
  }) => {
    const revealURL = await stubbedRevealURL(request);
    await page.clock.install();
    await stubPolicy(page, { regenerateLimit: 1, sessionTTLSec: 180 });
    await page.goto(revealURL);
    await page.getByRole("button", { name: /Décoder/i }).click();

    const passwords = page.locator('[data-testid="password"]');
    await expect(passwords).toHaveCount(2);
    const countdown = page.getByTestId("countdown");
    await expect(countdown).toContainText("3 min");

    const first = await passwords.allTextContents();
    const regen = page.getByRole("button", { name: /Nouvelles propositions/i });
    await regen.click();
    await expect
      .poll(async () => (await passwords.allTextContents()).join())
      .not.toBe(first.join());
    await expect(regen).toBeDisabled(); // limit of 1 reached

    await page.clock.fastForward(61_000);
    await expect(countdown).toContainText("2 min");
    await page.clock.fastForward(60_000);
    await expect(countdown).toContainText("moins d'une minute");
    await page.clock.fastForward(60_000);
    await expect(page.getByTestId("expired")).toBeVisible();
    await expect(passwords).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Copier/i })).toHaveCount(0);
    await expect(regen).toBeHidden();
  });

  // FR-B.32: the purge used to overwrite the clipboard unconditionally,
  // wiping whatever the user had copied since.
  test("clipboard purge clears only our own value", async ({
    page,
    context,
    request,
    browserName,
  }) => {
    test.skip(
      browserName !== "chromium",
      "clipboard permissions are Chromium-only",
    );
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const revealURL = await stubbedRevealURL(request);
    await page.clock.install();
    await stubPolicy(page, {});
    await page.goto(revealURL);
    await page.getByRole("button", { name: /Décoder/i }).click();
    const password = await page
      .locator('[data-testid="password"]')
      .first()
      .textContent();
    const readClipboard = () =>
      page.evaluate(() => navigator.clipboard.readText());

    await page
      .getByRole("button", { name: /Copier/i })
      .first()
      .click();
    await expect.poll(readClipboard).toBe(password);
    await page.clock.fastForward(30_000);
    await expect.poll(readClipboard).toBe("");

    await page
      .getByRole("button", { name: /Copier/i })
      .first()
      .click();
    await expect.poll(readClipboard).toBe(password);
    await page.evaluate(() => navigator.clipboard.writeText("not ours"));
    await page.clock.fastForward(30_000);
    await page.clock.runFor(1_000);
    expect(await readClipboard()).toBe("not ours");
  });

  // Leaving the page (or a bfcache snapshot) must not keep the secrets.
  test("pagehide purges the proposals and the clipboard", async ({
    page,
    context,
    request,
    browserName,
  }) => {
    test.skip(
      browserName !== "chromium",
      "clipboard permissions are Chromium-only",
    );
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const revealURL = await stubbedRevealURL(request);
    await stubPolicy(page, {});
    const res = await page.goto(revealURL);
    expect(res?.headers()["cache-control"]).toBe("no-store");
    await page.getByRole("button", { name: /Décoder/i }).click();
    const password = page.locator('[data-testid="password"]').first();
    await expect(password).toHaveAttribute("translate", "no");
    await page
      .getByRole("button", { name: /Copier/i })
      .first()
      .click();
    await expect
      .poll(() => page.evaluate(() => navigator.clipboard.readText()))
      .toBe(await password.textContent());

    await page.evaluate(() =>
      window.dispatchEvent(
        new PageTransitionEvent("pagehide", { persisted: true }),
      ),
    );
    await expect(page.locator('[data-testid="password"]')).toHaveCount(0);
    await expect
      .poll(() => page.evaluate(() => navigator.clipboard.readText()))
      .toBe("");
  });

  test("@happy-path token is single-use (second consumption returns 410)", async ({
    request,
  }) => {
    const accept = await request.post("/api/v1/request", {
      data: { email: `single+${Date.now()}@example.test` },
      headers: { "Content-Type": "application/json" },
    });
    const { debug_reveal_url: url } = (await accept.json()) as {
      debug_reveal_url: string;
    };
    const token = url.split("/").pop()!;

    // A token in the URL ends up in access logs: it is refused and NOT
    // consumed (the POST below still succeeds).
    const inQuery = await request.get(`/api/v1/policy?token=${token}`);
    expect(inQuery.status()).toBe(400);
    expect((await inQuery.json()).title).toBe("token_in_query");

    const consume = () =>
      request.post("/api/v1/policy", {
        data: { token },
        headers: { "Content-Type": "application/json" },
      });
    const first = await consume();
    expect(first.status()).toBe(200);

    const second = await consume();
    expect(second.status()).toBe(410);
    expect(second.headers()["content-type"]).toMatch(
      /application\/problem\+json/,
    );
    const body = await second.json();
    expect(body.title).toBe("token_consumed");
  });

  test("rate-limited request stays silent (FR-B.13)", async ({ request }) => {
    // Saturate the per-email bucket. SK_RATE_LIMIT_EMAIL_PER_HOUR defaults
    // to 3, so the 4th request from the same address MUST be rate-limited.
    const email = `flood+${Date.now()}@example.test`;
    const bodies: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 4; i++) {
      const r = await request.post("/api/v1/request", {
        data: { email },
        headers: { "Content-Type": "application/json" },
      });
      expect(r.status()).toBe(202);
      bodies.push((await r.json()) as Record<string, unknown>);
    }

    // First 3 expose a debug_reveal_url in eval mode; the 4th must not —
    // that's how we detect the silent drop without a leaking error code.
    const issued = bodies.filter((b) => typeof b.debug_reveal_url === "string");
    const dropped = bodies.filter((b) => b.debug_reveal_url === undefined);
    expect(issued.length).toBe(3);
    expect(dropped.length).toBe(1);
    // FR-B.13: the body shape is identical (status: accepted) regardless.
    for (const b of bodies) {
      expect(b.status).toBe("accepted");
    }
  });

  test("readiness and liveness endpoints behave per FR-D.49 / FR-D.50", async ({
    request,
  }) => {
    const live = await request.get("/healthz");
    expect(live.status()).toBe(200);
    expect((await live.json()).status).toBe("ok");

    const ready = await request.get("/readyz");
    expect(ready.status()).toBe(200);
    const readyBody = await ready.json();
    expect(readyBody.status).toBe("ok");
    expect(readyBody.subsystems).toBeDefined();
  });
});
