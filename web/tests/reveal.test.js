import { describe, expect, it } from "vitest";
import Reveal, {
  CLIPBOARD_PURGE_MS,
  DEFAULT_SESSION_TTL_SEC,
  createClipboardGuard,
  createRevealSession,
  remainingLabel,
  sessionTTLSec,
} from "../src/reveal.js";
import Generation, { regenerate, regenerationsLeft } from "../src/index.js";

describe("sessionTTLSec", () => {
  it("uses the policy value, clamped to the admin bounds", () => {
    expect(sessionTTLSec({ sessionTTLSec: 600 })).toBe(600);
    expect(sessionTTLSec({ sessionTTLSec: 5 })).toBe(60);
    expect(sessionTTLSec({ sessionTTLSec: 10 ** 9 })).toBe(86400);
  });

  it("falls back to 15 minutes when absent or malformed", () => {
    for (const p of [
      null,
      {},
      { sessionTTLSec: "900" },
      { sessionTTLSec: 1.5 },
      { sessionTTLSec: -1 },
    ]) {
      expect(sessionTTLSec(p)).toBe(DEFAULT_SESSION_TTL_SEC);
    }
  });
});

describe("remainingLabel (FR-B.28)", () => {
  it("shows whole minutes only", () => {
    expect(remainingLabel(15 * 60000)).toBe("15 min");
    expect(remainingLabel(14 * 60000 + 1)).toBe("15 min");
    expect(remainingLabel(60001)).toBe("2 min");
    expect(remainingLabel(60000)).toBe("1 min");
  });

  it("switches to 'moins d'une minute' under the last minute, then expires", () => {
    expect(remainingLabel(59999)).toBe("moins d'une minute");
    expect(remainingLabel(1)).toBe("moins d'une minute");
    expect(remainingLabel(0)).toBe("Session expirée");
    expect(remainingLabel(-5)).toBe("Session expirée");
  });
});

describe("createRevealSession (FR-B.29)", () => {
  it("expires ttlSec after it starts", () => {
    let t = 1000;
    const s = createRevealSession({ ttlSec: 120, now: () => t });
    expect(s.expired()).toBe(false);
    expect(s.remainingMs()).toBe(120000);
    expect(s.label()).toBe("2 min");
    t += 60000;
    expect(s.label()).toBe("1 min");
    t += 59999;
    expect(s.expired()).toBe(false);
    expect(s.label()).toBe("moins d'une minute");
    t += 1;
    expect(s.expired()).toBe(true);
    expect(s.remainingMs()).toBe(0);
    expect(s.label()).toBe("Session expirée");
  });

  it("defaults to the monotonic clock", () => {
    const s = createRevealSession({ ttlSec: 60 });
    expect(s.expired()).toBe(false);
    expect(s.remainingMs()).toBeGreaterThan(59000);
  });
});

// fakeClipboard mimics navigator.clipboard; `focused` false makes writes
// fail the way Chromium does for an unfocused document.
function fakeClipboard(initial = "") {
  const c = {
    value: initial,
    focused: true,
    async writeText(v) {
      if (!c.focused)
        throw Object.assign(new Error("Document is not focused."), { name: "NotAllowedError" });
      c.value = v;
    },
    async readText() {
      return c.value;
    },
  };
  return c;
}

function fakeTimers() {
  const pending = new Map();
  let next = 1;
  return {
    setTimer: (fn, ms) => {
      pending.set(next, { fn, ms });
      return next++;
    },
    clearTimer: (id) => pending.delete(id),
    async fire() {
      const all = [...pending.values()];
      pending.clear();
      for (const t of all) t.fn();
      await new Promise((r) => setTimeout(r, 0));
    },
    get size() {
      return pending.size;
    },
    get delays() {
      return [...pending.values()].map((t) => t.ms);
    },
  };
}

const granted = { query: async () => ({ state: "granted" }) };
const denied = { query: async () => ({ state: "prompt" }) };

describe("createClipboardGuard (FR-B.32)", () => {
  it("purges our value 30 s after the copy", async () => {
    const clip = fakeClipboard();
    const timers = fakeTimers();
    const g = createClipboardGuard({ clipboard: clip, permissions: granted, ...timers });
    await g.copy("s3cret");
    expect(clip.value).toBe("s3cret");
    expect(g.pending).toBe(true);
    expect(timers.delays).toEqual([CLIPBOARD_PURGE_MS]);
    await timers.fire();
    expect(clip.value).toBe("");
    expect(g.pending).toBe(false);
  });

  it("leaves the clipboard alone when the user copied something else", async () => {
    const clip = fakeClipboard();
    const timers = fakeTimers();
    const g = createClipboardGuard({ clipboard: clip, permissions: granted, ...timers });
    await g.copy("s3cret");
    clip.value = "user's own text";
    await timers.fire();
    expect(clip.value).toBe("user's own text");
    expect(g.pending).toBe(false);
  });

  it("clears anyway when the clipboard cannot be read", async () => {
    for (const permissions of [
      denied,
      undefined,
      { query: async () => Promise.reject(new Error("x")) },
    ]) {
      const clip = fakeClipboard();
      const timers = fakeTimers();
      const g = createClipboardGuard({ clipboard: clip, permissions, ...timers });
      await g.copy("s3cret");
      clip.value = "other";
      await timers.fire();
      expect(clip.value).toBe("");
    }
    const noRead = { value: "", writeText: async (v) => (noRead.value = v) };
    const g = createClipboardGuard({ clipboard: noRead, permissions: granted });
    await g.copy("s3cret");
    expect(await g.purge()).toBe(true);
    expect(noRead.value).toBe("");
  });

  it("keeps an unwritable purge pending and retries it on resume", async () => {
    const clip = fakeClipboard();
    const timers = fakeTimers();
    const g = createClipboardGuard({ clipboard: clip, permissions: denied, ...timers });
    await g.copy("s3cret");
    clip.focused = false;
    await timers.fire();
    expect(clip.value).toBe("s3cret");
    expect(g.pending).toBe(true);
    clip.focused = true;
    expect(await g.resume()).toBe(true);
    expect(clip.value).toBe("");
    expect(g.pending).toBe(false);
  });

  it("resume does nothing before the purge is due", async () => {
    const clip = fakeClipboard();
    const timers = fakeTimers();
    const g = createClipboardGuard({ clipboard: clip, permissions: granted, ...timers });
    await g.copy("s3cret");
    expect(await g.resume()).toBe(true);
    expect(clip.value).toBe("s3cret");
  });

  it("an explicit purge (pagehide, expiry) clears at once and cancels the timer", async () => {
    const clip = fakeClipboard();
    const timers = fakeTimers();
    const g = createClipboardGuard({ clipboard: clip, permissions: granted, ...timers });
    expect(await g.purge()).toBe(true); // nothing copied yet
    await g.copy("s3cret");
    expect(await g.purge()).toBe(true);
    expect(clip.value).toBe("");
    expect(timers.size).toBe(0);
  });

  it("a new copy restarts the delay and is the value purged", async () => {
    const clip = fakeClipboard();
    const timers = fakeTimers();
    const g = createClipboardGuard({ clipboard: clip, permissions: granted, ...timers });
    await g.copy("first");
    await g.copy("second");
    expect(timers.size).toBe(1);
    await timers.fire();
    expect(clip.value).toBe("");
  });

  it("does not drop a copy made while a purge is in flight", async () => {
    const clip = fakeClipboard();
    let release;
    const slow = { query: () => new Promise((r) => (release = () => r({ state: "granted" }))) };
    const g = createClipboardGuard({ clipboard: clip, permissions: slow });
    await g.copy("first");
    const p = g.purge();
    await g.copy("second");
    release();
    expect(await p).toBe(true);
    expect(clip.value).toBe("second");
    expect(g.pending).toBe(true);
  });

  it("uses the real timers by default", async () => {
    const clip = fakeClipboard();
    const g = createClipboardGuard({ clipboard: clip, permissions: granted, delayMs: 1 });
    await g.copy("s3cret");
    await new Promise((r) => setTimeout(r, 20));
    expect(clip.value).toBe("");
  });
});

describe("namespace", () => {
  it("default export carries the helpers", () => {
    expect(Reveal.sessionTTLSec).toBe(sessionTTLSec);
    expect(Reveal.createClipboardGuard).toBe(createClipboardGuard);
    expect(Generation.regenerationsLeft).toBe(regenerationsLeft);
  });

  it("regenerationsLeft counts down with regenerate (FR-B.27)", async () => {
    const policy = { generator: "G3", proposalCount: 1, regenerateLimit: 2 };
    expect(regenerationsLeft(policy)).toBe(2);
    await regenerate(policy);
    expect(regenerationsLeft(policy)).toBe(1);
    await regenerate(policy);
    expect(regenerationsLeft(policy)).toBe(0);
    expect(regenerationsLeft({ generator: "G3", regenerateLimit: 0 })).toBe(0);
  });
});
