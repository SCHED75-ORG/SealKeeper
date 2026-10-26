// =============================================================================
// SealKeeper — reveal-page session helpers
// =============================================================================
// PRD B §3.5–3.6 (FR-B.27..32). DOM-free so the timing and clipboard rules
// are unit-tested; the reveal page (internal/httpserver/server.go) only
// wires them to its elements.
//
// What the server can and cannot enforce. Generation is client-side by
// design (the server never sees a password), so once GET /api/v1/policy has
// consumed the token there is no further server round trip to gate:
//   - the session TTL (FR-B.29) and the regeneration bound (FR-B.27) are
//     enforced here, in the page. Anyone holding the policy and the public
//     bundle can generate as many proposals as they like — that is
//     equivalent to running the generator locally and grants no access;
//   - what the server does enforce is the single use of the link (atomic
//     consume, FR-B.36/37) and its audit trail (FR-B.38).
// =============================================================================

export const DEFAULT_SESSION_TTL_SEC = 900;
export const MIN_SESSION_TTL_SEC = 60;
export const MAX_SESSION_TTL_SEC = 86400;
export const CLIPBOARD_PURGE_MS = 30000;

/**
 * The session lifetime carried by the resolved policy (`sessionTTLSec`),
 * clamped to the bounds the admin form accepts. Missing or malformed
 * (the built-in default policy has none) means 15 minutes.
 * @param {object} policy
 * @returns {number} seconds
 */
export function sessionTTLSec(policy) {
  const v = policy && policy.sessionTTLSec;
  if (!Number.isInteger(v) || v <= 0) return DEFAULT_SESSION_TTL_SEC;
  return Math.min(MAX_SESSION_TTL_SEC, Math.max(MIN_SESSION_TTL_SEC, v));
}

/**
 * FR-B.28: whole minutes only, rounded up (a fresh 15-minute session reads
 * "15 min"); under the last minute "moins d'une minute".
 * @param {number} ms remaining
 * @returns {string}
 */
export function remainingLabel(ms) {
  if (ms <= 0) return "Session expirée";
  if (ms < 60000) return "moins d'une minute";
  return `${Math.ceil(ms / 60000)} min`;
}

const monotonicNow = () => performance.now();

/**
 * A reveal session that starts now and lasts ttlSec. `now` defaults to the
 * monotonic clock so changing the system time does not extend it.
 * @param {{ttlSec:number, now?:() => number}} opts
 */
export function createRevealSession({ ttlSec, now = monotonicNow }) {
  const deadline = now() + ttlSec * 1000;
  return {
    remainingMs: () => Math.max(0, deadline - now()),
    expired: () => now() >= deadline,
    label: () => remainingLabel(deadline - now()),
  };
}

/**
 * FR-B.30/32 clipboard hygiene. copy() writes the value and schedules a
 * purge delayMs later. A purge:
 *   - leaves the clipboard alone when it can tell the user has copied
 *     something else since. Reading needs the clipboard-read permission:
 *     it is used only when already granted, never prompted for. When the
 *     clipboard cannot be read, the purge clears it anyway (the PRD makes
 *     the purge a MUST);
 *   - stays pending when the write fails (Chromium refuses clipboard
 *     writes while the document is unfocused — typically while the user
 *     pastes in another window); resume() retries it when the page
 *     regains focus or visibility.
 * @param {{clipboard:object, permissions?:object, delayMs?:number,
 *          setTimer?:Function, clearTimer?:Function}} opts
 */
export function createClipboardGuard({
  clipboard,
  permissions,
  delayMs = CLIPBOARD_PURGE_MS,
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (id) => clearTimeout(id),
}) {
  let held = null; // the value we wrote and have not purged yet
  let timer = null;
  let due = false;

  function cancelTimer() {
    if (timer !== null) {
      clearTimer(timer);
      timer = null;
    }
  }

  async function stillOurs(value) {
    if (!permissions || typeof clipboard.readText !== "function") return true;
    try {
      const status = await permissions.query({ name: "clipboard-read" });
      if (status.state !== "granted") return true;
      return (await clipboard.readText()) === value;
    } catch {
      return true;
    }
  }

  async function purge() {
    cancelTimer();
    const value = held;
    if (value === null) return true;
    due = true;
    const ours = await stillOurs(value);
    if (held !== value) return true; // a newer copy took over meanwhile
    if (ours) {
      try {
        await clipboard.writeText("");
      } catch {
        return false; // still pending: resume() retries
      }
    }
    if (held === value) {
      held = null;
      due = false;
    }
    return true;
  }

  async function copy(text) {
    await clipboard.writeText(text);
    cancelTimer();
    held = text;
    due = false;
    timer = setTimer(() => {
      timer = null;
      void purge();
    }, delayMs);
  }

  return {
    copy,
    purge,
    /** Retries a purge that came due but could not be written. */
    resume: () => (due ? purge() : Promise.resolve(true)),
    get pending() {
      return held !== null;
    },
  };
}

const Reveal = {
  sessionTTLSec,
  remainingLabel,
  createRevealSession,
  createClipboardGuard,
};

export default Reveal;
