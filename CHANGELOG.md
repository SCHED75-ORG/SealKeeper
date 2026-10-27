# Changelog

All notable changes to SealKeeper are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-27

First public release. Nothing was released before this version, so every
security issue below affects all earlier commits and none affects a published
release.

### Security

Externally reported (thank you, see Acknowledgements):

- **Admin TOTP lockout bypass** (medium). The failed-attempt counter was cleared
  as soon as the password matched, before the TOTP check, and a blank code also
  reset it, so an attacker holding an operator password could brute-force the
  second factor without ever reaching the lockout. The counter is now cleared
  only once every factor has passed. GHSA-xr59-fxvh-vx8h. Fixed in `90b963d`.
  Reported by Sri Charan Pedhiti (@Char0n1507).
- **Reveal flow ignored the configured generation policy** (medium). The reveal
  page replaced the policy served by `/api/v1/policy` with a hard-coded G2
  descriptor (5 proposals, empty parameters), so operators' generator, length,
  library and count were ignored and the strength badge misreported the
  output. The page now passes the resolved policy through
  `Generation.descriptorFromPolicy`. GHSA-h3vw-xg58-625j. Fixed in `019173b`.
  Reported by Sri Charan Pedhiti (@Char0n1507).

Found by the internal security audit — high:

- **Silent generation downgrade** (SK-01). The bundle fell back to its public
  32-citation / 256-word sample whenever a G1/G2 policy had no inline library
  (a 64.6-bit passphrase was badged 94.2 bits B2), and the server served the
  weak built-in default on any policy-resolution error after the token was
  already burned. The policy is now resolved before consumption (503
  `policy_unavailable`, link kept), the default applies only with zero policy
  rows, errors fail closed, the bundle throws `LibraryNotFound`, and such
  policies are refused at save time. GHSA-5v4q-f2wv-2j8r. `46233e0`, `5377c45`, `7e1e3f4`.
- **Admin CSRF not bound to the session** (SK-02). A cookie planted from a
  sibling subdomain, or an absent cookie with an empty field, passed the
  check; logout had no CSRF check. The token is now an HMAC of the session
  token checked against the session, and cross-origin admin POSTs are refused
  via Sec-Fetch-Site / Origin. GHSA-hpmf-8vgp-wrg9. `0e6ee82`.
- **Admin lockout bypass under concurrency, no login rate limit** (SK-03).
  Concurrent bursts were all evaluated (57 passwords / 87 TOTP codes per
  5-attempt window). Each attempt is now reserved atomically before
  verification and `POST /admin/login` is limited per IP. GHSA-px6x-c425-97ff.
  `43f43cf`.
- **Stolen admin session became a permanent takeover** (SK-04). Password,
  e-mail and WebAuthn changes, and adding, disabling or deleting admins,
  needed no re-authentication; sessions survived a password change and revived
  after re-enabling an admin. All of these now require the current password
  (failures count toward lockout), credential changes revoke other sessions
  and disabling revokes them. GHSA-fmh4-vr55-g9fr. `0e6ee82`, PR #10 (`b7ecba4`).
- **Unauthenticated resource exhaustion on `POST /api/v1/request`** (SK-05).
  No body or e-mail bound, and the limiter janitor never ran. Body capped at
  4 KiB, e-mail limited to a bare addr-spec of at most 254 bytes, janitors
  started. GHSA-86vc-chc4-7r74. `ae2e1eb`, `43f43cf`.
- **Placeholder or weak `SK_MASTER_SECRET` accepted** (SK-06). The shipped
  `REPLACE_ME_WITH_BASE64_32_BYTES` was deployed by the default kustomization
  and accepted as the key protecting TOTP seeds, recovery codes and the relay
  password. Production now refuses placeholders and weak secrets; the
  Kubernetes, Helm and Compose paths no longer ship a usable value.
  GHSA-97gr-76c9-rx47. `db90236`, `e1b8896`.
- **SMTP STARTTLS downgrade** (SK-07). TLS mode `auto` continued in plaintext
  and AUTH LOGIN sent relay credentials without TLS. `auto` now requires
  STARTTLS except to a loopback relay and credentials are never sent in clear
  to a remote host. GHSA-hmx6-m9c4-v7w8. `e2355aa`.

Medium:

- **`X-Forwarded-For` trusted from any peer**, bypassing the per-IP limit and
  poisoning audit IPs; now honoured only from `SK_TRUSTED_PROXY_CIDRS`, walked
  right to left (`middleware.RealIP` removed). GHSA-3phm-q9w8-w262. `92f0cec`.
- **Prometheus label cardinality DoS** from unmatched paths (SK-08): now
  `route="unmatched"`. GHSA-p349-rfmg-pj77. `9868e6d`.
- **E-mail quota charged when the IP limit rejected** (SK-09), letting one IP
  block distribution for any mailbox. GHSA-m8vj-vxwx-q5pp. `43f43cf`.
- **Requester e-mail not canonicalised** (SK-10): CR/LF header injection into
  the reveal mail through an RFC 5322 comment (CWE-93), B3-to-B1 downgrade via
  quoted or `+tag` spellings, and per-address quota bypass.
  GHSA-m63x-mw9x-22hg. `ae2e1eb`, `43f43cf`, `46233e0`.
- **Raw reveal tokens in the audit log and SIEM events** (SK-11); now a
  pseudonymous `tokenRef`. Malformed integration filters no longer forward
  everything. GHSA-3c33-c5x6-76m8. `9868e6d`, `9d4fc51`.
- **Admin session and CSRF tokens stored in clear** (SK-12); only SHA-256
  digests are stored. GHSA-r2f4-3j9j-qh9v. `0e6ee82`.
- **TOTP codes replayable within their window** (SK-13); codes are now single
  use (migration 0013). GHSA-25wj-ggq7-fjcq. `dfecd64`.
- **Stored XSS via SVG logo; no CSP** (SK-14). Nonce-based CSP and security
  headers on every response; the logo is served in a CSP sandbox.
  GHSA-w8r4-7xjv-r69x. `483809f`.
- **Entropy calculator credited parameters the generators ignore** (SK-15),
  producing false B2/B3 badges. GHSA-vp6x-r6wr-629p. `9cc1763`, `72c1e3c`.
- **Elevations bound to a domain row** (SK-16): routine allowlist edits
  silently downgraded B3 users to B1. GHSA-32m2-xv47-r69q. `46233e0`.
- **Audit chain integrity** (SK-17b): unkeyed SHA-256 chain, undetectable tail
  truncation, ambiguous canonical form, green badge when verification could
  not run, and (after the first fix) re-blessing of a downgraded anchor at
  boot. Now HMAC-SHA256 with a sealed `audit_head` anchor (migration 0014).
  GHSA-2g8r-x99g-vmj2. `411b7a9`, `abe1725`, PR #10 (`b7ecba4`),
  PR #10 (`b7ecba4`).
- **New admin's initial password in the redirect URL** (SK-18).
  GHSA-wm34-5rq8-58h6. `0e6ee82`.
- **SIEM dispatcher head-of-line blocking and drop-on-full** (SK-19) let
  unauthenticated traffic evict security events. GHSA-w2gp-x88w-x6pw. `9d4fc51`.
- **Weak operator password policy** (SK-20): `Sealkeeper2026!!` passed as
  "B3". GHSA-8rm6-7x7f-jm6x. `aa5e515`.
- **Release pipeline could sign an unverified commit under a verified tag**,
  with script injection from `inputs.tag` (SK-21). GHSA-8465-qjjj-4vpx.
  `8036827`.
- **Public request endpoint accepted cross-origin simple requests** (any site
  could mint links from its visitors' IPs). GHSA-6rhf-gv3h-xqh8.
  PR #10 (`b7ecba4`).
- **Reveal tokens in reverse-proxy and ingress logs**: tokens were consumed
  via `GET ?token=` and every shipped proxy logged full URIs (access, error
  and redirect logs). GHSA-3h85-6cm8-97wc. PR #10 (`b7ecba4`).
- **WebAuthn ceremony state trusted from an unauthenticated cookie**: a forged
  enrolment blob bypassed the step-up and login challenges could be replayed.
  GHSA-g2wq-f4hr-pgq8. PR #10 (`b7ecba4`).

Low:

- SSRF from admin-configured SIEM sinks, including NAT64/6to4 forms (SK-22).
  GHSA-866c-h62v-23vj. `9d4fc51`, `b256e07`, PR #10 (`b7ecba4`).
- Stored SMTP password reusable towards a new host; integration credentials in
  clear (SK-23). GHSA-42xc-wqrj-x6jw. `742dcf0`, `9d4fc51`.
- Public demo: unblocked mutations, incomplete 24 h reset (including orphaned
  library files), `/__captured_mail` exposed (SK-24). GHSA-3qgw-4775-jrg4.
  `536b498`, `309d95d`, `b56522b`, PR #10 (`b7ecba4`).
- Setup wizard trusted client-supplied TOTP secret and recovery codes;
  recovery codes never accepted (SK-25). GHSA-5q5q-j4jc-34mr. `dfecd64`.
- Last-active-admin race (SK-26). GHSA-5gfq-xj7x-88cc. `9bb048f`, `fdd1aa7`.
- WebAuthn clone warning ignored (SK-27). GHSA-xwx2-mwv9-2jr5. `083fe26`.
- Timing oracle on `POST /api/v1/request` (SK-28). GHSA-ffw3-c5hm-6q93.
  `c88392a`.
- Reversible IP / User-Agent pseudonyms (SK-29). GHSA-pwvq-96q8-4rcw.
  `9868e6d`, `92f0cec`.
- Content spoofing via `/admin/login?err=` (SK-30). GHSA-5rx4-9rmj-6878.
  `483809f`.
- `/static/` directory listing and dotfiles (SK-31). GHSA-vf5g-3cjg-7rr3.
  `483809f`.
- `/readyz` leaked database error strings (SK-32). GHSA-hx7r-6phj-43vv.
  `9868e6d`.
- `/metrics` token compared case-insensitively, non-constant-time (SK-33).
  GHSA-8jv3-mq77-2578. `9868e6d`.
- Security knobs silently ignored; lax config parsing (SK-34).
  GHSA-g2gh-w36m-q6x3. `67a816b`.
- Trusted-proxy defaults collapsing clients or allowing XFF forgery (SK-35).
  GHSA-wf5w-rpwc-frqw. `d441e69`.
- Example proxies cached the generation bundle as immutable for a year
  (SK-36). GHSA-j6f2-83v8-665c. `60ec4b7`.
- Admin e-mail enumeration on login: bcrypt timing (invalid dummy hash) and the
  `locked` / `disabled` slugs. GHSA-p45x-p5mr-xxr7. `a9dcc70`, PR #10 (`b7ecba4`).
- Policies the bundle refuses could be saved, burning each user's link at
  reveal time. GHSA-82m5-xfqw-hcvp. PR #10 (`b7ecba4`).
- Per-IP limits keyed on the full IPv6 /128; reveal mails dropped when all
  workers were busy. GHSA-89cf-cwxq-vjvw. PR #10 (`b7ecba4`).
- Mail templates could exfiltrate live tokens or load remote content
  (including a `<noscript>`/`<xmp>` bypass of the first check).
  GHSA-pc67-5xxc-chq7. PR #10 (`b7ecba4`).
- Policy, template and branding audit events too thin to detect a weakening.
  GHSA-vrm4-6c5q-77jx. PR #10 (`b7ecba4`).
- Requester chose the mail language of the target mailbox.
  GHSA-rgjx-mpp6-wghx. PR #10 (`b7ecba4`).
- No server-side ANSSI entropy floor at policy save.
  GHSA-3453-4w25-4gmq. PR #10 (`b7ecba4`).
- CLI `admin reset-password`, `migrate up` and the bootstrap admin were not
  audited. GHSA-62vc-7grw-9c7x. PR #10 (`b7ecba4`).
- Client-supplied `domain` stored and sent to audit/SIEM.
  GHSA-8v8g-8jg7-963p. PR #10 (`b7ecba4`).
- Unthrottled reveal-token state oracle. GHSA-rcc6-8w43-37fh.
  PR #10 (`b7ecba4`).
- Build version printed on public pages. GHSA-4j8f-xvvv-p424.
  PR #10 (`b7ecba4`).
- Reveal page never expired its session; clipboard purge clobbered the
  user's clipboard; passwords left in DOM/bfcache.
  GHSA-qpvw-mq4c-w5h9. PR #10 (`b7ecba4`).
- Post-consultation alert lost at shutdown and unusable by the recipient.
  GHSA-98r6-6cwc-rv73. PR #10 (`b7ecba4`).
- Data race when the SMTP sender is replaced at runtime.
  GHSA-wm8r-gpgj-qv4p. PR #10 (`b7ecba4`).
- WebAuthn accepted authenticators without user verification.
  GHSA-hpv3-rxf7-74qc. PR #10 (`b7ecba4`).
- SIEM HTTP sinks accepted plain `http://` outside eval; Splunk `insecure_tls`
  silently ignored. GHSA-2v22-477j-mw89. PR #10 (`b7ecba4`).
- SMTP test echoed remote replies into the UI and audit.
  GHSA-4p54-82x8-qc75. PR #10 (`b7ecba4`).

Hardening without an advisory:

- `cmd/healthcheck` accepts only loopback targets and never follows redirects
  or proxies. PR #10 (`b7ecba4`).
- The weekly govulncheck scanned Go 1.25 and parsed a JSON exit code that is
  always 0; it now scans the shipped Go, pinned govulncheck v1.9.0, and counts
  findings from the report. PR #10 (`b7ecba4`).
- Prebuilt, unsigned `sealkeeper-linux-*` binaries removed from the repository.
  PR #10 (`b7ecba4`).

Found by the internal security audit, round 3 (PR #11, `5b2a849`). Same scope: every
commit up to `b7ecba4`, no published release affected.

- **Default deployments pulled the image from a namespace the project does
  not own** (critical). Compose, Helm, K8s, the Makefile, the docs and the
  site referenced `ghcr.io/sealkeeper/sealkeeper`, which belongs to an
  unrelated account, and the documented cosign identity named the wrong
  repository. Every reference now names `ghcr.io/sched75-org/sealkeeper` and
  `github.com/SCHED75-ORG/SealKeeper`. GHSA-gv35-8xj3-4w7m.
- **Release tagged images before its gates** (high). `:vX.Y.Z`, `:X.Y.Z` and
  `:latest` (prereleases included) were pushed before Trivy, the bundle
  assertion and the smoke tests. The image is now pushed by digest, every
  gate runs on that digest, and tags are added last (`:latest` only for a
  final release). GHSA-6h3j-677p-cjq6.
- **Empty allowlist admitted every address in production** (medium): a fresh
  instance mailed reveal links through its relay to anyone. It now fails
  closed outside eval/demo. GHSA-74w4-qw6w-8cj8.
- **Reveal tokens stored in clear in the database** (medium): only a SHA-256
  digest is kept (migration 0016). GHSA-jf5m-g56g-q723.
- **Entropy floor bypass through separators inside library entries**
  (medium): such entries are no longer credited, in Go and JS alike.
  GHSA-4gff-f8vh-ggh9.
- **Throttled public requests each appended an audit row** (medium): later
  hits are folded into 5-minute `request.rate_limited.summary` rows.
  GHSA-582g-j2qg-7746.
- **Unbounded e-mail field on unauthenticated admin login** (medium), stored
  in the audit log and the redirect: bodies are capped and the e-mail limited
  to 254 bytes. GHSA-qg24-8c5q-262m.
- **Anonymous login failures could drop admin events bound for the SIEM**
  (medium): they now use their own dispatcher lane.
  GHSA-5gmc-44fp-6rp7.
- **Mail-template CSS filter bypassed with comment markers in strings**
  (medium): CSS comments are refused. GHSA-959w-9vrf-c76c.
- **SMTP transactions ignored their timeout after dial** (medium): a stalled
  relay could pin every mail worker. GHSA-w8hc-m48m-33gh.
- Low: reveal-token lookup limiter keyed per IPv6 /128
  (GHSA-ww6h-ww3m-9hv6); sink transport errors exposed the
  sealed sink URL (GHSA-xp6p-4xm5-9v67); clearing the SMTP override
  kept the old relay (GHSA-phvp-8rq2-gq3g); a blank TOTP code revealed
  whether the password was right (GHSA-9vcw-qv98-gwhw); a
  replayed audit anchor hid a truncated tail
  (GHSA-6q77-mqm2-hjmx); a large G1 corpus crashed the reveal
  bundle after consuming the token (GHSA-mh7r-5wxr-v7cq).

### Changed

- **Public API.** `POST /api/v1/request` requires `Content-Type:
  application/json` (415) and same-origin requests (403); the body is
  capped at 4 KiB and a malformed e-mail returns 400 `invalid_email`; the
  `domain` and `subject` fields are ignored (domain derived from the e-mail). Accepted requests are held to a 250 ms floor plus jitter and the
  mail is sent asynchronously (bounded queue of 1024).
- **Token consumption** moves to `POST /api/v1/policy` with a JSON body (1 KiB
  cap); `GET /api/v1/policy?token=` returns 400 `token_in_query` and does not
  consume. `GET /api/v1/policy` without a token still returns the default
  policy. E-mailed `/reveal/<token>` links are unchanged.
- An unresolvable policy, or one the bundle would refuse, answers 503
  `policy_unavailable` without consuming the token. Token lookups on
  `/reveal/{token}` and `/api/v1/policy` are limited to 60 per 15 minutes per
  IP (429 with `Retry-After`).
- **Policies.** G1/G2 require a non-empty inline `parameters.library` array;
  invalid or inconsistent parameters (size claims, `alphabetSize`,
  `proposal_count` > 50, unknown transforms, …) are refused at save time;
  saving requires the guaranteed entropy to meet the level's floor: B1 ≥ 50,
  B2 ≥ 80, B3 ≥ 100 bits (`err=below_floor`). The edit page shows
  the level read-only. Policies saved earlier are not re-checked.
- **Entropy reporting** credits only what the generators draw and rounds down
  to 0.1 bit (the 7776 × 6 G2 baseline reads 94.1); the zero-config default
  is badged from the real sample size (64.6 bits, B1).
- **Admin step-up.** Changing e-mail or password, enrolling or deleting a
  security key, and adding, enabling/disabling or deleting an admin require the
  current password [admin actions: PR #10]. Password and e-mail changes sign
  out every other session; disabling an admin revokes its sessions.
- **Operator passwords** must reach an estimated 100 bits of guessing entropy
  (zxcvbn-style estimator; only the first 72 bytes count). Existing passwords
  keep working until changed.
- **Login.** `POST /admin/login` is limited to 20 attempts per 15 minutes per
  IP (IPv6 keyed on the /64); the TOTP field also accepts a recovery
  code; a locked account shows `bad_creds`, and `disabled` is reported only
  after a correct password. Admin POSTs flagged cross-origin by
  Sec-Fetch-Site / Origin are refused.
- **WebAuthn** requires user verification for enrolment and login, discourages
  resident keys and requests no attestation; ceremonies expire after 5 minutes
  server-side.
- **Public rate limiter.** The IP is checked first and a rejected request
  charges neither dimension; `+tag` sub-addresses share their address's quota;
  native IPv6 is keyed on its /64.
- **SMTP.** TLS mode `auto` requires STARTTLS except to a loopback relay;
  changing host, port, username, TLS mode or server name, or disabling
  certificate verification, requires re-entering the relay password; failed
  tests show a sanitised status (stage + SMTP code).
- **Mail.** Templates are checked against an element/attribute allowlist at
  save, preview and every render; `{{ .RevealURL }}` is allowed only as the
  whole `href` of an `<a>` or standalone in the text body, never in the
  subject. Mail language is the instance setting `SK_MAIL_LANGUAGE`
  (`en` default, `fr`), no longer the requester's `Accept-Language`.
  Header values refuse CR/LF and the Subject is Q-encoded. Each mail gets a
  random Message-ID.
- **Integrations.** Sinks may not reach loopback, link-local, metadata or
  (unless `SK_INTEGRATIONS_ALLOW_PRIVATE=true`) private addresses; redirects
  are errors; only the HTTP status is reported; the Sentinel workspace ID must
  be a GUID; HTTP sinks must use `https://` outside eval and Splunk
  `insecure_tls` is refused; credentials are sealed (migration 0015)
  and never rendered back; filters are decoded strictly.
- **Audit.** HMAC-SHA256 chain keyed from `SK_MASTER_SECRET` (HKDF) with a
  sealed `audit_head` anchor; pre-0014 rows keep verifying as SHA-256. Events
  carry `tokenRef` instead of the token and real `sequence_no` values.
  Policy, template and branding events carry the stored row, diffs and
  fingerprints, and `token.consumed` records `policy_id` / `policy_sha256`. IP / User-Agent pseudonyms are HMACs and change once on upgrade.
  The integrity badge shows "not verified" when verification cannot run.
- **HTTP.** Every response carries a nonce-based Content-Security-Policy,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy: no-referrer`,
  COOP, and HSTS when `SK_BASE_URL` is https. `/static/` refuses directories
  and dot-segments. `?err=` / `?ok=` render only known slugs. `/readyz`
  returns no error details. `/metrics` uses `route="unmatched"` for unmatched
  paths and compares its token in constant time. The build version is no
  longer shown on the landing and reveal pages (still on the dashboard and
  `/version`).
- **Reveal page** shows a countdown, ends the session at `sessionTTLSec`,
  offers "Nouvelles propositions (N)" bounded by `regenerateLimit`, purges only
  its own clipboard value, and empties the DOM on `pagehide`. The
  post-consultation mail quotes the IP and User-Agent (never stored).
- **`HEALTHCHECK_URL`** must target a loopback IP literal or `localhost`;
  redirects count as unhealthy.
- **Configuration.** Production refuses a placeholder or weak
  `SK_MASTER_SECRET` (must decode to 32 bytes, or be a passphrase of at least
  32 characters). Malformed integers, booleans and durations are startup
  errors naming the variable; `SK_CONFIG_FILE` rejects unknown keys.
  `SK_ADMIN_SESSION_TTL_SECONDS` / `SK_ADMIN_SESSION_IDLE_SECONDS` are now
  honoured (≥ 60 s, idle ≤ TTL). `SK_MAX_LIBRARY_SIZE_MB` caps library uploads
  (1–1024, default 10; the previous hard-coded cap was 32 MB).
  `SK_MAINTENANCE_MODE=true` is a startup error. Malformed
  `SK_TRUSTED_PROXY_CIDRS` entries are refused. `SK_MODE=demo` is refused with
  a pointer to `SK_DEMO_MODE=true`.
- **Demo mode** makes the admin console read-only outside the demo story
  (`err=demo_readonly`), restores accounts, branding, SMTP and kv on every
  24 h reset, deletes orphaned library files, and scopes captured mail
  to the requesting browser. `/__captured_mail` is never registered in
  production.
- **Storage.** SQLite now enforces foreign keys. Migrations: 0013
  (`admins.totp_last_step`), 0014 (`audit_head`), 0015
  (`integrations.config_enc`). Admin session tokens are stored hashed (no
  migration; existing sessions are invalidated).
- **Deployment.** Compose pins the backend subnet to `172.31.250.0/24` with
  Caddy at `172.31.250.10` (the only trusted proxy); Helm requires
  `secret.masterSecret` outside eval and defaults `config.trustedProxyCIDRs` to
  `""`; NetworkPolicy is enabled by default; `k8s/secret.example.yaml` is no
  longer applied by the kustomization; example proxies serve `/static/` with
  `Cache-Control: no-cache` and pass the server's security headers through;
  Caddy, nginx (`sealkeeper_json` log format), Traefik and the ingresses
  redact or skip reveal paths in their logs; Helm gains
  `ingress.revealPaths` (on by default); Traefik moves to v3.3.
- **Release.** Tag push is the only release trigger; every job builds the
  tag's commit; signing runs in the protected `release` environment; actions
  and tools are pinned. The image builds the JS bundle in a pinned Node stage
  and the release refuses to sign an image without it.

- **Round 3 (PR #11, `5b2a849`).** A disabled domain row is terminal: a broader active
  wildcard no longer admits its users, and links issued under it keep its
  policy until their TTL (FR-C.23). Template CSS may not contain comments.
  WebDir autodetection only accepts a directory that holds the bundle. The
  site self-hosts marked and mermaid (checked against `SHA256SUMS`), moves
  inline scripts to `site.js` and ships security headers in `_headers`.
  `SK_SWAGGER_UI_ENABLED` is a dead knob: it warns and is no longer shipped.
  Elevations accept an e-mail only under its own domain and on one list.

### Deprecated

- `SK_MAX_ACTIVE_SESSIONS` and `SK_SESSION_TTL_SECONDS` are not implemented
  (user session TTL is per policy); a non-default value logs a startup
  warning. They are removed from every shipped template.

### Removed

- chi `middleware.RealIP`.
- The `workflow_dispatch` trigger of `release.yml`.
- The stale committed `web-bundle/` copy of the generation bundle.
- Tracked prebuilt `sealkeeper-linux-*` binaries.
- The unused `Accept-Language` parser (`PickLanguage`).

### Added

- `sealkeeper admin enable --email <e>` to recover from a zero-active-admin
  state (audited as `admin.enabled`).
- Audit events `admin.recovery_code_used`, `admin.webauthn_clone_detected`,
  `admin.step_up_failed`, `integration.events_dropped`, and, for the CLI,
  `admin.password_reset`, `schema.migrated`, `admin.bootstrapped`.
- Metrics `sealkeeper_integrations_events_{delivered,failed,dropped}_total`
  and `sealkeeper_rate_limit_hits_total{dimension="token_lookup"}`.
- Configuration knobs `SK_INTEGRATIONS_ALLOW_PRIVATE` and `SK_MAIL_LANGUAGE`.
- `storage/storagetest.DSN`: the repository test suite replays on Postgres
  when `TEST_PG_DSN` is set; Playwright honours `SK_E2E_DATABASE_URL`.
- `@csp` Playwright spec (every admin page and the public flow, fails on any
  CSP violation), a `@happy-path` test of a non-default policy, and reveal
  session / token-in-body e2e assertions.
- `window.SealKeeper.Generation.descriptorFromPolicy`, the `LibraryNotFound`
  error, `Generation.regenerationsLeft` and `window.SealKeeper.Reveal`
  helpers.
- Go mirror of the bundle's policy rules (`policies.ValidateForReveal`,
  `internal/policies/entropy.go`) with node cross-check tests and shared
  `testdata/reveal_parity.json`.
- `docs/security/mail-authentication.md` (sender identity, SPF, DKIM, DMARC).

- Retention purge (RGPD FR-I.31/37, PR #11, `5b2a849`): `serve` deletes ended sessions,
  old request tokens, captured mail, long-disabled admins and audit rows past
  their period at boot and then daily, and audits `retention.purge_run`.
  Audit rows leave whole from the old end (`audit.Repo.Prune`) and the chain
  stays verifiable through a MAC-bound base (migration 0017). Knobs:
  `SK_RETENTION_REQUEST_TOKENS_DAYS` (30), `SK_RETENTION_SESSION_GRACE_HOURS`
  (24), `SK_RETENTION_AUDIT_DAYS` (365), `SK_RETENTION_CAPTURED_MAIL_DAYS`
  (7), `SK_RETENTION_DISABLED_ADMIN_DAYS` (90).
- Refused opening attempts of a reveal link are audited
  (`token.reuse_attempt`, `token.expired_attempt`, `token.unknown_attempt`,
  the last one rate-capped per client; FR-B.38).
- Standalone release binaries embed the JS bundle and its source map.
- Website: RFC 9116 `/.well-known/security.txt` with the security contact's
  public PGP key, and `wrangler.jsonc` to deploy `design/` from `main` with
  Cloudflare Workers Builds.

### Fixed

- Postgres backend never worked: placeholders were never rewritten
  (`f9474da`); BOOLEAN columns, `LastInsertId` and unique-violation detection
  (`46d7933`); the audit chain always reported "broken" (µs vs ns timestamps)
  and could fork under concurrent appends (`2d66ff1`); the `/admin/audit`
  page query (`401be3b`).
- SQLite did not enforce foreign keys, so deletes cascaded on Postgres only
  (`ec6a757`).
- WebAuthn `last_used_at` could not be scanned on SQLite, breaking every
  WebAuthn login after the first (`083fe26`).
- The signed release image shipped without the JS generation bundle
  (`/static/sealkeeper-generation.umd.js` returned 404), and the release
  smoke test could not start (PR #10, `b7ecba4`).
- Every mail carried the same Message-ID (PR #10, `b7ecba4`).
- A `-` among T08 symbols made the G1 entropy calculator and generation throw
  (PR #10, `b7ecba4`).
- `cryptoRandomInt` returned negative values for `max > 2^31` (`7a3ec2f`;
  latent, no exploitable path).
- The policy editor preview kept stale badges when the calculation failed
  (`72c1e3c`); the policy save handler now answers `err=not_found` for an
  unknown id (PR #10, `b7ecba4`).
- `reset-password` failed on about 0.3% of generated passwords (`aa5e515`).
- `audit.Append` returned `SequenceNo=0` (`411b7a9`); the demo `ResetOnce`
  swallowed errors (`309d95d`); the demo capture callback raced between
  requests (`b56522b`).
- The `admin enable` audit row used the pre-HMAC chain (`fdd1aa7`).
- CI: hadolint, gosec G101 and the e2e runner image (PR #10, `b7ecba4`).

- The default Compose stack could not start: uploaded libraries defaulted to
  the read-only `/app`, and `/data` was created root-owned. The image now sets
  `SK_LIBRARIES_DIR=/data/libraries` and ships `/data` owned by UID 65532.
  Caddy's healthcheck targeted `::1` and was always unhealthy (PR #11, `5b2a849`).
- A legacy audit log could stay flagged as broken for good when the run that
  applied migration 0014 never sealed it; the seal now happens inside that
  migration (PR #11, `5b2a849`).
- The step-up password check never cleared an expired lockout; links died
  as soon as their domain was disabled; an unknown `SK_SMTP_TLS` silently
  dropped every mail (now a startup error) (PR #11, `5b2a849`).

### Dependencies

- Go toolchain 1.26.3 → 1.26.10 (builder `golang:1.26.10-alpine3.23`; `go`
  directive 1.26.0; CI matrix 1.26.10 / 1.27.3): standard library fixes
  GO-2026-6599, GO-2026-6600 (html/template); GO-2026-6603, GO-2026-6610,
  GO-2026-6611, GO-2026-6612, GO-2026-6617 (HTTP/2); GO-2026-6605,
  GO-2026-6609, GO-2026-6613 (net/http); GO-2026-6607 (crypto/tls);
  GO-2026-6608 (net/textproto); GO-2026-6604 (os); GO-2026-6809
  (crypto/x509); plus the fixes of 1.26.4–1.26.9. `c00ad66`.
- `github.com/go-chi/chi/v5` v5.2.5 → v5.5.0 (`RealIP` spoofing:
  GO-2026-5774, GO-2026-5775, GO-2026-5777; SealKeeper also stopped using
  `RealIP`, see `92f0cec`). `c00ad66`.
- `golang.org/x/crypto` v0.51.0 → v0.58.0 (ssh advisories), `golang.org/x/text`
  v0.37.0 → v0.43.0 (GO-2026-5970, GO-2026-6629), `golang.org/x/net` v0.53.0 →
  v0.61.0, `golang.org/x/sys` v0.44.0 → v0.49.0, `golang.org/x/sync` v0.20.0 →
  v0.24.0. `c00ad66`. `golang.org/x/net` v0.61.0 becomes a direct dependency
  (PR #10, `b7ecba4`).
- `govulncheck ./...`: 0 affecting. GO-2026-5932 (deprecated
  `x/crypto/openpgp`, no fix) is informational and not imported.
- Web tooling (`npm audit fix`, `npm audit`: 0): vite 8.0.13 → 8.3.5, postcss
  8.5.14 → 8.5.31, nanoid 3.3.12 → 3.3.20, js-yaml 4.1.1 → 4.3.2,
  source-map-js 1.2.1 → 1.2.2, vitest and `@vitest/coverage-v8` 4.1.6 →
  4.1.12 (GHSA-82fw-gwwq-j7x9, GHSA-qxg6-89mg-rqv8). `c00ad66`.
- Image build: new `node:22.22.3-alpine3.22` stage pinned by digest
  (PR #10, `b7ecba4`); Traefik example v3.2 → v3.3 (PR #10, `b7ecba4`); trivy 0.58.0 → 0.75.0
  and syft pinned by SHA-256 (`8036827`); govulncheck pinned to v1.9.0
  (PR #10, `b7ecba4`).

### Upgrade notes

Operators running any pre-release build must:

1. **Pin `SK_MASTER_SECRET`** to a random 32-byte base64 value, identical
   across restarts and rebuilds. Production refuses placeholders and weak
   values. If you used a passphrase of at least 32 characters, keep it: your
   existing key derives from it. If the shipped placeholder was ever used,
   rotate the SMTP relay password and re-enrol every operator's TOTP after
   setting a real secret. The audit chain key also derives from this secret.
2. **Sign in again.** Admin sessions are stored hashed; every existing session
   is invalidated by the upgrade.
3. **Re-enter the SMTP password** when you change host, port, username, TLS
   mode or server name. In TLS mode `auto`, a non-loopback relay must offer
   STARTTLS. If you relayed through a remote server in `auto` mode, rotate its
   credential.
4. **Set trusted proxies.** Set `SK_TRUSTED_PROXY_CIDRS` to the exact address
   of your reverse proxy (Helm now trusts nobody by default; Compose trusts
   only `172.31.250.10/32` on the pinned `172.31.250.0/24` subnet, which may
   collide with an existing network). Make the edge proxy overwrite
   `X-Forwarded-For`.
5. **Review custom mail templates.** Templates that load remote images or
   stylesheets, use CSS `url()`, or place `{{ .RevealURL }}` anywhere other
   than a link `href` or a standalone text line are refused at save time, and
   stored rows that break the rules are refused at send time (the mail is not
   sent). Re-save or reset them. French deployments set `SK_MAIL_LANGUAGE=fr`.
6. **Review policies.** G1/G2 policies need an inline library; policies the
   reveal bundle would refuse now answer 503 at reveal time; new or updated
   policies must meet B1 ≥ 50 / B2 ≥ 80 / B3 ≥ 100 bits. Policies saved before
   this release are not re-checked: open each one in the editor. Ask users who
   received passwords from the built-in default, from a G1/G2 policy without
   an inline library, or through the pre-`019173b` reveal page to rotate them.
7. **Rotate weak operator passwords.** The new estimator applies only when a
   password is set.
8. **API clients**: send `Content-Type: application/json` to
   `/api/v1/request`, and consume tokens with `POST /api/v1/policy`.
9. **Integrations**: `http://` sinks stop working outside eval (switch to
   https); sinks on private addresses need
   `SK_INTEGRATIONS_ALLOW_PRIVATE=true`; Splunk `insecure_tls` is refused.
   Credentials are sealed at boot (migration 0015).
10. **Run migrations** (`sealkeeper migrate up`, or startup in eval) to apply
    0013–0015; the process that applies 0014 seals the audit anchor. Postgres
    operators: the red integrity badge before this release was a known false
    positive.
11. **Fix configuration** that now fails at startup: malformed numbers or
    booleans, unknown YAML keys, `SK_MAINTENANCE_MODE=true`, malformed
    `SK_TRUSTED_PROXY_CIDRS`, `SK_MODE=demo` (use `SK_DEMO_MODE=true`). Remove
    `SK_MAX_ACTIVE_SESSIONS` / `SK_SESSION_TTL_SECONDS`. Raise
    `SK_MAX_LIBRARY_SIZE_MB` if you upload libraries larger than 10 MB.
    `HEALTHCHECK_URL` must point at loopback.
12. **Proxies**: use Traefik v3.3 or later with the shipped labels; nginx
    users adopt the `sealkeeper_json` log format; purge existing proxy,
    ingress and SIEM logs and indices that contain `/reveal/<token>`,
    `?token=` or raw tokens in audit `target` fields.
13. **WebAuthn keys** without user verification (PIN or biometric) can no
    longer be enrolled or used.
14. **IP pseudonyms** in new audit rows change once (keyed HMAC); update any
    SIEM correlation that relied on the old values.

15. **Round 3 (PR #11, `5b2a849`)**: migrations 0016 and 0017 run at startup or with
    `migrate up`; reveal links issued before the upgrade stop working. In
    production an empty allowlist refuses every request, and a disabled
    domain refuses its users even under an active wildcard. Remove CSS
    comments from custom mail templates. Point images at
    `ghcr.io/sched75-org/sealkeeper` and cosign verification at the
    `SCHED75-ORG/SealKeeper` workflow identity. Review the retention periods
    (`SK_RETENTION_*`) against your own RGPD record.

### Acknowledgements

We thank **Sri Charan Pedhiti (@Char0n1507)** for responsibly disclosing
GHSA-xr59-fxvh-vx8h (admin TOTP lockout bypass) and GHSA-h3vw-xg58-625j
(reveal flow ignoring the configured policy) through GitHub private
vulnerability reporting, with clear analyses and working proofs of concept
that made both fixes straightforward to verify.

[0.1.0]: https://github.com/SCHED75-ORG/SealKeeper/releases/tag/v0.1.0
