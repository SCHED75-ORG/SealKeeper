# SealKeeper — handover for Claude / other AI assistants

> **Purpose of this file.** Drop a Claude (claude.ai, Claude Code, or any other LLM agent) into the SealKeeper repository and have it productive in a single read. It covers what the project *is*, how the code is laid out, the conventions that hold across modules, the run modes, the testing strategy, and the pitfalls observed while building. The PRD modules under `docs/prd/` are the source of truth for *requirements*; this document is the source of truth for *implementation*.

State of the repo at the time of writing: **v0.1 in development**, single-binary deployment, Go 1.26.10 toolchain, all twelve PRD modules (A → L plus M for admin-accounts) drafted, multi-tenant deployment surface (Compose, Helm, K8s manifests) sketched. CI is green; the local Docker stack runs in eval mode out of the box.

---

## 1. What SealKeeper is — and is not

**SealKeeper is an ANSSI-compliant, ephemeral, single-use password *distributor*.** A user submits their email to a public form, the server mints a 256-bit opaque single-use token, sends the link by email, and when the recipient clicks the link the browser — **not the server** — generates a small number of password proposals using `crypto.getRandomValues()` over a policy descriptor served by the API. The token is consumed atomically on the policy fetch; a second visit returns `410 Gone`.

**Architecturally this means the server never sees a generated password.** No ciphertext is stored, no key is sent in a URL fragment, no zero-knowledge envelope. The earlier threat-model description that talked about "decryption key K travelling via URL fragment" was wrong and has been rewritten (`design/threat-model.html`).

SealKeeper is **not**:

* A password *manager* — it does not store credentials for the user, only mints one-shot proposals.
* A *secrets manager* like Vault — no application secrets, no key-value store, no policy engine for non-human callers.
* A *zero-knowledge* service — the server holds the policy + the JS bundle that drives generation; tampering with either yields predictable output.

It is opinionated about three things: **single-binary distribution**, **AGPL v3 source availability**, and **ANSSI B1/B2/B3 thresholds applied uniformly** (operator passwords clear B3 by policy — see Module M).

---

## 2. Repository layout

```
.
├── cmd/
│   ├── sealkeeper/             # main entry — serve | migrate | backup | admin | version
│   └── healthcheck/            # tiny Go probe baked into the distroless image
├── internal/
│   ├── admin/                  # account lifecycle, sessions, TOTP, password policy
│   ├── audit/                  # SHA-256 hash-chained audit log
│   ├── branding/               # single-row instance identity (name, colours, logo)
│   ├── config/                 # env + yaml config loader; IsEval / IsDemo
│   ├── cryptobox/              # AES-256-GCM Seal/Open with AAD discipline
│   ├── demo/                   # 24h data resetter (public demo mode)
│   ├── domains/                # allowlisted email domains (FQDN + wildcard)
│   ├── elevations/             # B2/B3 promotion lists per (domain, email)
│   ├── httpserver/             # HTTP router, public + admin handlers, templates
│   ├── integrations/           # outbound SIEM sinks + non-blocking dispatcher
│   ├── libraries/              # uploaded dictionaries / corpora (SHA-256 addressed)
│   ├── mail/                   # RFC 2822 multipart assembly (boundary from rand)
│   ├── mailcapture/            # in-memory mail store for eval + demo modes
│   ├── mailer/                 # Sender interface; Nop / Capture / SMTP impls
│   ├── mailtemplates/          # per-kind, per-language email defaults + DB overrides
│   ├── policies/               # B1/B2/B3 policy rows + Resolve(email) gate
│   ├── policy/                 # legacy PolicyDescriptor JSON for /api/v1/policy
│   ├── ratelimit/              # sliding-window per-key limiter (composite IP+email)
│   ├── readiness/              # /readyz aggregate
│   ├── smtpconfig/             # admin-editable SMTP override (encrypted password)
│   ├── storage/                # *sql.DB facade + embedded goose migrations
│   ├── tokens/                 # reveal tokens (issue + atomic consume)
│   ├── totp/                   # RFC 6238 HMAC-SHA1, base32 secrets, recovery codes
│   ├── version/                # ldflags-injected build metadata
│   └── webauthn/               # FIDO2 registration + assertion ceremonies
├── web/                        # JavaScript generation bundle (Vite + Vitest)
│   ├── src/
│   │   ├── entropy.js          # calculateEntropy() — shared by user UI + admin
│   │   ├── generators/{g1,g2,g3}.js
│   │   ├── crypto.js           # WebCrypto wrapper (NO Math.random ever)
│   │   ├── transforms.js       # T01..T09 admin-policy-driven transforms
│   │   └── index.js            # exports + window.SealKeeper.Generation
│   └── dist/sealkeeper-generation.umd.js   (build artefact, gitignored)
├── tests/e2e/                  # Playwright multi-browser suite
├── docs/prd/                   # 13 modules A..M (validated v1.0 in French)
├── design/                     # marketing site, palette/typography source of truth
├── helm/sealkeeper/            # production Helm chart
├── k8s/                        # raw K8s manifests
├── docker-compose.yml          # production Compose (postgres + sk + caddy)
├── Dockerfile                  # distroless multi-stage build
└── .github/workflows/          # CI (ci.yml) + release (release.yml)
```

### Where to look first when you arrive

1. **`cmd/sealkeeper/main.go`** — wiring tree. Reads every repo, hands them to `httpserver.Server` via `Set*` methods.
2. **`internal/httpserver/server.go`** — public surface (landing, reveal, /api/v1/*).
3. **`internal/httpserver/admin.go`** — every admin page and handler lives here (~4 000 LoC, monolithic on purpose so changes don't ripple).
4. **`docs/prd/00-work-plan.md`** — work-plan ledger of which modules are done.

---

## 3. Data model

Twelve migrations under `internal/storage/migrations/{postgres,sqlite}/`. Each migration ships in **both dialects** (forward-only, embedded via `go:embed`):

| #    | Table(s)                            | Purpose                                                  |
|------|-------------------------------------|----------------------------------------------------------|
| 0001 | `schema_meta`, `kv`, `captured_mail`, `audit_log` | Bootstrap: metadata, KV store, eval-mode capture, hash-chained audit |
| 0002 | `request_tokens`, `user_sessions`   | Public flow's one-shot tokens + reveal sessions          |
| 0003 | `admins`, `admin_sessions`          | Operators (bcrypt) + cookie-bound sessions               |
| 0004 | `domains`                           | Allowlist with `*.example.com` wildcard support          |
| 0005 | `policies`, `elevations`            | Up-to-three policies per domain; B2/B3 promotion lists   |
| 0006 | `libraries`                         | Dictionaries / corpora, content-addressed by SHA-256     |
| 0007 | `email_templates`                   | Per-kind / per-language overrides (system fallback)      |
| 0008 | `integrations`                      | SIEM sink definitions + filters                          |
| 0009 | `branding`                          | Single-row instance identity (CHECK id=1)                |
| 0010 | `admin_webauthn_credentials`        | FIDO2 keys per admin                                     |
| 0011 | *(branding heraldic defaults)*      | Re-paints factory blue → cardinal/gold/ink               |
| 0012 | `smtp_config`                       | Admin-editable relay override (single row, CHECK id=1)   |

**Single-row tables (`branding`, `smtp_config`)** use `CHECK (id = 1)`. The repo's `Get` auto-bootstraps the row on first call so the public surface never errors on a missing row.

**Hash-chained audit** (`audit_log`): each row carries `entry_hash = sha256(prev_hash || canonical(event))`. `audit.Repo.VerifyChain` returns the sequence number of the first broken row; the integrity badge on `/admin/audit` turns red on the next page load.

**SQLite vs Postgres parity** is mandatory. Helpers in each repo translate `?` placeholders to `$N` when the driver is pgx (function `rebind`). Single statement upserts use the SQLite-portable probe + INSERT/UPDATE pattern (see `smtpconfig.Repo.Update`) rather than `ON CONFLICT`.

---

## 4. HTTP surface

### Public (unauthenticated)

| Method | Path                            | Purpose                                                    |
|--------|---------------------------------|------------------------------------------------------------|
| GET    | `/healthz`                      | Liveness (no dependencies)                                 |
| GET    | `/readyz`                       | Readiness aggregate (DB ping etc.)                         |
| GET    | `/metrics`                      | Prometheus exposition (optional bearer)                    |
| GET    | `/version`                      | Build metadata                                             |
| GET    | `/`                             | Landing + request form                                     |
| POST   | `/api/v1/request`               | Issue reveal token, send email (always 202 — FR-B.13)      |
| GET    | `/api/v1/policy`                | Returns default policy. With `?token=X` it **consumes** the token atomically and returns the typed policy. |
| GET    | `/reveal/{token}`               | Reveal page HTML; the JS bundle does the actual consumption |
| GET    | `/static/*`                     | JS bundle + assets (origin: `cfg.WebDir`)                  |
| GET    | `/static/branding/logo`         | Inline logo blob streamed from the branding repo           |
| GET    | `/__captured_mail`              | In-memory mail viewer (eval + demo only)                   |

### Admin (session-gated)

Login, setup wizard, dashboard, then management surfaces:

| Route                                  | Files                              |
|----------------------------------------|------------------------------------|
| `/admin/login` GET/POST                | Login + password + TOTP            |
| `/admin/login/webauthn/{begin,finish,cancel}` | WebAuthn step-up after password OK |
| `/admin/setup` GET/POST                | First-login wizard (B3 password + TOTP + recovery codes); QR PNG via `rsc.io/qr`, returned as `template.URL` so `data:` URLs aren't neutered |
| `/admin/dashboard`                     | Run-mode panel + production howto |
| `/admin/account` + `/account/{email,password}` | Self-account: rename, rotate password |
| `/admin/admins` + `/admins/{add,toggle,delete}` | Multi-admin management; last-active-admin safeguards |
| `/admin/domains` + import + CRUD       | Allowlist + CSV import             |
| `/admin/policies` + `/policies/{id}/{edit,save,toggle,delete}` + `/policies/add` | Policy CRUD; live entropy preview backed by `window.SealKeeper.Generation.calculateEntropy` |
| `/admin/elevations` + import + CRUD    | B2/B3 lists + CSV import           |
| `/admin/libraries` + upload/delete/download | Dictionary + corpus management   |
| `/admin/templates` + edit + save + preview + reset | Mail template overrides       |
| `/admin/integrations` + add/toggle/delete/test | SIEM sink CRUD                |
| `/admin/smtp` + save/clear/test        | Admin-editable SMTP relay          |
| `/admin/branding` + save + logo + clear | Instance identity                 |
| `/admin/security` + add/finish/delete  | WebAuthn key enrolment             |
| `/admin/audit`                         | Hash-chained audit log viewer      |
| `/admin/captured-mail`                 | Captured mail viewer (eval + demo) |

**CSRF discipline.** Every admin POST requires the `sk_admin_csrf` cookie value echoed in a hidden `csrf_token` form field (double-submit). Login uses a separate short-lived `sk_admin_login_csrf` cookie. Helpers: `checkSessionCSRF`, `checkLoginCSRF`.

---

## 5. Run modes

Two run modes, picked **at startup** by `SK_MODE` (`eval` or `production`), plus the public-demo toggle `SK_DEMO_MODE=true` layered on either. `SK_MODE=demo` is **not** a value: `config.validate` refuses it with a message pointing at `SK_DEMO_MODE`. Switching requires a restart — there is no `/admin/mode` toggle. The dashboard surfaces the current mode and the env envelope required to switch.

| Setting      | What flips                                                              |
|--------------|-------------------------------------------------------------------------|
| `SK_MODE=eval` | Auto-generated master secret + SQLite DSN if missing; in-memory `CaptureSender`; `/__captured_mail` + `/admin/captured-mail` expose the whole queue; admin cookies without `Secure` (plain-http localhost); plain `http://` SIEM sinks accepted; bootstrap admin password printed once on stdout; `debug_reveal_url` in `/api/v1/request` replies |
| `SK_DEMO_MODE=true` | Capture sender forced (env-wired and `/admin/smtp` SMTP ignored); `/__captured_mail` scoped to the caller's own mail; 1/h IP and 1/h email request limits; admin console read-only outside the demo story (domains, policies, elevations, templates stay editable); integration enable + library upload refused; `internal/demo.Resetter` empties the editable tables every 24 h and restores accounts, branding, SMTP override and kv from the boot snapshot |
| `SK_MODE=production` (default) | `SK_MASTER_SECRET` required (placeholder/weak refused); NopSender unless SMTP wired; full rate limits and lockout; no `/__captured_mail`; HTTP SIEM sinks must be `https://`; no banner |

The dashboard mode panel shows `eval` when `SK_MODE=eval` (even with the demo toggle on), else `demo` when `SK_DEMO_MODE=true`, else `production`; both banners render independently.

---

## 6. Configuration reference

Loaded by `internal/config.Load` with precedence: defaults → `SK_CONFIG_FILE` (YAML) → env vars → flags. Every knob carries a default that makes the eval flow zero-config.

Key env vars:

| Variable                         | Default                | Notes                                                       |
|----------------------------------|------------------------|-------------------------------------------------------------|
| `SK_MODE`                        | `production`           | `eval` / `production` (`demo` is refused — use `SK_DEMO_MODE`) |
| `SK_BASE_URL`                    | `http://localhost:8443`| Drives reveal URLs + WebAuthn RPID derivation               |
| `SK_HTTP_LISTEN`                 | `:8443`                | TCP address                                                 |
| `SK_DATABASE_URL`                | sqlite in eval         | `postgres://…` or `sqlite://…`                              |
| `SK_MASTER_SECRET`               | auto in eval only      | base64 32 bytes — **pin in production AND across rebuilds** |
| `SK_INSTANCE_DOMAIN`             | derived from BaseURL   | From-address host, WebAuthn RPID                            |
| `SK_BOOTSTRAP_ADMIN_PASSWORD`    | random 20-char         | **Eval-only** override; ≥ 12 chars                          |
| `SK_RATE_LIMIT_*`                | 3/h email, 10/h IP     | Demo mode forces 1/1                                        |
| `SK_SMTP_*`                      | unset                  | Env-wired sender; overridden at runtime by `/admin/smtp`    |
| `SK_TRUSTED_PROXY_CIDRS`         | unset (Compose: `172.31.250.10/32`) | XFF honoured only from these peers, walked right-to-left; validated at startup |
| `SK_LOG_FORMAT` / `SK_LOG_LEVEL` | `json` / `info`        | slog                                                        |
| `SK_DEMO_MODE`                   | `false`                | Public-demo toggle, orthogonal to `SK_MODE` (see §5)        |
| `SK_ADMIN_SESSION_TTL_SECONDS`   | `28800` (8 h)          | Absolute admin session lifetime; ≥ 60                       |
| `SK_ADMIN_SESSION_IDLE_SECONDS`  | `1800` (30 min)        | Admin idle timeout; 60 ≤ idle ≤ TTL                         |
| `SK_MAX_LIBRARY_SIZE_MB`         | `10`                   | Max `/admin/libraries` upload; 1..1024                      |
| `SK_MAX_ACTIVE_SESSIONS`         | `10000`                | **Not implemented**; a non-default value warns at startup   |
| `SK_SESSION_TTL_SECONDS`         | `900`                  | **Ignored** (TTL is per policy); non-default value warns   |
| `SK_MAINTENANCE_MODE`            | `false`                | **Not implemented** — `true` is a startup error             |
| `SK_INTEGRATIONS_ALLOW_PRIVATE`  | `false`                | Let SIEM sinks dial RFC 1918 / ULA / CGNAT. Loopback, link-local (cloud metadata), unspecified and multicast stay refused; checked on the resolved IP at connect time |

Parsing is strict: a malformed integer, boolean (`true/false/1/0/yes/no/on/off`) or seconds value is a startup error, not a silent fallback to the default (an empty value counts as unset). Unknown keys in the `SK_CONFIG_FILE` YAML are a startup error too (`KnownFields`); YAML durations take Go syntax (`30m`), a bare integer would be nanoseconds and fails the 60 s floor.

**Pinning `SK_MASTER_SECRET` is critical.** TOTP secrets and SMTP relay passwords are AES-256-GCM-wrapped with this key. A rebuild without the env var minted a fresh key in earlier sessions, which left the wrapped TOTP blob unopenable — observed bug, surfaced as the new `admin.ErrTOTPUnrecoverable` (login slug `totp_unrecoverable`).

---

## 7. Patterns and conventions

### Cryptobox AAD discipline

`internal/cryptobox` exposes `Seal(plaintext, aad)` / `Open(ciphertext, aad)` over AES-256-GCM. Every caller derives its AAD from a domain-specific tag so the same ciphertext copied to a different column will refuse to decrypt:

```go
sha256("sealkeeper-admin:<id>")     // admin TOTP + recovery codes
sha256("sealkeeper-smtp")           // SMTP relay password
```

Add an AAD for any new encrypted field; never reuse one.

### Audit-append pattern

State-changing handlers call:

```go
s.auditAppend(r.Context(), "<event_type>", actor, target, map[string]any{…})
```

Helper guarantees the chain stays valid and never returns to the caller — failures are logged. Event types are namespaced by subsystem: `admin.login`, `domain.created`, `policy.updated`, `smtp.test_failed`, `integration.toggled`, etc. The `auditAppend` also pushes through the integrations dispatcher when one is wired (FR-F).

### Repo constructor shape

Every `internal/<thing>/Repo` follows:

```go
type Repo struct { db *sql.DB; now func() time.Time; ... }
func NewRepo(db *sql.DB, ...) *Repo
func (r *Repo) WithClock(now func() time.Time) *Repo   // test helper
```

Methods return typed `Err*` sentinels (`ErrNotFound`, `ErrAlreadyExists`, etc.) that handlers map to URL slugs.

### Single-row table bootstrap

`branding`, `smtp_config`. The `Get` method:

1. SELECT.
2. If `sql.ErrNoRows`, INSERT a default row with explicit values (don't rely on column DEFAULTs alone).
3. Re-read and return.

Race tolerance: if INSERT fails with a UNIQUE conflict (another worker just inserted), fall through to the second read.

### Anti-enumeration on public surface

`POST /api/v1/request` always returns `202 accepted` — never 4xx — even when the email is denied, the domain isn't allowlisted, or the rate limit fired. The audit log is the operator's source of truth (FR-B.13). Eval mode adds `debug_reveal_url` to the response so smoke tests can exercise the consume path.

### HTML templates

Every admin page is a Go `html/template` string constant in `internal/httpserver/admin.go`. The base shell (`adminBaseTpl`) provides the wax-seal SVG mark, the topbar nav, the eval/demo banners and the CSS variables (`--cream`, `--cardinal`, `--gold`, etc.) that match `/design`.

**Pitfall observed.** `html/template` neuters non-{http,https,mailto,ftp} URLs in `src=`/`href=` attributes (rewrites to `#ZgotmplZ`). The QR code in the setup wizard uses a `data:image/png;base64,…` URL — wrap it in `template.URL` to bypass the sanitiser. See `otpauthQRDataURL`.

### CSS palette

Tokens shared between the public site (`design/*.html`) and the admin shell:

```
--cream        #F4EFE6   parchment background
--cream-deep   #ECE5D5   form-input fill
--bg-elev      #FBF7EE   card surface
--ink          #1A1814   primary text
--stone        #7A7670   muted text
--cardinal     #7A1F2B   primary action / accent
--gold         #C9A961   secondary highlight / eval banner
--night        #1E2D45   link colour
```

Display font: Cormorant Garamond. Body: Inter. Code: JetBrains Mono. Served from `fonts.bunny.net` (no Google Fonts).

---

## 8. Testing strategy

### Go unit tests (`go test ./...`)

Per-package, hermetic. Each repo test opens an in-process SQLite via `storage.Open(ctx, Options{DSN: "sqlite://..."})` against a `t.TempDir()` path, calls `MigrateUp`, and asserts repository behaviour. No shared fixtures across packages.

Tables of cases use `cases := []struct{…}{…}; for _, c := range cases { t.Run(c.name, ...) }`. Don't pre-Go-1.22 the loop variable shadow.

Common patterns:

* `errors.Is(err, repo.ErrXxx)` for typed assertions.
* `golang.org/x/crypto/bcrypt`, `cryptobox.New(base64key)`, `time.Time` via `Repo.WithClock(func() time.Time {...})`.

### JS unit tests (`cd web && npm test`)

Vitest 4, 90% coverage threshold. Generator + entropy + transforms all have spec files under `web/tests/`. `npm run build` re-creates `web/dist/sealkeeper-generation.umd.js` (gitignored).

### Playwright (`cd tests/e2e && npx playwright test`)

* **`happy-path.spec.ts`** — runs in CI on every PR (Chromium only, `@happy-path` grep). Public landing + request + reveal.
* **`a11y.spec.ts`** — axe-core checks. CI-optional.
* **`nightly.spec.ts`** — extended public flow.
* **`screenshots.spec.ts`** — manual: drives the public + admin flow and saves PNGs to `design/screenshots/`. Run with `SK_BOOTSTRAP_ADMIN_PASSWORD=…` so the spec can log in deterministically.

Playwright launches the SealKeeper binary itself via `webServer:` in `playwright.config.ts`. `SEALKEEPER_BIN=/path/to/sk` shortcircuits the `go run` fallback when iterating against a pre-built binary.

### Linting

`golangci-lint v2.12.2` with `.golangci.yml`. Enabled linters cover the FR-L.39 mandated set + a curated bug-catcher list. Gosec's heuristic false positives (G104/G120/G124/G703/G704/G705/G710) are excluded with documented rationale; the standalone gosec docker action in CI mirrors that exclude list.

Use `// #nosec Gnnn -- rationale` for surgical exemptions (e.g. the fire-and-forget post-consultation goroutine). golangci-lint's `//nolint:` directive works inside Go, but standalone gosec reads `// #nosec`.

---

## 9. CI/CD

`.github/workflows/ci.yml` (every PR + push to main):

* **Lint** — gofmt, golangci-lint v2.12.2, prettier, eslint, hadolint, yamllint (strict), markdownlint, shellcheck.
* **Build** — `linux/{amd64,arm64} × go {1.26.10, 1.27.3}` matrix.
* **Test Go** — same matrix; coverage uploaded to Codecov.
* **Test JS** — Vitest with `--coverage`.
* **SAST** — govulncheck (blocking on affecting CVEs), gosec docker (`securego/gosec@v2.24.6`), semgrep (OWASP + CWE-Top-25 + golang + javascript via `pip install semgrep` + `--exclude-rule` list mirroring the gosec excludes).
* **E2E subset** — Playwright `@happy-path` on Chromium.
* **CI success** — verifies every upstream job is green; the branch protection rule keys off this single job.

Go version is **pinned to 1.26.10** end-to-end (setup-go, Dockerfile builder, `go.mod` toolchain directive) so stdlib CVEs fixed up to 1.26.10 stay closed even on cached runner images.

`.github/workflows/release.yml` — tag-driven; pushes a cosign-signed OCI image to GHCR + SLSA provenance attestation. Same pinned Go version.

---

## 10. Common tasks — recipes

### Add a new admin page

1. Add a route inside the session-required group in `registerAdminRoutes` (`internal/httpserver/admin.go`).
2. Write `handleAdminXxx` + `handleAdminXxxSave/Delete/...` mirroring the existing pattern: `ParseForm` → `checkSessionCSRF` → demo-mode refusal if mutating → repo call → typed error → `auditAppend` → 303 See Other.
3. Add a template constant `adminXxxTpl` at the end of `admin.go`; reference it in the `adminTpls` parse list.
4. Add the nav link inside the `<nav>` block of `adminBaseTpl`.
5. Render-time data lives in the `map[string]any` passed to `s.renderAdmin`. Always include `Admin`, `Session`, `EvalBanner`, `DemoBanner`, `Label`, `CSRF`, plus the page-specific data.

### Add a new DB column

1. Write `internal/storage/migrations/{postgres,sqlite}/NNNN_descriptor.sql` (forward-only + Down). Mirror the syntax between dialects.
2. Update the repo's `Get` / `read` and `Update` / `Create` queries.
3. Add the field to the row struct + `scan` helper. SQLite returns timestamps as strings — use the `toTime(any)` helper, which tolerates the four common layouts.
4. Run `go test ./internal/storage/...` — the storage smoke test asserts `MigrateUp` runs without error.

### Add a new admin subcommand

1. Add a `case "<verb>":` in `cmd/sealkeeper/main.go` dispatching to `runXxx`.
2. Use the `openAdminRepo(ctx)` helper if you need an `*admin.Repo`. It reads `config.Load()`, opens storage, runs migrations, returns the repo + cleanup.
3. Append a line to the `usage()` block.
4. The subcommand inherits the running container's env, so `SK_DATABASE_URL` + `SK_MASTER_SECRET` Just Work for `docker exec` invocations.

### Bump a Go dependency

```
go get github.com/foo/bar@vX.Y.Z
go mod tidy
go test ./...
```

Then rerun `govulncheck ./...` locally — CI will block the PR otherwise.

### Capture a fresh screenshot set

```
SK_BOOTSTRAP_ADMIN_PASSWORD=screenshot-admin-passw0rd \
  SEALKEEPER_BIN=/tmp/sk.exe \
  npx playwright test screenshots --project=chromium --grep=@screenshots
```

The spec wipes 15 PNGs under `design/screenshots/`. Pages they cover are listed in `screenshots.spec.ts`.

---

## 11. Pitfalls observed during the build

A running list of things that have tripped Claude or a human in this codebase. **Read this before changing anything in those areas.**

1. **`html/template` strips `data:` URLs from `src`/`href` attributes.** Wrap with `template.URL` for legitimate uses (QR codes, inline SVGs as data URIs).
2. **The bootstrap admin email is `admin@localhost`.** The email-validation regex must accept bare hostnames, not just FQDNs. See `admin.emailRe`.
3. **bcrypt has a 72-byte input limit.** Long unicode passwords are silently truncated. Both login and password-change paths bcrypt the same input so they match — but the truncation is invisible.
4. **Master secret rotation is silent.** Until the recent fix, a rebuild of the eval container regenerated `SK_MASTER_SECRET` and left the stored TOTP secret undecryptable; the login surface returned a vague "internal". Now wraps with `ErrTOTPUnrecoverable` → slug `totp_unrecoverable`. Operator advice: **pin the env var across rebuilds**.
5. **Entropy must match what the generator draws.** `web/src/params.js` is the single validated reading of policy parameters, shared by the generators and `calculateEntropy`; invalid values throw `InvalidPolicyDescriptor` instead of falling back. G1/G2 need an inline `parameters.library` array (no library id lookup yet) or they throw `LibraryNotFound`; only the server's zero-config default (`builtinDefault`) may use the bundled sample, and its badge reflects the sample's real size. Entropy counts unique entries and credits only what is drawn (G2: `numericGroups[0]` only, no transforms; G3: `length` + `excludeAmbiguous`). Never let the badge round up across a threshold.
6. **`-buildvcs=true` requires git in the builder image.** Alpine ships without it — the Dockerfile installs git in the builder stage. The error message is hard to map back to "missing git" otherwise.
7. **SQLite cannot `ALTER COLUMN ... SET DEFAULT`.** Postgres can. Migration 0011 demonstrates the workaround: UPDATE-only on SQLite, ALTER + UPDATE on Postgres.
8. **Volume permissions in Docker.** The container runs as UID 65532; named volumes are created root-owned. Either chown in an init step (`docker run --rm -v sealkeeper-data:/data alpine chown -R 65532:65532 /data`) or use a `:memory:` SQLite for ephemeral testing.
9. **Distroless has no shell.** `docker exec sealkeeper-local sh` fails. To run a CLI subcommand: `docker exec sealkeeper-local /usr/local/bin/sealkeeper admin list` (or `//usr/local/...` from Git Bash on Windows to dodge path mangling).
10. **Goose migrations are checksummed.** Never edit a migration after it lands in `main` — write a new one. SQLite + Postgres files must both exist, both pass the same forward steps.
11. **Alpine 3.22 is retired for Go 1.26.10.** Use `golang:1.26.10-alpine3.23` (3.21 went the same way at 1.26.3). Same trap will appear at the next Go minor.
12. **The login error slug `bad_creds` covers three different failures** (unknown email, wrong password, wrong TOTP code) — that's anti-enumeration on purpose. A real internal failure surfaces as `internal`; a master-secret rotation surfaces as `totp_unrecoverable` now.
13. **gosec `Nosec: N, Issues: 0` is the success line.** Tools shipping a `// #nosec Gxxx -- rationale` exemption still register in the Nosec count.
14. **Operator passwords are scored, not just length-checked.** `admin.ValidateAdminPassword` requires 16 chars + 3 classes *and* ≥ 100 bits of estimated guessing entropy (`EstimatePasswordEntropy`: dictionary/common words with leet and case variants, product/instance/email words, years, sequences, keyboard walks, repeats; only the first 72 bytes count). Test fixtures like `Strong-Admin-2026!` are refused — use random-looking strings. Generated passwords (`randomPassword`) redraw until they pass.
15. **Last-active-admin guard must stay one atomic write.** `SetDisabled`/`Delete` carry the "another active admin exists" condition inside the UPDATE/DELETE, and on Postgres lock the active rows (`FOR UPDATE`) first — READ COMMITTED would otherwise let two cross-disables both pass. Recovery from zero active admins: `sealkeeper admin enable --email <e>`.
16. **WebAuthn clone signal is the RP's job.** go-webauthn only sets `Authenticator.CloneWarning`; `webauthn.Repo.FinishLogin` turns it into `ErrCloneDetected` (audited `admin.webauthn_clone_detected`).

---

## 12. PRD index

`docs/prd/00-work-plan.md` is the ledger. Modules in scope at v0.1:

| Module | File                       | Topic                                                   |
|--------|----------------------------|---------------------------------------------------------|
| A      | `A-generation.md`          | Generators G1/G2/G3, entropy formulas, transforms       |
| B      | `B-user-worflow.md`        | Public request → reveal flow, anti-enumeration          |
| C      | `C-admin-console.md`       | Admin console requirements (auth, domains, policies, …) |
| D      | `D-backend.md`             | Go backend conventions, cmd/ layout, observability      |
| E      | `E-security-audit.md`      | Audit log shape, SIEM dispatch, hash-chain integrity    |
| F      | `F-integrations.md`        | Outbound SIEM (webhook / Splunk / Sentinel / Elastic / syslog) |
| G      | `G-api-rest.md`            | Public REST surface contract                            |
| H      | `H-deployment.md`          | Docker, Compose, K8s, Helm, security hardening          |
| I      | `I-rgpd-compliance.md`     | RGPD / GDPR posture, DPO record, retention              |
| J      | `J-I18n-accessibility.md`  | i18n + a11y requirements (axe-core in CI)               |
| K      | `K-mobile-tablet.md`       | Responsive viewport requirements                        |
| L      | `L-quality-release.md`     | CI/CD, lint floor, govulncheck, release procedure       |
| M      | `M-admin-accounts.md`      | Operator account management (B3 policy, multi-admin)    |

The PRD modules are validated French v1.0 — written by Pascal-Louis Darmon with assistance. The implementation strictly tracks the FR-* identifiers in commit messages.

---

## 13. Where to send questions

* **Code-level / how does X work** — read this file first, then the package's `*_test.go`, then the package doc-comment at the top of the main file.
* **Why does X exist** — `docs/prd/<module>.md`, look at the FR-* line.
* **Security disclosure** — `SECURITY.md`, do *not* open a public issue.
* **Marketing / copy / visual identity** — `design/*.html`, `design/style.css`.
* **Roadmap** — GitHub Projects, plus `docs/prd/00-work-plan.md`.

Last updated: 2026-05-23.
