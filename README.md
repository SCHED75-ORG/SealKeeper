<div align="center">

# SealKeeper

**An ANSSI-compliant password — memorable, in two clicks.**

*Self-hosted password distributor for enterprises. The browser generates, the server gates. No password ever crosses the wire.*

[![License: AGPL v3](https://img.shields.io/github/license/SCHED75-ORG/SealKeeper?style=flat-square&color=7A1F2B&labelColor=1A1814)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/SCHED75-ORG/SealKeeper?style=flat-square&color=C9A961&labelColor=1A1814&logo=go&logoColor=C9A961)](go.mod)
[![Build Status](https://img.shields.io/github/actions/workflow/status/SCHED75-ORG/SealKeeper/ci.yml?branch=main&style=flat-square&color=1E2D45&labelColor=1A1814)](https://github.com/SCHED75-ORG/SealKeeper/actions)
[![Latest Release](https://img.shields.io/github/v/release/SCHED75-ORG/SealKeeper?style=flat-square&include_prereleases&color=C9A961&labelColor=1A1814)](https://github.com/SCHED75-ORG/SealKeeper/releases)
[![Stars](https://img.shields.io/github/stars/SCHED75-ORG/SealKeeper?style=flat-square&color=C9A961&labelColor=1A1814&logo=github&logoColor=C9A961)](https://github.com/SCHED75-ORG/SealKeeper/stargazers)

[Website](https://sealkeeper.eu) · [Documentation](https://sealkeeper.eu/docs.html) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Hall of thanks](https://sealkeeper.eu/hall-of-thanks.html)

</div>

---

## What is SealKeeper?

SealKeeper is a **self-hosted password distributor for enterprises**. It helps your employees choose passwords that are *at once* compliant with [ANSSI recommendations](https://cyber.gouv.fr/publications/recommandations-relatives-lauthentification-multifacteur-et-aux-mots-de-passe) (levels B1, B2, B3) and easy to remember.

A user opens the public page, enters their work email, receives a single-use link, and is presented with several password proposals — generated entirely **inside their browser** via the [WebCrypto API](https://www.w3.org/TR/WebCryptoAPI/). They pick the one they find easiest to remember. The password never crosses the server. SealKeeper has nothing to leak.

## Why does this exist?

Every IT department faces the same dilemma:

— Either users pick passwords they can remember, which usually fail an ANSSI audit (birth years, child names, keyboard sequences).
— Or they pick something strong, write it on a sticky note, and effectively negate the strength.

SealKeeper closes this gap with three calibrated generators (citations, word assembly, pure random), one per ANSSI level, mapped to the sensitivity of the user's account.

## Key features

- **Three generators, three ANSSI levels** — Citations transformed (B1, ~55-65 bits), word assembly Diceware-style (B2, ~90 bits), pure random grouped (B3, ~119 bits).
- **Per-domain policies** — Each authorised email domain has up to three policies (one per ANSSI level), each binding a generator with its own parameters, dictionary, or corpus.
- **B2 / B3 elevation lists** — Administrators maintain two curated lists per domain: addresses entitled to B2 (managers) and addresses entitled to B3 (system admins). All other addresses default to B1.
- **Zero-knowledge by design** — Password generation runs in the user's browser. The server holds only allowlists, policies, audit logs, and session tokens. No symmetric key, no plaintext.
- **Live entropy meter** — When configuring a policy, the admin sees the computed entropy in real time, with ANSSI level indicators (B1 / B2 / B3 reached or not). SealKeeper advises; the admin decides.
- **Editorial libraries** — Upload custom dictionaries and quotation corpora per language. Default bundles include EFF Diceware FR/EN and a public-domain quotation corpus.
- **TOTP for admins** — Console authentication gated by password + RFC 6238 TOTP, with optional WebAuthn for hardware key support.
- **SIEM-ready** — Signed audit log (HMAC chained), export to syslog RFC 5424, JSON webhook, or push to Splunk / Sentinel / Elastic. Prometheus metrics on `/metrics`.
- **Self-hosted, AGPL v3** — Single Go binary, OCI image, SQLite or PostgreSQL backend, your infrastructure.

## Quickstart

The fastest way to try SealKeeper is in **evaluation mode**, which captures emails locally instead of sending them and uses SQLite for storage:

```bash
docker run --rm -p 8443:8443 \
  -e SK_MODE=eval \
  -e SK_BASE_URL="https://localhost:8443" \
  ghcr.io/sched75-org/sealkeeper:latest
```

The first run prints a bootstrap password to the container logs. Then:

1. Open `https://localhost:8443/admin` and sign in.
2. Add a test domain to the allowlist (e.g. `example.com`).
3. Configure one B1 policy with generator G2 (word assembly, 6 words).
4. Open `https://localhost:8443/` and request a password as a user (any address matching your allowlist).
5. Captured emails appear in `/admin/captured-mail` — click the link, see proposals generated in your browser.

> **Evaluation mode is not for production.** See the [deployment guide](https://sealkeeper.eu/docs.html) for production setup (real SMTP, PostgreSQL, TLS termination, log shipping).

## How it works

```mermaid
sequenceDiagram
    autonumber
    actor User as 👤 User · Browser
    participant Server as 🛡️ SealKeeper · Gatekeeper

    User->>Server: POST /api/request (work email)
    activate Server
    Note right of Server: Allowlist check<br/>Determine ANSSI level (B1/B2/B3)<br/>Anti-enumeration: response always identical
    Server-->>User: Single-use link via email
    deactivate Server

    Note left of User: User clicks the email link

    User->>Server: GET /api/policy (session token)
    activate Server
    Server-->>User: Policy descriptor (generator + params)
    deactivate Server

    Note left of User: 🔐 In-browser WebCrypto generation<br/>N password proposals computed locally<br/>Password never crosses the wire
    Note right of Server: ✋ No password seen<br/>No symmetric key<br/>Signed audit log only

    Note left of User: User picks one proposal<br/>Clipboard auto-purged after 30s<br/>Page closes when session expires
```

Detailed flow on the [website's How it works](https://sealkeeper.eu/#how) section.

## Configuration

Administration is done entirely through the embedded admin console at `/admin`. Key configuration surfaces:

| Section | Configures |
|---|---|
| Allowlist domains | Which email domains are accepted on the public page |
| Policies per domain | Up to three policies per domain, one per ANSSI level |
| Elevation lists B2 / B3 | Email addresses entitled to higher-level passwords |
| Editorial libraries | Word dictionaries and quotation corpora, by language |
| SMTP relay | Server, port, authentication, TLS mode |
| Branding | Logo, accent colour, email subject and signature |
| Audit & SIEM | Syslog / webhook / Splunk / Sentinel / Elastic |
| TOTP / WebAuthn | Admin console second factor |

Configuration changes are versioned and exported as JSON for review or replication across environments.

## Security

SealKeeper is a security product. We treat reports the way we would wish ours to be treated: promptly, in writing, without legal threat. See [SECURITY.md](SECURITY.md) for the responsible disclosure process, PGP fingerprint, and what to include in a report.

PGP fingerprint: `1E11 670E 11A0 4C0D 808F  B94D CCC4 93CB A701 6D6E`

Verifiable on [keys.openpgp.org](https://keys.openpgp.org/search?q=security@sealkeeper.eu) and on the site at [/.well-known/pgp-key.asc](https://sealkeeper.eu/.well-known/pgp-key.asc).

Past acknowledgements (currently none — pre-release) are maintained at the [Hall of thanks](https://sealkeeper.eu/hall-of-thanks.html).

## Roadmap

- **0.1.0** (pre-alpha) — Single-tenant evaluation binary, three generators, policy-per-domain, TOTP admin console, French and English UI.
- **0.2.0** — Mobile-optimised reveal page, QR-transfer between devices, German/Spanish/Italian translations.
- **0.3.0** — SAML/OIDC for admin SSO, reproducible builds with SLSA attestation, Helm chart for Kubernetes deployment.
- **0.4.0** — Multi-tenant mode, team scoping, granular RBAC for elevation lists.
- **1.0.0** — API stability commitment, third-party security audit, production deployment readiness.

Detailed roadmap on the [changelog page](https://sealkeeper.eu/changelog.html).

## Standards and references

SealKeeper is engineered to align with:

- **[ANSSI](https://cyber.gouv.fr/publications/recommandations-relatives-lauthentification-multifacteur-et-aux-mots-de-passe)** — *Recommandations relatives à l'authentification multifacteur et aux mots de passe* (mapped to generators G1/G2/G3).
- **[NIST SP 800-63B](https://csrc.nist.gov/publications/detail/sp/800-63b/final)** — *Digital Identity Guidelines* (length over complexity).
- **OWASP ASVS 4.0** — Authentication Verification Standard (level 2 for the console).
- **[RGAA 4.1](https://accessibilite.numerique.gouv.fr/)** — Accessibility (target level AA).
- **RGPD / GDPR** — Configurable retention, DPO export, data minimisation by design.
- **[RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)** — TOTP for admin second factor.
- **[W3C WebCrypto API](https://www.w3.org/TR/WebCryptoAPI/)** — Standardised in-browser cryptographic primitives.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, coding style (Go: `gofmt`, `go vet`, `golangci-lint`), commit conventions, and pull request process. The project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md) code of conduct.

If you find a security issue, please **do not** open a public issue. Follow the procedure in [SECURITY.md](SECURITY.md).

## License

SealKeeper is licensed under the **GNU Affero General Public License v3.0** ([LICENSE](LICENSE)). Any deployment of SealKeeper, including network-accessible deployments, must offer its source code to users under the same licence.

---

<div align="center">

Copyright © 2026 Pascal-Louis Darmon — [pgp 1E11 670E 11A0 4C0D 808F B94D CCC4 93CB A701 6D6E](https://sealkeeper.eu/.well-known/pgp-key.asc)

</div>
