# Release checklist

> Human gate to walk through **before** pushing the annotated, GPG-signed tag
> that triggers `release.yml`. Each item is mandatory unless explicitly marked
> *(optional)*.
>
> References: PRD module L §6.3 — *Release process*, FR-L.56 (SemVer), FR-L.61
> (Conventional Commits), FR-L.63 (signed tags), FR-L.78 (Keep a Changelog).

| # | Step | Owner | Done? |
|---|------|-------|-------|
| 1 | Confirm the target version follows **SemVer 2.0** (FR-L.56). Decide MAJOR / MINOR / PATCH against the rules in module L §3.7 — breaking change → MAJOR, additive feature → MINOR, bugfix only → PATCH. | Release manager | ☐ |
| 2 | Verify `main` is green: latest `CI` run on the release commit is **success** (FR-L.47, FR-L.53), including the `CI success` summary status. | Release manager | ☐ |
| 3 | Update `CHANGELOG.md` (FR-L.78). Move *Unreleased* entries under a new `## [vX.Y.Z] - YYYY-MM-DD` heading. Group by `Added` / `Changed` / `Fixed` / `Security` / `Deprecated` / `Removed`. Highlight any operator action required (env vars, migrations, breaking changes — FR-H.67). | Release manager | ☐ |
| 4 | Update `README.md` Quickstart and Roadmap sections **if** the release adds new modes, env vars or supported platforms (FR-L.70). | Release manager | ☐ |
| 5 | Bump version references that are not yet auto-driven by the tag: Helm `Chart.yaml` (`appVersion`, `version`), any `version` field in docs front-matter or sample files. | Release manager | ☐ |
| 6 | Confirm pre-commit passes locally: `pre-commit run --all-files`. | Release manager | ☐ |
| 7 | Confirm the deployment bundle assembles locally (`make release-bundle`) and the smoke checklist passes on your laptop: `docker compose up -d`, `curl /healthz`, `curl /api/v1/policy`, mail capture in eval mode (mirrors the `smoke-bundle` job in `release.yml`). | Release manager | ☐ |
| 8 | Confirm the maintainer's GPG key is available locally (`gpg --list-secret-keys`) and matches the fingerprint pinned in `MAINTAINER_GPG_FPR` (FR-L.64). | Release manager | ☐ |
| 9 | Tag from `main` with an annotated **signed** tag (FR-L.63): `git tag -s vX.Y.Z -m "SealKeeper vX.Y.Z"`. Verify locally with `git tag -v vX.Y.Z` before pushing. | Release manager | ☐ |
| 10 | Push the tag (`git push origin vX.Y.Z`) and watch the `release` workflow. Do not delete or recreate the tag once `release.yml` has started — Rekor will already have recorded the signature. | Release manager | ☐ |

## One-time repository settings (release supply chain)

`release.yml` only runs on a tag push (there is no manual `workflow_dispatch`
path), builds exactly the commit the verified tag points to, and runs every
signing / publishing job (`build-image`, `sign-binaries`, `release`) in the
protected `release` environment. The workflow file cannot enforce the
following by itself — a maintainer must configure them once in GitHub:

| Setting | Where | Value |
|---------|-------|-------|
| `release` environment | Settings → Environments → New environment | Name `release` (must match `environment: release` in the workflow). |
| Required reviewers | `release` environment | At least one maintainer; enable **Prevent self-review**. The run pauses twice: once before `build-image` + `sign-binaries`, once before the final `release` job. |
| Deployment branches and tags | `release` environment | **Selected branches and tags** → add tag rule `v*.*.*` only (no branches). A run started from any other ref cannot enter the environment or read its secrets. |
| Environment secrets | `release` environment | `MAINTAINER_GPG_PRIVATE`, `MAINTAINER_GPG_PASSPHRASE`, `HELM_REPO_URL`, `HELM_REPO_USER`, `HELM_REPO_TOKEN`. **Delete any repository-level copies** — a repository secret is readable by every workflow run, including one started from an unreviewed branch. `MAINTAINER_GPG_PUBLIC` and `MAINTAINER_GPG_FPR` may stay repository secrets (they are public). |
| Tag ruleset | Settings → Rules → Rulesets → New tag ruleset | Target `v*.*.*`; restrict creations, updates and deletions; bypass list = release maintainers only. |
| Actions permissions | Settings → Actions → General | Workflow permissions: **Read repository contents** (the workflow requests write scopes per job). |

## Post-release

| # | Step | Owner | Done? |
|---|------|-------|-------|
| 11 | Verify the GitHub Release page lists every artifact: binaries × 4, `SHA256SUMS{,.asc}`, image SBOM, Helm chart `.tgz`, deployment bundle `.tar.gz` + `.zip` + `.sha256`. | Release manager | ☐ |
| 12 | Sanity-check the image: `docker run --rm -p 8443:8443 -e SK_MODE=eval ghcr.io/sealkeeper/sealkeeper:vX.Y.Z` then `curl http://localhost:8443/healthz` (smoke-image job already validated this in CI — this is a belt-and-braces check). | Release manager | ☐ |
| 13 | Verify signatures against the [verification guide](security/verification.md): `cosign verify`, `gh attestation verify`, `gpg --verify SHA256SUMS.asc`. | Release manager | ☐ |
| 14 | Announce: short message in the project README's "Latest release" badge area, release notes excerpt to whichever channels are wired (Slack/email — optional). | Release manager | ☐ |
| 15 | Open the next *Unreleased* block in `CHANGELOG.md` and bump development snapshot pointers if used. | Release manager | ☐ |

## Aborted release

If the `release` workflow fails after the tag is pushed:

1. **Do not** delete or move the tag. The signed tag is immutable and may already
   be referenced in Rekor.
2. Investigate the failing job. A transient failure (runner, network) is
   retried with **Re-run failed jobs** on the original tag-push run — never
   from another branch, which would not be able to enter the `release`
   environment and would sign under the wrong identity. Smoke-test failures should be treated as
   "release blocker, the bundle does not actually work".
3. If a fix is required, commit it to `main` (`fix:` prefix), then issue a new
   patch tag (e.g. `v0.1.1` after a failed `v0.1.0`). Never re-use a tag that
   was already pushed.
