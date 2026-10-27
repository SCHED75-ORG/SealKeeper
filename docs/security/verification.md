# Verifying SealKeeper release artifacts

> This page is the canonical reference for verifying everything we publish:
> binary checksums, OCI image signatures, SBOMs and SLSA provenance.
>
> PRD: FR-L.64 (GPG-signed checksums), FR-L.65 (cosign keyless), FR-L.66
> (CycloneDX 1.5 SBOM via syft), FR-L.67 (SLSA L2 provenance), FR-L.69 (this
> page itself), FR-H.3 (image at `ghcr.io/sched75-org/sealkeeper`).

## TL;DR — verify everything

```bash
TAG=v0.1.0   # ← the release you downloaded

# 1. GPG-signed checksums for the binaries
gpg --import docs/security/release-signing-key.asc   # from this repository
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS

# 2. Cosign keyless signature on the OCI image
cosign verify \
  --certificate-identity "https://github.com/SCHED75-ORG/SealKeeper/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/sched75-org/sealkeeper:${TAG}

# 3. SLSA provenance attestation
gh attestation verify oci://ghcr.io/sched75-org/sealkeeper:${TAG} \
  --repo SCHED75-ORG/SealKeeper \
  --signer-workflow SCHED75-ORG/SealKeeper/.github/workflows/release.yml \
  --source-ref "refs/tags/${TAG}"

# 4. SBOM (CycloneDX 1.5) for the image
cosign download attestation \
  --predicate-type https://cyclonedx.org/bom \
  ghcr.io/sched75-org/sealkeeper:${TAG} > image.sbom.intoto.jsonl
```

If every command exits with status 0 and no warning, the release is intact and
provably came from this project's `release.yml` workflow.

---

## 1. Verify binaries (GPG)

Each release attaches `SHA256SUMS` and `SHA256SUMS.asc`. The `.asc` is a
detached, ASCII-armored GPG signature produced by the **release signing key**
documented in `SECURITY.md` under "Release signing key" (fingerprint
`BB1F EC0B 3D83 B6F0 3CCF  2869 FA3F BAF2 05E4 48DA`).
It is not the security-contact key listed above it. The signing key is
**never** the same as the cosign keyless identity — cosign signs the image,
GPG signs the binary checksum file.

1. Download both files from the GitHub Release page along with the binary you
   actually want (`sealkeeper-linux-amd64`, etc.).
2. Import the release signing key (`docs/security/release-signing-key.asc` in
   this repository) and check that `gpg --fingerprint` shows the fingerprint
   above.
3. Verify the signature:
   ```bash
   gpg --verify SHA256SUMS.asc SHA256SUMS
   ```
   Expected: `Good signature from "Pascal-Louis DARMON <…>"`. gpg also warns
   that the key is not certified with a trusted signature until you certify
   it yourself; the fingerprint check in step 2 is what matters.
4. Verify the binary against the signed checksums:
   ```bash
   sha256sum -c --ignore-missing SHA256SUMS
   ```
   `--ignore-missing` skips the platforms you did not download. In the
   deployment bundle, `SHA256SUMS` and its signature sit next to the
   binaries in `binaries/`.
   Expected: every line ends with `OK`.

If the signature is `BAD` or the key fingerprint differs from the one pinned
in `SECURITY.md`, **do not run the binary**.

---

## 2. Verify the OCI image (cosign keyless)

Images are signed with cosign in keyless mode (Sigstore) — no static key, the
signature attests *the workflow that produced it*. Verification therefore
checks that the signing identity matches our GitHub Actions workflow.

Install cosign ≥ v2.4 (`brew install cosign` or
[releases](https://github.com/sigstore/cosign/releases)).

```bash
cosign verify \
  --certificate-identity 'https://github.com/SCHED75-ORG/SealKeeper/.github/workflows/release.yml@refs/tags/v0.1.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/sched75-org/sealkeeper:v0.1.0
```

Expected: `Verification for ghcr.io/sched75-org/sealkeeper:v0.1.0 — The
following checks were performed: …`. Key fields to eyeball:

- `Issuer: https://token.actions.githubusercontent.com`
- `Subject: https://github.com/SCHED75-ORG/SealKeeper/.github/workflows/release.yml@refs/tags/vX.Y.Z`

The signature is also recorded in the public Rekor transparency log; cosign
checks Rekor inclusion automatically.

---

## 3. Verify SLSA build provenance

The release workflow uses `actions/attest-build-provenance@v2` to attach a
SLSA Level 2 provenance attestation to the image. The GitHub CLI can verify
it natively:

```bash
gh attestation verify oci://ghcr.io/sched75-org/sealkeeper:v0.1.0 \
  --repo SCHED75-ORG/SealKeeper \
  --signer-workflow SCHED75-ORG/SealKeeper/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0
```

Expected: `Loaded ... attestation(s) from ...; verified signed by ...; the
following predicate types were found: https://slsa.dev/provenance/v1`.

The predicate names the exact workflow run that built the image, so a
tampered image (different workflow, different commit, different runner) will
fail verification.

---

## 4. Inspect the SBOM (CycloneDX 1.5)

SBOMs are produced by `syft` (FR-L.66) and attached two ways:

- As a release asset (`sbom-image.cdx.json` and `sbom/sealkeeper-*.cdx.json`
  per binary) — convenient for offline review.
- As a cosign attestation on the image — verifiable end-to-end:

  ```bash
  cosign download attestation \
    --predicate-type https://cyclonedx.org/bom \
    ghcr.io/sched75-org/sealkeeper:v0.1.0 \
    | jq -r '.payload | @base64d | fromjson | .predicate' \
    > image.sbom.cdx.json

  # Sanity check
  jq -e '.specVersion == "1.5"' image.sbom.cdx.json
  ```

Feed the resulting `image.sbom.cdx.json` into your supply-chain tooling
(Dependency-Track, Grype, etc.) to keep tabs on advisories that affect this
specific build.

---

## 5. What to do on a mismatch

Treat any verification failure as a potential supply-chain compromise:

1. Stop deploying or running the affected artifact.
2. Capture the exact commands and output you used.
3. File a private report following `SECURITY.md` (do **not** open a public
   issue first — this prevents an attacker from observing your discovery).
4. Re-check from a different network and machine, and against the canonical
   fingerprints published on the project website.

---

## See also

- [`SECURITY.md`](../../SECURITY.md) — maintainer key fingerprint, contact
  channel, disclosure policy.
- [Release checklist](../release-checklist.md) — what the maintainer does
  before pushing a tag.
- Module L of the PRD — full quality & release strategy.
