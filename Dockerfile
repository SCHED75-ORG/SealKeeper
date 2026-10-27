# syntax=docker/dockerfile:1.7
# =============================================================================
# SealKeeper — production image
# =============================================================================
# PRD:
#   - FR-H.18, D-H.1   distroless/static base, image < 50 MB
#   - FR-H.19          non-root user UID 65532
#   - FR-H.16          multi-arch linux/amd64 + linux/arm64 (build via buildx)
#   - FR-H.47          internal Go-based healthcheck (no curl/wget in runtime)
#   - FR-L.68          reproducible build: -trimpath, -buildvcs, pinned ldflags
#   - FR-L.44          Dockerfile must pass hadolint
# DECISION: builder image pinned to specific patch; cosign cosign-friendly
#   OCI labels are set in release.yml at push time (org.opencontainers.image.*).
# =============================================================================

# ---------- 0) JS generation bundle ----------
# The reveal page and the admin entropy preview load
# /static/sealkeeper-generation.umd.js. web/dist is gitignored, so the bundle
# MUST be built here from web/src + the committed lockfile — otherwise a fresh
# checkout (release.yml) ships an image with an empty /app/web.
# DECISION: node image pinned by multi-arch index digest (reproducible input);
#   run on $BUILDPLATFORM because the output is architecture-independent JS.
#   `npm ci --ignore-scripts` installs exactly package-lock.json and runs no
#   dependency lifecycle scripts. Only web/ manifests + sources are copied so a
#   developer's local node_modules or stale dist can never leak in.
FROM --platform=$BUILDPLATFORM node:22.22.3-alpine3.22@sha256:cd7807368cf24826297cbad5dca1a44972ccfd770647db52a8c7589eb4599ac8 AS webbuild

WORKDIR /web

COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY web/vite.config.js ./
COPY web/src ./src
RUN npm run build \
 && test -s dist/sealkeeper-generation.umd.js

# ---------- 1) Builder ----------
FROM golang:1.26.10-alpine3.23 AS builder

ENV CGO_ENABLED=0 \
    GOFLAGS="-trimpath -buildvcs=true"

# git is required by -buildvcs=true so the VCS stamp lands in the binary.
# Alpine ships without it; hadolint-friendly --no-cache install.
RUN apk add --no-cache git

WORKDIR /src

# Cache modules layer separately from sources
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy sources
COPY . .

# Migrations are embedded into the binary via go:embed (see
# internal/storage/migrations) and need no copy. The JS bundle comes from the
# webbuild stage, never from the build context.

# Build args (set by buildx from --platform and by the release workflow)
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# DECISION: a single static binary covers `sealkeeper serve`, `migrate`, `backup`
# and admin sub-commands (D-D.x cmd/ structure).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build \
        -ldflags="-s -w \
          -X github.com/sched75/sealkeeper/internal/version.Version=${VERSION} \
          -X github.com/sched75/sealkeeper/internal/version.Commit=${COMMIT} \
          -X github.com/sched75/sealkeeper/internal/version.BuildDate=${BUILD_DATE}" \
        -o /out/sealkeeper \
        ./cmd/sealkeeper

# Tiny Go health probe baked into the runtime image so distroless needs no
# curl/wget (FR-H.47). Source lives at cmd/healthcheck.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck

# Writable data root. The runtime image is distroless (no mkdir) and the
# root filesystem is read-only in every shipped deployment (FR-H.70), so
# /data/libraries is created here and copied in owned by 65532: a fresh
# named volume mounted on /data inherits that ownership.
RUN mkdir -p /out/data/libraries

# ---------- 2) Runtime ----------
FROM gcr.io/distroless/static:nonroot

# OCI labels — release.yml overrides org.opencontainers.image.{version,revision}
LABEL org.opencontainers.image.title="SealKeeper" \
      org.opencontainers.image.description="ANSSI-compliant password distributor" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="SealKeeper" \
      org.opencontainers.image.source="https://github.com/SCHED75-ORG/SealKeeper" \
      org.opencontainers.image.documentation="https://sealkeeper.eu" \
      org.opencontainers.image.base.name="gcr.io/distroless/static:nonroot"

# Distroless `nonroot` is UID:GID 65532:65532 (FR-H.19)
USER 65532:65532

WORKDIR /app

COPY --from=builder --chown=65532:65532 /out/sealkeeper /usr/local/bin/sealkeeper
COPY --from=builder --chown=65532:65532 /out/healthcheck /usr/local/bin/healthcheck

# JS generation bundle, built from source in the webbuild stage
COPY --from=webbuild --chown=65532:65532 /web/dist /app/web

# Uploaded libraries live on the /data volume, not under the read-only
# WORKDIR (the config default "data/libraries" is relative to /app).
COPY --from=builder --chown=65532:65532 /out/data /data
ENV SK_LIBRARIES_DIR=/data/libraries

EXPOSE 8443

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/healthcheck"]

ENTRYPOINT ["/usr/local/bin/sealkeeper"]
CMD ["serve"]
