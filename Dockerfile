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

# Guarantee the JS bundle path exists so the runtime COPY layer succeeds even
# when the JS bundle has not been built yet. Migrations are embedded into the
# binary via go:embed (see internal/storage/migrations) and need no copy.
RUN mkdir -p /src/web/dist

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
          -X main.Version=${VERSION} \
          -X main.Commit=${COMMIT} \
          -X main.BuildDate=${BUILD_DATE}" \
        -o /out/sealkeeper \
        ./cmd/sealkeeper

# Tiny Go health probe baked into the runtime image so distroless needs no
# curl/wget (FR-H.47). Source lives at cmd/healthcheck.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck

# ---------- 2) Runtime ----------
FROM gcr.io/distroless/static:nonroot

# OCI labels — release.yml overrides org.opencontainers.image.{version,revision}
LABEL org.opencontainers.image.title="SealKeeper" \
      org.opencontainers.image.description="ANSSI-compliant password distributor" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="SealKeeper" \
      org.opencontainers.image.source="https://github.com/sched75/SealKeeper" \
      org.opencontainers.image.documentation="https://sealkeeper.eu" \
      org.opencontainers.image.base.name="gcr.io/distroless/static:nonroot"

# Distroless `nonroot` is UID:GID 65532:65532 (FR-H.19)
USER 65532:65532

WORKDIR /app

COPY --from=builder --chown=65532:65532 /out/sealkeeper /usr/local/bin/sealkeeper
COPY --from=builder --chown=65532:65532 /out/healthcheck /usr/local/bin/healthcheck

# Static assets and migrations live next to the binary
COPY --from=builder --chown=65532:65532 /src/web/dist /app/web

EXPOSE 8443

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/healthcheck"]

ENTRYPOINT ["/usr/local/bin/sealkeeper"]
CMD ["serve"]
