# =============================================================================
# SealKeeper — developer Makefile
# =============================================================================
# Targets are POSIX-friendly: no bashisms, works on macOS and Linux. `make help`
# auto-generates the help screen from `## comments` next to each target.
# =============================================================================

SHELL          := /bin/sh
.SHELLFLAGS    := -eu -c
.ONESHELL:
.DEFAULT_GOAL  := help

GO             ?= go
DOCKER         ?= docker
HELM           ?= helm

VERSION        ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT         ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE_REPO     ?= ghcr.io/sched75-org/sealkeeper
IMAGE          ?= $(IMAGE_REPO):$(VERSION)

LDFLAGS         = -s -w \
                   -X main.Version=$(VERSION) \
                   -X main.Commit=$(COMMIT) \
                   -X main.BuildDate=$(BUILD_DATE)

# ----- Help -----------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@printf "SealKeeper — Makefile targets:\n"
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / { printf "  %-22s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\nVariables:\n  VERSION=%s\n  IMAGE=%s\n" "$(VERSION)" "$(IMAGE)"

# ----- Build ----------------------------------------------------------------

.PHONY: build
build: ## Build local binary into ./dist/sealkeeper
	mkdir -p dist
	$(GO) build -trimpath -buildvcs=true -ldflags "$(LDFLAGS)" -o dist/sealkeeper ./cmd/sealkeeper

.PHONY: build-all
build-all: ## Build linux+darwin × amd64+arm64 binaries
	mkdir -p dist
	for os in linux darwin; do \
	  for arch in amd64 arm64; do \
	    echo ">> $$os/$$arch"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	      $(GO) build -trimpath -buildvcs=true -ldflags "$(LDFLAGS)" \
	      -o dist/sealkeeper-$$os-$$arch ./cmd/sealkeeper; \
	  done; \
	done

# ----- Test -----------------------------------------------------------------

.PHONY: test
test: ## Run Go tests with race + coverage
	$(GO) test -race -covermode=atomic -coverprofile=coverage.out ./...

.PHONY: test-js
test-js: ## Run Vitest with coverage (web/)
	cd web && npm test -- --coverage

.PHONY: e2e
e2e: ## Run Playwright happy-path (Chromium only)
	cd tests/e2e && npx playwright test --project=chromium --grep="@happy-path"

# ----- Lint -----------------------------------------------------------------

.PHONY: lint
lint: ## Run golangci-lint, prettier, eslint, yamllint, markdownlint, hadolint
	golangci-lint run --config=.golangci.yml ./...
	if [ -d web ]; then cd web && npx prettier --check . && npx eslint . --max-warnings=0; fi
	yamllint -c .yamllint.yaml .
	markdownlint-cli2 "**/*.md" "!**/node_modules/**"
	hadolint --config .hadolint.yaml Dockerfile

.PHONY: fmt
fmt: ## gofmt + goimports + prettier
	gofmt -w .
	if command -v goimports >/dev/null; then goimports -w .; fi
	if [ -d web ]; then cd web && npx prettier --write .; fi

# ----- Docker / Compose ------------------------------------------------------

.PHONY: docker
docker: ## Build the OCI image locally
	$(DOCKER) build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t $(IMAGE) .

.PHONY: compose-up
compose-up: ## Start the Compose stack (auto-creates .env from .env.example if absent)
	test -f .env || cp .env.example .env
	$(DOCKER) compose up -d

.PHONY: compose-down
compose-down: ## Stop the Compose stack
	$(DOCKER) compose down

.PHONY: compose-logs
compose-logs: ## Tail SealKeeper logs
	$(DOCKER) compose logs -f sealkeeper

# ----- Helm ------------------------------------------------------------------

.PHONY: helm-lint
helm-lint: ## helm lint helm/sealkeeper
	$(HELM) lint helm/sealkeeper --set secret.masterSecret="$$(openssl rand -base64 32)"

.PHONY: helm-package
helm-package: ## Package the chart into chart-dist/
	mkdir -p chart-dist
	$(HELM) package helm/sealkeeper \
	  --version $(patsubst v%,%,$(VERSION)) \
	  --app-version $(patsubst v%,%,$(VERSION)) \
	  --destination chart-dist

# ----- Release bundle --------------------------------------------------------

.PHONY: release-bundle
release-bundle: build-all helm-package ## Assemble a local release bundle (binaries + chart + manifests + compose)
	mkdir -p bundle
	ROOT=bundle/sealkeeper-deploy-$(patsubst v%,%,$(VERSION))
	rm -rf $$ROOT
	mkdir -p $$ROOT/k8s $$ROOT/examples/caddy $$ROOT/examples/traefik $$ROOT/examples/nginx $$ROOT/helm $$ROOT/binaries
	cp docker-compose.yml .env.example $$ROOT/
	cp examples/caddy/Caddyfile $$ROOT/examples/caddy/
	cp examples/traefik/docker-compose.traefik.yml $$ROOT/examples/traefik/
	cp examples/nginx/sealkeeper.conf $$ROOT/examples/nginx/
	cp -r k8s/. $$ROOT/k8s/
	cp chart-dist/sealkeeper-*.tgz $$ROOT/helm/
	cp dist/sealkeeper-* $$ROOT/binaries/
	(cd $$ROOT/binaries && sha256sum sealkeeper-* > ../SHA256SUMS)
	cp QUICKSTART.md $$ROOT/README-DEPLOY.md
	if [ -f LICENSE ]; then cp LICENSE $$ROOT/LICENSE; fi
	(cd bundle && tar -czf sealkeeper-deploy-$(patsubst v%,%,$(VERSION)).tar.gz sealkeeper-deploy-$(patsubst v%,%,$(VERSION)))
	(cd bundle && zip -rq sealkeeper-deploy-$(patsubst v%,%,$(VERSION)).zip sealkeeper-deploy-$(patsubst v%,%,$(VERSION)))
	@echo
	@echo "Bundle ready:"
	@ls -lh bundle/sealkeeper-deploy-$(patsubst v%,%,$(VERSION)).*

# ----- Misc ------------------------------------------------------------------

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build outputs
	rm -rf dist bundle chart-dist coverage.out web/coverage tests/e2e/test-results tests/e2e/playwright-report

.PHONY: pre-commit
pre-commit: ## Run all pre-commit hooks on the entire tree
	pre-commit run --all-files
