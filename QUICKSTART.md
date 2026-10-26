# SealKeeper — Quickstart

Three ways to get SealKeeper running. Pick one.

## 1. Evaluation (5 seconds, no config)

```bash
docker run --rm -p 8443:8443 -e SK_MODE=eval \
  ghcr.io/sealkeeper/sealkeeper:latest
```

Open <http://localhost:8443/>.

**What you get** (FR-H.11..19):

- SQLite at `/data/sealkeeper.db` inside the container (lost on `--rm`).
- A master secret is auto-generated at boot — visible in the logs.
- Bootstrap admin password printed at startup. Grep for `bootstrap admin password`.
- An orange banner reminds you this is not production.
- SMTP is captured locally — view the queue at <http://localhost:8443/__captured_mail>.
- A self-signed certificate is generated on demand if you proxy in front; for direct browser access we serve plain HTTP on 8443.

**Stop**: <kbd>Ctrl-C</kbd>. Nothing persists.

---

## 2. Production simple (Docker Compose)

Prerequisites: Docker ≥ 24 and Docker Compose v2.

```bash
git clone https://github.com/sched75/SealKeeper.git
cd SealKeeper

cp .env.example .env
${EDITOR:-vi} .env
# At minimum: SK_BASE_URL, SK_DOMAIN, SK_MASTER_SECRET, POSTGRES_PASSWORD, ACME_EMAIL

# Generate the master secret once and paste it into .env:
openssl rand -base64 32

docker compose up -d
docker compose logs -f sealkeeper
```

Caddy will obtain a real TLS certificate for `SK_DOMAIN` automatically (you need a public DNS record pointing at the host and port 80 + 443 reachable from the Internet).

**Verify**:

```bash
curl -fsS https://${SK_DOMAIN}/healthz   # 200 OK
```

**Upgrade**:

```bash
docker compose pull
docker compose up -d
```

**Stop and remove everything**:

```bash
docker compose down -v   # -v drops volumes — keep them off in production
```

### Alternate reverse proxies

| Reverse proxy | Path |
|---|---|
| Traefik | `examples/traefik/docker-compose.traefik.yml` |
| Nginx | `examples/nginx/sealkeeper.conf` (drop into `/etc/nginx/conf.d/`) |
| WAF guidance | `docs/deployment/waf.md` |

---

## 3. Kubernetes (Helm)

Prerequisites: Kubernetes ≥ 1.27, Helm ≥ 3.14, an ingress controller, and a PostgreSQL 16 instance reachable from the cluster.

```bash
git clone https://github.com/sched75/SealKeeper.git
cd SealKeeper

# 1. Create the namespace (PSA-restricted)
kubectl apply -f k8s/namespace.yaml

# 2. Provision your secret out of band — example using kubectl directly.
#    In production prefer ExternalSecrets / SealedSecrets.
kubectl -n sealkeeper create secret generic sealkeeper \
  --from-literal=SK_MASTER_SECRET="$(openssl rand -base64 32)" \
  --from-literal=SK_DATABASE_URL='postgres://sealkeeper:CHANGEME@postgres.sealkeeper.svc.cluster.local:5432/sealkeeper?sslmode=require'

# 3. Install the chart
helm upgrade --install sealkeeper helm/sealkeeper \
  --namespace sealkeeper \
  --set secret.create=false \
  --set secret.existingSecret=sealkeeper \
  --set config.baseUrl=https://sealkeeper.example.com \
  --set ingress.hosts[0].host=sealkeeper.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix \
  --set ingress.tls[0].secretName=sealkeeper-tls \
  --set ingress.tls[0].hosts[0]=sealkeeper.example.com

# 4. Watch the rollout
kubectl -n sealkeeper rollout status deploy/sealkeeper
```

### Bare-Kubernetes alternative

If you prefer vanilla manifests over Helm:

```bash
# Steps 1–2 above (namespace + Secret) first: the kustomization does not ship
# a Secret, so no placeholder master key can be deployed by accident.
kubectl apply -k k8s/
```

`k8s/secret.example.yaml` only documents the expected keys; it is not part of `k8s/kustomization.yaml`. Set `SK_TRUSTED_PROXY_CIDRS` in `k8s/configmap.yaml` to your ingress controller's pod CIDR before applying.

---

## Verifying release artifacts

We sign everything. Before running a binary, verify the GPG signature on `SHA256SUMS`; before deploying an image, verify the cosign keyless signature and SLSA provenance. The full runbook is in [`docs/security/verification.md`](docs/security/verification.md).

```bash
TAG=v0.1.0
cosign verify \
  --certificate-identity "https://github.com/sched75/SealKeeper/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/sealkeeper/sealkeeper:${TAG}

gh attestation verify oci://ghcr.io/sealkeeper/sealkeeper:${TAG} --repo sched75/SealKeeper \
  --signer-workflow sched75/SealKeeper/.github/workflows/release.yml --source-ref "refs/tags/${TAG}"
```

---

## Where to go next

- [Release verification guide](docs/security/verification.md)
- [Release checklist (maintainers)](docs/release-checklist.md)
- [Product Requirements Document (PRD)](docs/prd/README.md)
- Issues and questions: <https://github.com/sched75/SealKeeper/issues>
