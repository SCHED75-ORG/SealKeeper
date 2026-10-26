# Kubernetes manifests

Vanilla manifests for deploying SealKeeper on any conformant cluster.
For a templated, configurable variant, prefer the Helm chart in `../helm/`.

## Layout

| File | Purpose |
|------|---------|
| `namespace.yaml` | `sealkeeper` namespace with Pod Security Admission in `restricted` mode |
| `serviceaccount.yaml` | Dedicated SA, no auto-mounted token |
| `configmap.yaml` | Non-sensitive SK_* runtime config |
| `secret.example.yaml` | **Reference only** — documents the keys of the `sealkeeper` Secret (SK_MASTER_SECRET, SK_DATABASE_URL, SK_METRICS_TOKEN). Not included in `kustomization.yaml`; create the Secret out of band |
| `deployment.yaml` | App `Deployment` (FR-H.30): 2 replicas, rolling update, readOnlyRoot, drop ALL, probes on `/healthz` + `/readyz` |
| `service.yaml` | `ClusterIP` on 8443 |
| `ingress.yaml` | `Ingress` for ingress-nginx, TLS via cert-manager (annotation commented) |
| `networkpolicy.yaml` | Default-deny + targeted allow (ingress controller → 8443, egress to DNS, PG, SMTP, SIEM) |
| `poddisruptionbudget.yaml` | `minAvailable: 1` for zero-downtime drains |
| `kustomization.yaml` | Bundles everything for `kubectl apply -k .` |

## Apply

```bash
# 1. Create the Secret out-of-band — it is NOT part of kustomization.yaml,
#    so a placeholder master key can never be deployed by `apply -k`.
#    (Or let External Secrets / Sealed Secrets create `sealkeeper`.)
kubectl apply -f namespace.yaml
kubectl -n sealkeeper create secret generic sealkeeper \
  --from-literal=SK_MASTER_SECRET="$(openssl rand -base64 32)" \
  --from-literal=SK_DATABASE_URL='postgres://sealkeeper:<password>@<host>:5432/sealkeeper?sslmode=verify-full'
# Back up SK_MASTER_SECRET in your vault now: losing it makes the stored
# TOTP seeds and SMTP relay password unrecoverable.

# 2. Set SK_TRUSTED_PROXY_CIDRS in configmap.yaml to your ingress
#    controller's pod CIDR (see "Client IP and trusted proxies" below).

# 3. Apply everything
kubectl apply -k .

# 4. Watch rollout
kubectl -n sealkeeper rollout status deploy/sealkeeper
```

## Bring your own database

`secret.example.yaml` documents an `SK_DATABASE_URL` pointing at a
PostgreSQL service inside the same namespace. SealKeeper does **not**
provision a database — pick one of:

- **CloudNativePG** (recommended): `kubectl apply -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/main/releases/cnpg-1.24.1.yaml`
  then declare a `Cluster` in the `sealkeeper` namespace.
- **Zalando postgres-operator**.
- A managed offering (RDS, Cloud SQL, Azure Flexible Server). Update the
  `SK_DATABASE_URL` value accordingly and prefer `sslmode=verify-full`.

## Migrations

Schema migrations are forward-only (FR-H.61, D-D.13). The recommended path on
upgrade:

```bash
# Pull the new image
kubectl -n sealkeeper set image deploy/sealkeeper sealkeeper=ghcr.io/sealkeeper/sealkeeper:vX.Y.Z

# Run migrations from a one-shot Job (the binary's `migrate up` sub-command)
kubectl -n sealkeeper run sk-migrate --rm -it --restart=Never \
  --image=ghcr.io/sealkeeper/sealkeeper:vX.Y.Z \
  --env="SK_DATABASE_URL=$(kubectl -n sealkeeper get secret sealkeeper -o jsonpath='{.data.SK_DATABASE_URL}' | base64 -d)" \
  -- migrate up
```

Once migrations succeed, the rolling update completes itself.

## NetworkPolicy notes

`networkpolicy.yaml` is conservative: ingress is allowed only from the
`ingress-nginx` namespace. If your ingress controller lives elsewhere (Cilium,
Istio gateway, AWS Load Balancer Controller), edit the namespace label
selector to match. The egress SMTP/SIEM CIDRs are intentionally broad —
narrow them to the actual IPs of your relay and SIEM forwarder.
