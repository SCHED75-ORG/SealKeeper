# Module H — Déploiement

**Statut** : validé
**Version** : 1.1
**Dernière mise à jour** : 2026-10-28
**Auteur** : Pascal-Louis Darmon (assisté par Daneel / Claude)
**Dépendances** : modules D (binaire et CLI), E (TLS, WAF), G (endpoints à exposer) ; alimente L (release process)

---

## 1. Purpose

Ce module spécifie les **modes de déploiement** supportés par SealKeeper, les **artefacts livrés** à chaque release, la **configuration recommandée** des composants externes (reverse proxy, base de données, observabilité), les **procédures de mise à jour**, **backup / restore** et **bascule en mode maintenance**.

Trois modes de déploiement sont supportés :

- **Mode évaluation** : conteneur Docker autonome avec SQLite, SMTP capture, bootstrap automatique.
- **Mode production simple** : Docker Compose avec PostgreSQL, Caddy reverse proxy, volumes nommés.
- **Mode production Kubernetes** : Helm chart, ConfigMap, Secret, Ingress, NetworkPolicy.

---

## 2. Actors and use cases

| Acteur | Interaction |
|---|---|
| Évaluateur (DSI, RSSI, dev) | Lance `docker run` pour tester en local en quelques minutes |
| Admin déploiement (DevOps, SRE) | Configure production, gère le cycle de vie, sauvegardes, mises à jour |
| Système de monitoring | Scrape `/metrics`, alerte sur `/readyz` |
| Reverse proxy (Caddy / Traefik / Nginx) | Termine TLS, route vers le binaire, applique optionnellement un WAF |
| Système de backup | Sauvegarde la base + volume `data/` + secrets |

---

## 3. Functional requirements

### 3.1 Artefacts livrés à chaque release

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.1 | Une release publie systématiquement les artefacts suivants : | MUST |
| FR-H.2 | **Binaire Go statique** pour `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64` | MUST |
| FR-H.3 | **Image OCI** publiée sur le registry GitHub (`ghcr.io/sched75-org/sealkeeper:<version>` et `:latest`) | MUST |
| FR-H.4 | **Helm chart** publié sur le repo Helm (`https://sealkeeper.eu/charts`) | MUST |
| FR-H.5 | **Manifests Kubernetes vanilla** (Deployment, Service, Ingress, ConfigMap, Secret de référence) téléchargeables en tarball | SHOULD |
| FR-H.6 | **docker-compose.yml de référence** dans le repo et téléchargeable | MUST |
| FR-H.7 | **Caddyfile, Traefik et Nginx de référence** dans `examples/reverse-proxy/` | MUST |
| FR-H.8 | **Checksums SHA-256** signés GPG (clé du mainteneur) pour tous les binaires et tarballs | MUST |
| FR-H.9 | **Notes de release** détaillées (changelog, breaking changes, instructions de migration) | MUST |
| FR-H.10 | **Reproducible builds** : le binaire est rebuildable à l'identique depuis le tag Git (📋 v0.3 : SLSA niveau 3 attestation) | SHOULD |

### 3.2 Mode évaluation (Docker single-binary)

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.11 | L'image OCI permet un démarrage en une commande : `docker run --rm -p 8443:8443 -e SK_MODE=eval ghcr.io/sched75-org/sealkeeper:latest` | MUST |
| FR-H.12 | Le mode `SK_MODE=eval` active : SQLite embarqué (fichier `/data/sealkeeper.db`), SMTP capture (table `captured_mail` + UI), TLS auto-généré (certificat self-signed à la volée), bootstrap admin avec mot de passe dans les logs | MUST |
| FR-H.13 | Un volume Docker `data` est monté sur `/data` (DB + bibliothèques) pour persister entre runs | MUST |
| FR-H.14 | Le master secret (`SK_MASTER_SECRET`) est auto-généré au premier démarrage et écrit dans `/data/.master_secret` avec warning visible | MUST |
| FR-H.15 | Le mode eval est **explicitement marqué** dans toutes les pages (bandeau orange *« Mode évaluation — ne pas utiliser en production »*) | MUST |
| FR-H.16 | Le mode eval expose la section *Captured mail* en console admin (FR-C.63) | MUST |
| FR-H.17 | Aucune connexion sortante (vers SMTP, vers SIEM) n'est tentée en mode eval, même si configurée | MUST |
| FR-H.18 | Image de référence est **basée sur `distroless/static`** ou `scratch`, < 50 MB | MUST |
| FR-H.19 | L'utilisateur dans le conteneur est non-root (UID 65532 = `nonroot` distroless) | MUST |

### 3.3 Mode production simple — Docker Compose

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.20 | Un fichier `docker-compose.yml` de référence est fourni, démarrant : SealKeeper, PostgreSQL 16, Caddy comme reverse proxy | MUST |
| FR-H.21 | Le compose utilise des **volumes nommés** pour : `sealkeeper-data` (libraries), `postgres-data` (DB), `caddy-data` (certificats Let's Encrypt) | MUST |
| FR-H.22 | Le PostgreSQL est sur un **réseau Docker interne** non exposé à l'extérieur | MUST |
| FR-H.23 | Le master secret est fourni via fichier `.env` (template `.env.example` livré) | MUST |
| FR-H.24 | Healthcheck Docker sur SealKeeper : `curl -fsS http://localhost:8443/healthz || exit 1`, interval 10s, timeout 5s, retries 3 | MUST |
| FR-H.25 | Le compose configure `restart: unless-stopped` sur les trois services | MUST |
| FR-H.26 | Logs JSON via le driver Docker par défaut, rotation configurée (`max-size: 10m`, `max-file: 3`) | MUST |
| FR-H.27 | Le compose expose **uniquement le port 443** sur Caddy (TLS terminé par Caddy), pas de port direct sur SealKeeper | MUST |

### 3.4 Mode production avancé — Kubernetes (Helm)

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.28 | Un **Helm chart** est livré, compatible Helm 3.x | MUST |
| FR-H.29 | Le chart contient les templates : `deployment.yaml`, `service.yaml`, `ingress.yaml`, `configmap.yaml`, `secret.yaml`, `serviceaccount.yaml`, `networkpolicy.yaml`, `poddisruptionbudget.yaml`, `servicemonitor.yaml` (si Prometheus Operator présent) | MUST |
| FR-H.30 | Le chart utilise un **Deployment** (pas StatefulSet), avec backend PostgreSQL externe au cluster ou via opérateur (cf. CloudNativePG, Zalando) | MUST |
| FR-H.31 | Le master secret est stocké dans un **Kubernetes Secret** (non chiffré par défaut, à coupler avec External Secrets Operator, Sealed Secrets, ou KMS selon contexte client) | MUST |
| FR-H.32 | **NetworkPolicy** par défaut : ingress depuis Ingress controller uniquement, egress vers PostgreSQL + SMTP relay + intégrations SIEM configurées | MUST |
| FR-H.33 | **PodSecurityContext** strict : `runAsNonRoot: true`, `runAsUser: 65532`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` | MUST |
| FR-H.34 | Volume `emptyDir` ou PVC pour `/data` (PVC recommandé en production) | MUST |
| FR-H.35 | Liveness probe : `httpGet /healthz`, initialDelaySeconds=10, periodSeconds=30. Readiness probe : `httpGet /readyz`, initialDelaySeconds=5, periodSeconds=10 | MUST |
| FR-H.36 | **PodDisruptionBudget** : `minAvailable: 1` si la cible est haute disponibilité ; à ajuster selon réplicas | SHOULD |
| FR-H.37 | **HorizontalPodAutoscaler** : 📋 v0.3 (nécessite sessions Redis multi-instance, cf. D-D.20) | 📋 v0.3 |
| FR-H.38 | **ServiceMonitor** ou **PodMonitor** Prometheus Operator détecte `/metrics` automatiquement si annoté | SHOULD |

### 3.5 Configuration via variables d'environnement

Référence canonique : module D §3.9. Liste exhaustive ici pour le déploiement.

| Variable | Défaut | Description |
|---|---|---|
| `SK_MODE` | `production` | `eval` ou `production` |
| `SK_BASE_URL` | (requis) | URL publique de l'instance, ex : `https://sealkeeper.entreprise.com` |
| `SK_HTTP_LISTEN` | `:8443` | Adresse d'écoute Go |
| `SK_DATABASE_URL` | `sqlite:///data/sealkeeper.db` (eval) | DSN SQLite ou PostgreSQL |
| `SK_MASTER_SECRET` | (requis prod) | 32 octets base64 |
| `SK_METRICS_TOKEN` | vide | Token bearer optionnel pour `/metrics` |
| `SK_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `SK_LOG_FORMAT` | `json` (prod), `text` (eval) | Format des logs slog |
| `SK_CONFIG_FILE` | `/etc/sealkeeper/config.yaml` | Path optionnel vers config YAML |
| `SK_MAX_LIBRARY_SIZE_MB` | `10` | Taille max upload bibliothèque |
| `SK_MAX_ACTIVE_SESSIONS` | `10000` | Limite sessions simultanées |
| `SK_SESSION_TTL_SECONDS` | `900` | TTL par défaut sessions utilisateur (15 min) |
| `SK_ADMIN_SESSION_TTL_SECONDS` | `28800` | TTL session admin (8h) |
| `SK_ADMIN_SESSION_IDLE_SECONDS` | `1800` | Idle timeout admin (30 min) |
| `SK_TRUSTED_PROXY_CIDRS` | vide | CIDRs des reverse proxies de confiance (pour `X-Forwarded-For`) |
| `SK_SWAGGER_UI_ENABLED` | `false` (prod), `true` (eval) | Active `/api/docs` Swagger UI |

### 3.6 Reverse proxy

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.39 | SealKeeper s'attend à fonctionner **derrière un reverse proxy** qui termine TLS et fournit les certificats Let's Encrypt | MUST |
| FR-H.40 | Le binaire écoute par défaut sur `0.0.0.0:8443` en HTTP plain (pas TLS), à raccorder au reverse proxy via réseau privé | MUST |
| FR-H.41 | Mode standalone TLS optionnel via `SK_TLS_CERT_FILE` + `SK_TLS_KEY_FILE` (cas où aucun reverse proxy n'est utilisé) | SHOULD |
| FR-H.42 | Le header `X-Forwarded-For` est honoré uniquement si l'IP source est dans `SK_TRUSTED_PROXY_CIDRS` | MUST |
| FR-H.43 | **Caddyfile de référence** livré dans `examples/caddy/Caddyfile` | MUST |
| FR-H.44 | **Traefik labels Docker** de référence livrés dans `examples/traefik/docker-compose.traefik.yml` | MUST |
| FR-H.45 | **Nginx config** de référence livrée dans `examples/nginx/sealkeeper.conf` | MUST |
| FR-H.46 | Documentation **WAF optionnel** (Cloudflare, ModSecurity, AWS WAF) dans `docs/deployment/waf.md` | SHOULD |

**Exemple Caddyfile minimal**

```
sealkeeper.entreprise.com {
  reverse_proxy sealkeeper:8443
  encode gzip zstd
  log {
    output file /var/log/caddy/sealkeeper-access.log
    format json
  }
  header /static/* {
    Cache-Control "public, max-age=31536000, immutable"
  }
}
```

### 3.7 Healthchecks et probes (référence module D §3.7)

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.47 | Docker `HEALTHCHECK` instruction dans le Dockerfile : `CMD ["wget", "-qO-", "http://localhost:8443/healthz", "||", "exit", "1"]` (avec un binaire wget ou curl ajouté à l'image — sinon healthcheck externe par Docker Compose) | SHOULD |
| FR-H.48 | Kubernetes liveness probe : `httpGet /healthz` | MUST |
| FR-H.49 | Kubernetes readiness probe : `httpGet /readyz` | MUST |
| FR-H.50 | Aucune probe ne consomme de ressources DB (FR-D.49 garantit que `/healthz` est instant) | MUST |

### 3.8 Backup et restore

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.51 | Documentation **détaillée** dans `docs/operations/backup-restore.md` couvrant les trois modes (eval, Docker Compose, Kubernetes) | MUST |
| FR-H.52 | **Données à sauvegarder** : (1) base de données complète, (2) `data/libraries/*`, (3) master secret (stocké hors instance), (4) configuration des intégrations exportées en JSON | MUST |
| FR-H.53 | CLI `sealkeeper backup create --output <path>` produit un **tarball signé** contenant la DB + le dossier libraries. Le master secret n'est PAS inclus (responsabilité opérateur) | MUST |
| FR-H.54 | CLI `sealkeeper backup restore --input <path>` valide la signature, restaure la DB + libraries, exige confirmation `--yes` | MUST |
| FR-H.55 | Pour PostgreSQL en production, recommandation : utiliser `pg_dump` + WAL archiving (point-in-time recovery), pas le CLI SealKeeper | MUST |
| FR-H.56 | Fréquence recommandée : **quotidienne**, rétention 30 jours, off-site (S3 / Azure Blob / GCS) | MUST |
| FR-H.57 | Test de restauration **mensuel** recommandé dans la doc | SHOULD |
| FR-H.58 | Backup automatisé natif via S3 : 📋 v0.3 (intégration `restic` ou `borg` externe pour l'instant) | 📋 v0.3 |

### 3.9 Mises à jour

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.59 | Le versioning suit **SemVer 2.0** : `MAJOR.MINOR.PATCH` | MUST |
| FR-H.60 | Une mise à jour `PATCH` (ex : 0.1.0 → 0.1.1) est rétro-compatible, sans migration DB | MUST |
| FR-H.61 | Une mise à jour `MINOR` (0.1 → 0.2) peut introduire des migrations DB **forward-only** | MUST |
| FR-H.62 | Une mise à jour `MAJOR` (1.0 → 2.0) peut casser l'API ; cohabitation `/api/v1/` et `/api/v2/` documentée sur la version `MAJOR-1` | MUST |
| FR-H.63 | Procédure de mise à jour **standard** : (1) backup, (2) activer mode maintenance, (3) pull nouvelle image, (4) `sealkeeper migrate up`, (5) restart, (6) désactiver maintenance | MUST |
| FR-H.64 | Procédure **zero-downtime** (Kubernetes) : rolling update avec PodDisruptionBudget, à condition que les migrations soient compatibles avec l'ancien binaire (additive only) | SHOULD |
| FR-H.65 | Les migrations qui **brisent** la compatibilité avec l'ancien binaire sont précédées d'une release intermédiaire qui prépare le terrain (pattern *expand-contract*) | SHOULD |
| FR-H.66 | Rollback : **uniquement par restore de backup**. Les migrations ne sont jamais inversées | MUST |
| FR-H.67 | Notes de release détaillent toujours les opérations à effectuer (variables d'env nouvelles, migrations, breaking changes) | MUST |

### 3.10 Sécurité du déploiement

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.68 | **Utilisateur non-root** dans le conteneur (UID 65532 standard distroless) | MUST |
| FR-H.69 | Image basée sur **`distroless/static`** ou **`scratch`** ; pas de shell, pas d'outils système | MUST |
| FR-H.70 | **`readOnlyRootFilesystem: true`** ; seuls les volumes `/data` et `/tmp` sont writable | MUST |
| FR-H.71 | **Capabilities Linux** : toutes droppées (`capabilities.drop: [ALL]`) | MUST |
| FR-H.72 | **Limites de ressources** recommandées : `memory: 256Mi` (request) / `512Mi` (limit), `cpu: 100m` (request) / `500m` (limit) | SHOULD |
| FR-H.73 | **Mode maintenance** : activable via `POST /api/v1/admin/system/maintenance` ou via variable d'env `SK_MAINTENANCE_MODE=true` au boot. Renvoie 503 + message custom sur les routes publiques | MUST |
| FR-H.74 | Bannière de mode maintenance visible en console admin | MUST |
| FR-H.75 | **Pas de port DB exposé** publiquement | MUST |
| FR-H.76 | **TLS 1.2+ obligatoire** côté reverse proxy ; configurations de référence le respectent | MUST |
| FR-H.77 | Documentation explicite : SealKeeper **NE chiffre pas** les communications inter-services (DB, SMTP) — la responsabilité revient à l'orchestrateur (réseau privé, mTLS via service mesh, etc.) | MUST |

### 3.11 Instance démo publique (optionnelle)

| ID | Exigence | Niveau |
|---|---|---|
| FR-H.78 | Mode démo public **désactivé par défaut** ; activable via `SK_DEMO_MODE=true` | MUST |
| FR-H.79 | En mode démo : rate-limit agressif (1 demande / IP / heure), reset complet de la DB toutes les 24h, aucun SMTP réel (capture seulement), bandeau permanent *« Instance démo — toutes les données sont publiques et purgées quotidiennement »* | MUST |
| FR-H.80 | Aucune intégration SIEM activable en mode démo (refus en console) | MUST |
| FR-H.81 | Aucun upload de bibliothèque autorisé en mode démo (seules les bibliothèques système actives) | MUST |
| FR-H.82 | Pas d'instance démo hébergée par les mainteneurs en v0.1 (préserve les ressources) ; mode disponible pour quiconque souhaite l'héberger | 📋 SHOULD |

---

## 4. Non-functional requirements

| Type | Cible |
|---|---|
| Taille image OCI | < 50 MB (distroless/static) |
| Cold start | < 2 secondes (binaire + connexion DB) |
| Empreinte mémoire eval | < 100 MB RAM |
| Empreinte mémoire prod (< 100 domaines) | < 200 MB RAM |
| Zero-downtime sur PATCH | Toujours (pas de migration) |
| Zero-downtime sur MINOR | Effort raisonnable (rolling update si migration compatible) |
| TLS | 1.2 minimum, 1.3 préféré (alignement module E) |
| Logs | Format JSON structuré en prod, lisible humain en eval |
| Reproducible build | v0.3 (SLSA niveau 3 visé) |

---

## 5. Data model

### 5.1 Topologie de déploiement production type

```mermaid
graph TB
    Internet([Internet])
    LB[Load Balancer<br/>+ TLS termination<br/>+ WAF optionnel]
    Ingress[Ingress Controller<br/>Kubernetes]
    SK1[SealKeeper Pod 1]
    SK2[SealKeeper Pod 2]
    PG[(PostgreSQL<br/>+ replica)]
    SMTP[SMTP relay<br/>postfix / SES / etc.]
    SIEM[SIEM<br/>Splunk / Sentinel / Elastic]
    Prom[Prometheus]
    Graf[Grafana]
    Backup[Backup storage<br/>S3 / Azure Blob]

    Internet --> LB
    LB --> Ingress
    Ingress --> SK1
    Ingress --> SK2
    SK1 --> PG
    SK2 --> PG
    SK1 --> SMTP
    SK2 --> SMTP
    SK1 --> SIEM
    SK2 --> SIEM
    Prom -.->|"scrape"| SK1
    Prom -.->|"scrape"| SK2
    Graf --> Prom
    PG -.->|"dump"| Backup

    style SK1 fill:#7A1F2B,color:#F4EFE6
    style SK2 fill:#7A1F2B,color:#F4EFE6
```

### 5.2 Volumes et fichiers à persister

```mermaid
flowchart LR
    SK[Container SealKeeper]
    Data["/data"]
    Tmp["/tmp"]
    DB["data/sealkeeper.db<br/>(SQLite eval seul)"]
    Lib["data/libraries/*.txt<br/>(dictionnaires + corpus uploadés)"]
    Master["data/.master_secret<br/>(eval seulement)"]
    Captured["data/captured-mail/<br/>(eval seulement)"]

    SK -- read/write --> Data
    SK -- read/write --> Tmp
    Data --> DB
    Data --> Lib
    Data --> Master
    Data --> Captured

    style Data fill:#C9A961,color:#1A1814
```

### 5.3 Schéma de réseau Kubernetes

```mermaid
graph TB
    subgraph Public
        Internet([Internet])
    end

    subgraph IngressNS[Namespace ingress-system]
        IC[Ingress Controller<br/>nginx / traefik]
    end

    subgraph SKNS[Namespace sealkeeper]
        SK[Pods SealKeeper]
        SVC[Service ClusterIP]
        NP[NetworkPolicy:<br/>ingress depuis IC seul<br/>egress vers PG + SMTP + SIEM]
    end

    subgraph DBNS[Namespace database]
        PG[PostgreSQL]
    end

    subgraph MonNS[Namespace monitoring]
        Prom[Prometheus]
        Graf[Grafana]
    end

    Internet -->|443/TLS| IC
    IC --> SVC
    SVC --> SK
    SK -->|5432| PG
    SK -->|587/465| SMTP[(SMTP externe)]
    SK -->|443/514| SIEM[(SIEM externe)]
    Prom -.->|"scrape"| SK
    Graf --> Prom
```

---

## 6. Interfaces

### 6.1 Structure du Helm chart

Le chart Helm `sealkeeper` est organisé ainsi :

- `Chart.yaml` — métadonnées (version, dépendances)
- `values.yaml` — valeurs par défaut
- `templates/deployment.yaml`
- `templates/service.yaml`
- `templates/ingress.yaml`
- `templates/configmap.yaml`
- `templates/secret.yaml`
- `templates/serviceaccount.yaml`
- `templates/networkpolicy.yaml`
- `templates/poddisruptionbudget.yaml`
- `templates/servicemonitor.yaml` (conditionnel sur la présence de Prometheus Operator)
- `templates/_helpers.tpl`
- `templates/NOTES.txt`

**Exemple `values.yaml` minimal** :

```yaml
image:
  repository: ghcr.io/sched75-org/sealkeeper
  tag: 0.1.0
  pullPolicy: IfNotPresent

replicaCount: 2

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: sealkeeper.entreprise.com
      paths: ["/"]
  tls:
    - hosts: [sealkeeper.entreprise.com]
      secretName: sealkeeper-tls

database:
  externalUrl: postgres://sealkeeper:password@postgres.database.svc:5432/sealkeeper?sslmode=require

masterSecret:
  fromExistingSecret: sealkeeper-master-secret

resources:
  requests:
    memory: 256Mi
    cpu: 100m
  limits:
    memory: 512Mi
    cpu: 500m

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65532
  fsGroup: 65532

securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
```

### 6.2 Workflow de mise à jour zero-downtime (Kubernetes)

```mermaid
sequenceDiagram
    actor Admin
    participant K8s as Kubernetes
    participant Pod_old as Pod ancien
    participant Pod_new as Pod nouveau
    participant DB as PostgreSQL

    Admin->>K8s: helm upgrade sealkeeper sealkeeper --version 0.2.0
    K8s->>Pod_new: Démarre nouveau pod
    activate Pod_new
    Pod_new->>DB: Vérifie migrations
    alt Migrations en attente
        Pod_new->>Pod_new: readyz=503 jusqu'à fin des migrations
        Pod_new->>DB: Applique migrations forward-only
    end
    Pod_new->>DB: readyz=200 quand prêt
    K8s->>K8s: Detecte readyz nouveau pod OK
    K8s->>Pod_old: Arrête l'ancien pod gracieusement
    deactivate Pod_old
    Note over K8s,Pod_new: Trafic basculé sur Pod_new
```

---

## 7. Edge cases and error handling

| Cas | Réponse |
|---|---|
| Migration DB échoue à la mise à jour | Le binaire refuse de démarrer, `readyz` retourne 503. Procédure : restore du backup pré-update + investigation |
| Master secret modifié entre deux démarrages | Refus de démarrer (cf. module E). Restauration backup ou nouveau déploiement |
| PostgreSQL inaccessible au démarrage | Retry 5 fois avec backoff (1s, 2s, 5s, 10s, 30s), puis échec définitif. `readyz` reflète l'état |
| PostgreSQL inaccessible en cours d'exécution | Les handlers renvoient 500. Pool DB tente reconnect en arrière-plan |
| Disque saturé sur `/data` | Les uploads de bibliothèque échouent (422). L'audit log essaie de continuer en attendant. À surveiller via métrique `sealkeeper_disk_usage_percent` (📋 à ajouter à v0.2) |
| Container redémarré pendant une migration | Migration goose est transactionnelle ; redémarrage = reprise propre. Compatible *crash-only software* |
| Reverse proxy down | Pas de trafic, healthchecks externe alertent. SealKeeper continue de tourner en interne |
| TLS expiré côté reverse proxy | Caddy / Traefik renouvellent automatiquement via Let's Encrypt. Sinon : alerte monitoring |
| Helm upgrade qui échoue à mi-parcours | `helm rollback sealkeeper N-1` ramène à l'état précédent. Si migration DB déjà appliquée, restore manuel requis |
| Backup corrompu détecté à la restauration | Signature invalide ou hash incohérent → refus de restaurer. Backup précédent à utiliser |
| Mode maintenance reste activé après crash | `sealkeeper system maintenance off` via CLI ; persisté en DB, donc redémarrage du container ne suffit pas à le désactiver |
| Volume `/data` perdu (PVC supprimé par erreur) | Restauration depuis backup. **Documenter** que la perte du volume = perte des bibliothèques uploadées et de la DB en mode eval (rien à perdre en prod avec PG externe) |

---

## 8. Closed decisions

| # | Décision | Justification |
|---|---|---|
| D-H.1 | **Image OCI basée sur `distroless/static`** ou `scratch`, < 50 MB | Surface d'attaque minimale, pas de shell, posture défensive |
| D-H.2 | **PostgreSQL recommandé en production**, SQLite réservé au mode eval | PG = mature, multi-instance, sauvegardes pg_dump, replication |
| D-H.3 | **Caddy recommandé** comme reverse proxy par défaut ; Traefik et Nginx documentés | Caddy = HTTPS automatique Let's Encrypt, config minimale |
| D-H.4 | **Pas de StatefulSet en v0.1** ; Deployment avec PG externe | StatefulSet inutile sans état local persistant ; PG externe gère la persistance |
| D-H.5 | **Master secret en Kubernetes Secret** (pas de Vault natif) ; recommandation External Secrets / Sealed Secrets pour les clients sensibles | Standard K8s, intégration tierce possible |
| D-H.6 | **Mise à jour PATCH = rolling update**, MINOR = expand-contract migration pattern | Compromis entre vélocité et zero-downtime |
| D-H.7 | **Migrations forward-only** (cf. D-D.13) ; rollback = restore backup | Évite la complexité du rollback de schéma |
| D-H.8 | **Backup CLI natif pour SQLite + libraries** ; PG = pg_dump + WAL archiving | Outils mûrs pour PG, pas de réinvention |
| D-H.9 | **Backup automatisé natif S3 reporté v0.3** | Restic / borg externe couvre v0.1 |
| D-H.10 | **Mode démo public disponible mais non-hébergé par les mainteneurs** | Préserve les ressources ; mainteneurs auto-hébergeurs encouragés |
| D-H.11 | **Pas de mTLS DB / SMTP natif** ; délégation à la couche réseau (service mesh) | Restent simples ; complexité gérée par l'orchestrateur |
| D-H.12 | **Reproducible builds** : objectif v0.3 (SLSA niveau 3) | Coût d'ingénierie non-trivial, livré en maturité |
| D-H.13 | **HPA reporté v0.3** (nécessite Redis pour sessions, livré en v0.3 selon D-D.20) | Multi-instance demande externalisation des sessions |
| D-H.14 | **Helm chart sur repo dédié** (`https://sealkeeper.eu/charts`), pas Artifact Hub immédiatement | Maîtrise du flux ; Artifact Hub possible v0.2 |
| D-H.15 | **Documentation des configurations reverse proxy** pour Caddy, Traefik, Nginx dans `examples/` | Réduit la friction d'adoption ; trois solutions principales du marché |
| D-H.16 | **Image multi-arch amd64 + arm64 dès v0.1** | Build via `docker buildx`, couvre Raspberry Pi et Mac Apple Silicon, peu d'effort additionnel |
| D-H.17 | **Pas de chart OpenShift dédié en v0.1** ; documentation séparée si demande (`docs/deployment/openshift.md`) | Le chart Helm fonctionne souvent avec quelques annotations, pas de cas justifiant un fork |
| D-H.18 | **Opérateur Kubernetes (CRD `SealKeeperInstance`) reporté v0.4+** | Helm suffit largement, opérateur = complexité d'ingénierie non justifiée en pré-1.0 |
| D-H.19 | **Pas d'image alpine alternative** en v0.1 ; debug via ephemeral container ou `kubectl debug` | Distroless force la posture défensive ; alpine introduit shell et outils inutiles |
| D-H.20 | **UBI Red Hat évalué v0.2 si demande** clients régulés (santé, défense, finance) | Marché de niche, attendre confirmation |
| D-H.21 | **Healthcheck Docker externe via Compose** (pas wget dans l'image distroless) | Préserve la minimalité de l'image ; Compose `healthcheck` ou K8s probe couvrent le besoin |
| D-H.22 | **`SK_TRUSTED_PROXY_CIDRS` vide par défaut** ; documentation explicite invite à configurer selon déploiement | Évite que `X-Forwarded-For` soit honoré par accident |
| D-H.23 | **Pas de limite hard sur le nombre de domaines** ; recommandation pratique ~1000 domaines actifs documentée | Au-delà : envisager multi-tenancy (module à venir post-v1.0) |
| D-H.24 | **Procédure de désinstallation propre documentée** dans `docs/operations/uninstall.md` | Important pour les évaluateurs et la conformité RGPD (effacement des données) |

---

## 9. Open questions

**Toutes les questions ouvertes ont été tranchées le 16 mai 2026** par Pascal-Louis Darmon après recommandation de Daneel. Les 9 décisions correspondantes sont consignées en §8 sous les références D-H.16 à D-H.24. Le PRD H est intégralement validé en v1.0.

Trois fonctionnalités sont reportées sous condition de demande : chart OpenShift (v0.2), opérateur K8s (v0.4+), image UBI (v0.2).

---

## 10. References

- **Module D** — binaire et CLI déployés
- **Module E** — sécurité du déploiement (TLS, WAF)
- **Module G** — endpoints à exposer
- **Module L** — release process

- **Docker** — [docs.docker.com](https://docs.docker.com)
- **Kubernetes** — [kubernetes.io/docs](https://kubernetes.io/docs)
- **Helm 3** — [helm.sh/docs](https://helm.sh/docs)
- **Caddy** — [caddyserver.com/docs](https://caddyserver.com/docs)
- **Traefik** — [doc.traefik.io](https://doc.traefik.io)
- **Nginx** — [nginx.org/en/docs](https://nginx.org/en/docs)
- **Let's Encrypt** — [letsencrypt.org/docs](https://letsencrypt.org/docs)
- **Distroless** — [github.com/GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- **Sealed Secrets** — [github.com/bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)
- **External Secrets Operator** — [external-secrets.io](https://external-secrets.io)
- **CloudNativePG** — opérateur PostgreSQL Kubernetes
- **SLSA framework** — [slsa.dev](https://slsa.dev)
- **OWASP Docker security cheat sheet** — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- **Kubernetes Pod Security Standards** — restricted profile

---

## 11. Évolution de ce document

| Version | Date | Auteur | Changements |
|---|---|---|---|
| 1.1 | 2026-10-28 | P.-L. Darmon (Claude) | HPA (FR-H.37, D-H.13) reporté de v0.2 à **v0.3**, aligné sur Redis (D-D.20) |
| 1.0 | 2026-05-16 | P.-L. Darmon (Daneel) | **Version validée** — 9 décisions tranchées (D-H.16 à D-H.24) : multi-arch dès v0.1, OpenShift doc séparée, opérateur K8s v0.4+, pas d'alpine, UBI v0.2 sur demande, healthcheck Docker externe, trusted_proxy_cidrs vide par défaut, pas de limite domaines hard, doc uninstall |
| 0.1 | 2026-05-16 | P.-L. Darmon (Daneel) | Création initiale — 82 FR réparties en 11 sous-sections, 3 modes de déploiement (eval, Compose, K8s), Helm chart structuré, sécurité conteneur (distroless, non-root, read-only), backup/restore, mises à jour SemVer + expand-contract, 15 décisions tranchées, 9 questions ouvertes, 4 diagrammes Mermaid |

---

*Document maintenu dans le repo `SCHED75-ORG/SealKeeper` sous `docs/prd/H-deployment.md`.*
