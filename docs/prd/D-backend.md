# Module D — Backend serveur

**Statut** : validé
**Version** : 1.0
**Dernière mise à jour** : 2026-05-16
**Auteur** : Pascal-Louis Darmon (assisté par Daneel / Claude)
**Dépendances** : modules A (générateur), B (workflow), C (console admin) ; alimente G (API), E (sécurité), F (intégrations), H (déploiement)

---

## 1. Purpose

Ce module spécifie le **service serveur Go** qui sert SealKeeper. Il couvre l'architecture des packages, le schéma de la base de données, la gestion des tokens de session, le relais SMTP, le templating des emails, les healthchecks, les métriques Prometheus, et la gestion de configuration.

C'est le **module de cœur d'implémentation** : il décide concrètement de la stack technique, des bibliothèques, des conventions de code. Toutes ces décisions seront ensuite gravées dans le code Go produit.

---

## 2. Actors and use cases

| Acteur | Interaction principale |
|---|---|
| Serveur Go | Sert toutes les requêtes HTTP (public et admin) |
| Base de données (SQLite ou PostgreSQL) | Persistance complète |
| Relais SMTP externe | Envoi des emails |
| Reverse proxy (Caddy / Traefik / Nginx) | Termine le TLS, route vers le binaire Go |
| Conteneur Docker | Encapsule le binaire + les assets statiques |
| Console admin (module C) | Cliente HTTP du backend |
| Page publique + page de révélation (module B) | Clientes HTTP du backend |
| JS générateur (module A) | Bundle servi statiquement par le backend |

---

## 3. Functional requirements

### 3.1 Architecture des packages Go

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.1 | Le projet suit la structure **standard Go** : `cmd/sealkeeper/main.go` pour le binaire, `internal/` pour le code non exportable | MUST |
| FR-D.2 | Packages internes structurés par **domaine fonctionnel**, pas par couche technique. Un package par responsabilité : `domain`, `policy`, `library`, `elevation`, `admin`, `audit`, `session`, `smtp`, `template`, `integration`, `branding`, `system` | MUST |
| FR-D.3 | Un package `internal/http` regroupe les handlers HTTP, middlewares, et le routeur | MUST |
| FR-D.4 | Un package `internal/store` encapsule l'accès à la base : interface `Store` exposant des méthodes par domaine, implémentation concrète SQLite et PostgreSQL | MUST |
| FR-D.5 | Pas d'ORM. Requêtes SQL via **`sqlc`** (génération de code Go à partir de schémas SQL et requêtes annotées) | MUST |
| FR-D.6 | Bibliothèque HTTP : **`net/http` standard + `chi` router** (pas de framework lourd type Echo, Gin, Fiber) | MUST |
| FR-D.7 | Bibliothèque de configuration : **`koanf`** (multi-source : env, fichier YAML, defaults) | MUST |
| FR-D.8 | Logging : **`log/slog`** standard library (depuis Go 1.21), output JSON en production, texte en eval | MUST |
| FR-D.9 | Métriques : **`prometheus/client_golang`** | MUST |
| FR-D.10 | Templates emails : **`text/template`** et **`html/template`** standard library | MUST |
| FR-D.11 | Tests : **`testing` standard + `testify/require`** pour assertions, **`testcontainers-go`** pour tests d'intégration PostgreSQL | MUST |
| FR-D.12 | Migrations DB : **`goose`** | MUST |
| FR-D.13 | Chiffrement des secrets en base : **`crypto/aes`** standard avec clé d'instance dérivée du master secret | MUST |
| FR-D.14 | TOTP : **`pquerna/otp`** | MUST |
| FR-D.15 | WebAuthn : **`go-webauthn/webauthn`** | MUST |

### 3.2 Schéma de base de données

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.16 | Le serveur supporte **SQLite** (mode eval, fichier `data/sealkeeper.db`) et **PostgreSQL 14+** (mode production) | MUST |
| FR-D.17 | Le choix se fait par variable d'environnement `SK_DATABASE_URL` (ex : `sqlite:///data/sealkeeper.db` ou `postgres://user:pass@host/db`) | MUST |
| FR-D.18 | Les requêtes SQL sont **identiques** entre SQLite et PostgreSQL (utilisation des types ANSI standard), à l'exception des types datetime (gérés en couche d'abstraction) | MUST |
| FR-D.19 | Les migrations sont **forward-only**. Pas de rollback automatique (rollback = restauration de backup) | MUST |
| FR-D.20 | Chaque migration est numérotée séquentiellement et idempotente | MUST |

Tables principales (modèle de référence : §5.1 du module C qui décrit le schéma ER).

| Table | Origine module | Contenu |
|---|---|---|
| `admins` | C | Comptes admin |
| `domains` | C | Domaines autorisés |
| `policies` | C | Policies par domaine × niveau |
| `libraries` | C | Bibliothèques (dictionnaires, corpus) |
| `elevations` | C | Listes B2/B3 |
| `branding` | C | Singleton config branding |
| `email_templates` | C | Templates emails par type × langue |
| `smtp_config` | C | Singleton config SMTP (password chiffré) |
| `integrations` | C+F | Cibles SIEM |
| `audit_log` | C+E | Journal d'audit signé HMAC chaîné |
| `user_requests` | B+D | Demandes utilisateurs (rate-limit, anti-énumération) |
| `sessions` | B+D | Tokens de session (révélation) |
| `captured_mail` | C | Emails capturés (mode eval uniquement) |
| `system_config` | C | Configuration générale (singleton) |
| `webauthn_credentials` | C | Credentials FIDO2 par admin |

### 3.3 Génération et validation des tokens de session

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.21 | Les tokens de session utilisateur sont des **tokens opaques aléatoires** (pas JWT) de **128 bits minimum** | MUST |
| FR-D.22 | Format : 32 caractères hexadécimaux ou 22 caractères base64url | MUST |
| FR-D.23 | Source d'entropie : **`crypto/rand`** | MUST |
| FR-D.24 | Le token est **stocké en base** dans `sessions` avec : `id (token)`, `email`, `domain_id`, `policy_id`, `created_at`, `expires_at`, `consumed_at` (null tant que non consommé), `consumed_ip`, `consumed_user_agent` | MUST |
| FR-D.25 | Validation du token : recherche par `id = token`, vérification `consumed_at IS NULL` et `expires_at > now()`. Si OK, mise à jour `consumed_at`, `consumed_ip`, `consumed_user_agent` | MUST |
| FR-D.26 | TTL par défaut : **15 minutes** (configurable par policy, recadré par config globale) | MUST |
| FR-D.27 | Purge automatique des sessions expirées : job de fond qui supprime toutes les sessions où `expires_at < now() - 24h` (rétention 24h pour audit forensique) | MUST |
| FR-D.28 | Les sessions admin (console) utilisent un mécanisme distinct : **cookie de session HttpOnly + SameSite=Strict + Secure**, valeur signée HMAC, expiration absolue 8h, expiration idle 30 min | MUST |
| FR-D.29 | Les sessions admin sont stockées côté serveur dans `admin_sessions` avec révocation possible (logout) | MUST |
| FR-D.30 | CSRF token sur tous les formulaires admin : **double-submit cookie** (cookie + champ caché de form), validation côté serveur | MUST |

### 3.4 Endpoints HTTP (vue d'ensemble — détail en module G)

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.31 | Le serveur expose deux préfixes de routes : **`/api/v1/`** pour les endpoints API JSON, **`/admin/`** pour la console admin (HTML server-side rendered) | MUST |
| FR-D.32 | Endpoints publics (sans authentification) : `GET /`, `GET /reveal/{token}`, `POST /api/v1/request`, `GET /api/v1/policy` (policy par défaut), `POST /api/v1/policy` (token dans le corps JSON), `POST /api/v1/event` | MUST |
| FR-D.33 | Endpoints admin (authentification requise) : `/admin/...` (UI), `/api/v1/admin/...` (API JSON pour les actions XHR) | MUST |
| FR-D.34 | Endpoints observabilité : `GET /healthz` (sans auth), `GET /readyz` (sans auth), `GET /metrics` (sans auth, ou avec bearer token configurable) | MUST |
| FR-D.35 | Assets statiques (CSS, JS, polices, logo) servis depuis `/static/` avec en-têtes **`Cache-Control: public, max-age=31536000, immutable`** pour les assets versionnés | MUST |

### 3.5 Relais SMTP

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.36 | Le serveur se connecte au relais SMTP configuré en console (FR-C.57). Lib : **`net/smtp` standard + `go-mail/mail`** | MUST |
| FR-D.37 | Modes TLS supportés : `none` (clair, pour tests locaux), `starttls` (STARTTLS sur port 587), `tls` (TLS implicite sur port 465) | MUST |
| FR-D.38 | Timeout connexion : 10 secondes ; timeout envoi : 30 secondes | MUST |
| FR-D.39 | Retry en cas d'échec transitoire (codes 4xx SMTP) : 3 tentatives espacées de 1, 5, 15 minutes. Audit log capture chaque tentative | MUST |
| FR-D.40 | En cas d'échec définitif (codes 5xx ou retry épuisé), audit log marque l'événement `EMAIL_FAILED` avec raison. **L'utilisateur final voit toujours le message générique anti-énumération** (FR-B.7) | MUST |
| FR-D.41 | DKIM externe : le serveur n'effectue **pas** de signature DKIM en v0.1 (cf. décision D-C.19 — délégué à l'infra mail) | MUST |
| FR-D.42 | En mode eval (`SK_MODE=eval`), les emails ne sont **pas envoyés** au relais ; ils sont stockés dans `captured_mail` pour consultation via la console | MUST |
| FR-D.43 | Liste des destinataires d'un envoi : **un seul destinataire** par email (le demandeur). Pas de CC, pas de BCC | MUST |

### 3.6 Templating des emails

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.44 | Le serveur charge les templates depuis la table `email_templates` (modifiables en console — FR-C.69 à FR-C.75) | MUST |
| FR-D.45 | Au boot, si la table est vide, le serveur **insère les templates par défaut** (FR + EN, type *reveal* + *notification*) | MUST |
| FR-D.46 | Le rendu utilise `html/template` (échappement automatique XSS) et `text/template` (corps texte brut) | MUST |
| FR-D.47 | Les templates sont **compilés à la volée** à chaque envoi (admin peut modifier sans redémarrer). Cache en mémoire avec invalidation à la mise à jour | SHOULD |
| FR-D.48 | Variables disponibles documentées : `{{.RevealURL}}`, `{{.UserEmail}}`, `{{.ExpiresAt}}` (formaté localement), `{{.InstanceName}}`, `{{.ContactURL}}`, `{{.ConsumedAt}}` (notification seulement), `{{.ConsumedIP}}`, `{{.ConsumedUserAgent}}` | MUST |

### 3.7 Healthchecks et probes

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.49 | `GET /healthz` retourne **200 OK** dès que le binaire répond. Pas de vérification de dépendance | MUST |
| FR-D.50 | `GET /readyz` retourne **200 OK** si : DB joignable, migrations à jour, config valide. **503 Service Unavailable** sinon, avec corps JSON listant les sous-systèmes en échec | MUST |
| FR-D.51 | Pas de vérification SMTP dans `/readyz` (le SMTP peut être temporairement down sans nuire à la console admin) | MUST |
| FR-D.52 | Les probes ne sont **jamais loggées** au niveau INFO (sinon le log devient bruyant). Niveau DEBUG seulement | MUST |

### 3.8 Métriques Prometheus

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.53 | Endpoint `GET /metrics` expose les métriques au format Prometheus | MUST |
| FR-D.54 | Métriques exposées : **standard runtime Go** (heap, GC, goroutines) **+ métriques applicatives** : | MUST |
| FR-D.55 | `sealkeeper_requests_total{endpoint, status}` (counter) — toutes les requêtes HTTP | MUST |
| FR-D.56 | `sealkeeper_request_duration_seconds{endpoint}` (histogram) — latence par endpoint | MUST |
| FR-D.57 | `sealkeeper_user_requests_total{domain, level, outcome}` (counter) — demandes utilisateurs par domaine, niveau, résultat (`sent`, `rate_limited`, `domain_blocked`) | MUST |
| FR-D.58 | `sealkeeper_sessions_active` (gauge) — sessions utilisateur non consommées et non expirées | MUST |
| FR-D.59 | `sealkeeper_emails_sent_total{status}` (counter) — emails envoyés (`success`, `transient_failure`, `permanent_failure`) | MUST |
| FR-D.60 | `sealkeeper_admin_logins_total{outcome}` (counter) — logins admin (`success`, `wrong_password`, `wrong_totp`, `locked`) | MUST |
| FR-D.61 | `sealkeeper_audit_log_chain_intact` (gauge 0/1) — état d'intégrité de la chaîne HMAC | MUST |
| FR-D.62 | `sealkeeper_integration_sends_total{integration, status}` (counter) — envois vers SIEM | MUST |
| FR-D.63 | Endpoint `/metrics` accessible publiquement par défaut. Option : token bearer requis (`SK_METRICS_TOKEN`) | SHOULD |

### 3.9 Configuration

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.64 | Source de config par ordre de priorité décroissante : **(1) flags CLI**, **(2) variables d'environnement**, **(3) fichier YAML** (`SK_CONFIG_FILE`, défaut `/etc/sealkeeper/config.yaml`), **(4) defaults internes** | MUST |
| FR-D.65 | Variables d'env préfixées **`SK_`** : `SK_MODE`, `SK_BASE_URL`, `SK_DATABASE_URL`, `SK_MASTER_SECRET`, `SK_HTTP_LISTEN`, `SK_METRICS_TOKEN`, `SK_LOG_LEVEL`, etc. | MUST |
| FR-D.66 | Le **master secret** (`SK_MASTER_SECRET`) est la clé racine utilisée pour dériver les clés de chiffrement de secrets (SMTP password, DKIM key, integration tokens). 32 octets aléatoires, base64. Si non fourni, le serveur **refuse de démarrer** en mode production | MUST |
| FR-D.67 | En mode eval, si `SK_MASTER_SECRET` n'est pas fourni, le serveur en génère un et l'écrit dans un fichier `data/.master_secret` avec warning. Dans ce cas, **toute purge du fichier rend les secrets stockés irrécupérables** | MUST |
| FR-D.68 | Toutes les variables d'env disponibles sont documentées et listées via `sealkeeper config dump` (sans afficher les valeurs sensibles) | MUST |
| FR-D.69 | Le démarrage du binaire log un résumé de la config effective (sans secrets) au niveau INFO | MUST |

### 3.10 CLI

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.70 | Le binaire `sealkeeper` expose une CLI avec sous-commandes : `serve` (défaut), `migrate`, `admin`, `config`, `version` | MUST |
| FR-D.71 | `sealkeeper migrate up` exécute les migrations DB en attente. `migrate status` affiche la version courante | MUST |
| FR-D.72 | `sealkeeper admin reset-bootstrap` génère un nouveau bootstrap password (action loggée si DB déjà initialisée) | MUST |
| FR-D.73 | `sealkeeper admin reset-totp <email>` réinitialise le TOTP d'un admin (action loggée critique) | MUST |
| FR-D.74 | `sealkeeper admin emergency-unlock <email>` déverrouille un compte admin (action loggée critique) | MUST |
| FR-D.75 | `sealkeeper config dump` affiche la configuration effective sans secrets | MUST |
| FR-D.76 | `sealkeeper version` affiche la version, le commit Git, la date de build | MUST |

### 3.11 Anti-énumération et rate-limiting

| ID | Exigence | Niveau |
|---|---|---|
| FR-D.77 | Le handler `POST /api/v1/request` répond en **temps constant ~500ms ± 50ms** quel que soit le résultat. Si le traitement réel prend moins, le handler attend avant de répondre. Si plus, il prolonge à la marge supérieure | MUST |
| FR-D.78 | Rate-limit par email : **3 demandes par heure** (FR-B.11). Implémenté via la table `user_requests` (compteur + reset toutes les heures) | MUST |
| FR-D.79 | Rate-limit par IP : **10 demandes par heure** (FR-B.12). Implémenté de même | MUST |
| FR-D.80 | Au-delà du rate-limit, le handler renvoie quand même 200 + message générique (FR-B.13). Audit log marque l'événement | MUST |
| FR-D.81 | Rate-limit sur `/admin/login` : 5 tentatives par compte, 15 minutes de verrouillage (FR-C.10) | MUST |

---

## 4. Non-functional requirements

| Type | Exigence | Cible |
|---|---|---|
| Performance | Latence p50 `POST /api/v1/request` | < 500ms (constant) |
| Performance | Latence p50 autres endpoints API | < 50ms |
| Performance | Throughput soutenu | 100 req/s par cœur CPU |
| Empreinte mémoire | Heap stable | < 100 MB pour un déploiement < 100 domaines |
| Empreinte binaire | Taille du binaire Go | < 30 MB statiquement lié |
| Empreinte image Docker | Image basée sur `scratch` ou `distroless/static` | < 50 MB |
| Sécurité | Pas de dépendance CGO | MUST (binaire statique pur Go) |
| Sécurité | Pas d'évaluation de code à runtime | MUST |
| Disponibilité | Cible production | 99.9 % (single-instance) |
| Compatibilité | Go version | 1.22+ (pour `slog`, `range over int`, `errors.Is`) |
| Concurrency | Race conditions | 0 (vérifié par `go test -race`) |

---

## 5. Data model

### 5.1 Architecture des packages

```mermaid
graph TB
    Main[cmd/sealkeeper/main.go]
    Main --> Cmd[internal/cmd<br/>CLI subcommands]
    Cmd --> Config[internal/config<br/>koanf loader]
    Cmd --> Server[internal/server<br/>http + routing + middlewares]

    Server --> HTTP[internal/http<br/>handlers + middlewares]
    HTTP --> Domain[internal/domain<br/>domain logic]
    HTTP --> Admin[internal/admin<br/>console + sessions]
    HTTP --> API[internal/api<br/>public + admin API]

    Domain --> Policy[internal/policy]
    Domain --> Library[internal/library]
    Domain --> Elevation[internal/elevation]
    Domain --> Session[internal/session]
    Domain --> Audit[internal/audit<br/>HMAC chained log]

    Domain --> Store[internal/store<br/>Store interface]
    Store --> StoreSQLite[internal/store/sqlite<br/>sqlc-generated]
    Store --> StorePG[internal/store/postgres<br/>sqlc-generated]

    Domain --> Mail[internal/mail<br/>SMTP + templates]
    Mail --> Template[internal/template<br/>text + html/template]

    Domain --> Integration[internal/integration<br/>SIEM exporters]
    Integration --> Syslog[syslog]
    Integration --> Webhook[json webhook]
    Integration --> Splunk[Splunk HEC]
    Integration --> Sentinel[Microsoft Sentinel]
    Integration --> Elastic[Elastic ECS]

    Server --> Metrics[internal/metrics<br/>prometheus]
    Server --> Health[internal/health<br/>healthz + readyz]
```

### 5.2 Cycle de vie d'une demande utilisateur

```mermaid
sequenceDiagram
    actor User
    participant Server as Backend Go
    participant DB as Database
    participant SMTP as Relai SMTP
    participant Audit as Audit log

    User->>Server: POST /api/v1/request {email}
    activate Server
    Server->>Server: Démarre chrono cible 500ms

    Server->>DB: SELECT domain WHERE fqdn = email_domain
    DB-->>Server: domain | null

    alt domain absent ou inactif
        Server->>Audit: USER_REQUEST_RECEIVED + outcome=domain_blocked
        Server->>Server: Attend jusqu'à 500ms
        Server-->>User: 200 OK + message générique
    else domain présent et actif
        Server->>DB: SELECT count user_requests WHERE email AND ts > now - 1h
        alt rate-limit dépassé
            Server->>Audit: USER_REQUEST_BLOCKED_RATELIMIT
            Server->>Server: Attend jusqu'à 500ms
            Server-->>User: 200 OK + message générique
        else rate-limit OK
            Server->>DB: SELECT level = (email IN elevations B3 ? B3 : email IN elevations B2 ? B2 : B1)
            Server->>DB: SELECT policy WHERE domain_id AND anssi_level
            Server->>Server: Génère token 128 bits
            Server->>DB: INSERT session {token, email, domain_id, policy_id, expires_at}
            Server->>SMTP: Envoie email avec lien /reveal/{token}
            alt SMTP succès
                Server->>Audit: EMAIL_SENT
            else SMTP échec
                Server->>Audit: EMAIL_FAILED
            end
            Server->>Audit: USER_REQUEST_ALLOWED + level + policy_id
            Server->>Server: Attend jusqu'à 500ms
            Server-->>User: 200 OK + message générique
        end
    end
    deactivate Server
```

---

## 6. Interfaces

### 6.1 Structure du repo Go

Le repo Go est structuré ainsi :

- `cmd/sealkeeper/main.go` — point d'entrée
- `internal/` — packages internes (cf. §5.1)
- `migrations/` — fichiers SQL goose numérotés
- `web/` — assets statiques (CSS, JS bundle, fonts, logos par défaut)
- `web/templates/` — templates HTML server-side rendered de la console admin
- `web/email-templates/` — templates emails par défaut (FR, EN)
- `docs/prd/` — PRD (ce document et les autres)
- `Dockerfile` — multi-stage build
- `go.mod` / `go.sum` — gestion des dépendances
- `Makefile` — tâches courantes (build, test, lint, run)

### 6.2 Conventions de codage

| Convention | Règle |
|---|---|
| Linter | `golangci-lint` avec config dédiée (errcheck, govet, staticcheck, gosec, gocritic) |
| Format | `gofmt` + `goimports` (pre-commit hook) |
| Naming | Convention Go standard (camelCase pour packages non exportés, PascalCase pour exports) |
| Errors | `errors.New` ou `fmt.Errorf` avec `%w` pour wrapping ; jamais `panic` sauf au boot |
| Logging | `slog` avec niveaux DEBUG / INFO / WARN / ERROR ; champs structurés via `slog.Attr` |
| Context | `context.Context` propagé partout, dérivé du request context HTTP |
| Tests | Couverture cible 75 % (module L détaille la stratégie) |

---

## 7. Edge cases and error handling

| Cas | Réponse |
|---|---|
| DB indisponible au boot | Le binaire log ERROR et quitte avec code 1. `readyz` ne réagira pas |
| DB indisponible en cours d'exécution | Les handlers retournent 500. Reconnect automatique via pool. `readyz` retourne 503 |
| Migration en attente | `readyz` retourne 503 avec message *« migrations pending »*. Le binaire ne sert pas les routes applicatives, mais `/healthz` et `/metrics` répondent |
| Master secret invalide ou manquant en prod | Refus de démarrer, message ERROR clair |
| Master secret modifié entre deux démarrages | Refus de démarrer ; les secrets en base sont chiffrés avec l'ancienne clé. Procédure de rotation à documenter (CLI dédié, v0.2) |
| Relai SMTP injoignable | Retry 3 fois, puis abandon avec audit log. L'utilisateur final voit toujours le message générique |
| Token consommé concurremment (race) | La transaction de marquage `consumed_at` utilise `UPDATE ... WHERE consumed_at IS NULL` avec vérification du nombre de lignes affectées. Seul le premier requérant gagne |
| Disque plein | Les écritures DB échouent. Audit log capture si possible. Le binaire devient progressivement non fonctionnel. `readyz` retourne 503 |
| Mémoire OOM | Le runtime Go termine proprement (panic non récupérable). Le superviseur (Docker, systemd) relance |
| Trop de sessions actives | Limit configurable (`SK_MAX_ACTIVE_SESSIONS`, défaut 10 000). Au-delà, le handler `POST /api/v1/request` retourne 200 + message générique mais l'audit log marque `SESSIONS_LIMIT_REACHED` |
| Horloge serveur incorrecte | Les TTL sont décalés. Risque mineur (l'admin verra des sessions expirer trop tôt ou trop tard). Pas de garde-fou en v0.1 |

---

## 8. Closed decisions

Les décisions techniques structurantes sont prises et liantes :

| # | Décision | Justification |
|---|---|---|
| D-D.1 | **Go 1.22+** comme langage exclusif côté serveur | Performance, binaire statique, écosystème mature pour services HTTP |
| D-D.2 | **`net/http` standard + chi** (pas Echo, Gin, Fiber) | Simplicité, audit facile, pas de dépendance lourde |
| D-D.3 | **`sqlc`** pour les requêtes SQL (pas d'ORM type GORM, ent) | Type-safety, performance, lisibilité du SQL |
| D-D.4 | **SQLite ET PostgreSQL** supportés, même schéma SQL | Eval = SQLite simple, production = PostgreSQL robuste |
| D-D.5 | **Tokens session = opaques aléatoires** (pas JWT) | Révocation immédiate possible, pas de fuite par expiration claim, plus simple à auditer |
| D-D.6 | **128 bits d'entropie minimum** pour les tokens | Au-delà du brute-force pratique |
| D-D.7 | **Sessions admin = cookie HttpOnly + serveur stockage** | Révocation, audit, plus sûr que JWT côté serveur |
| D-D.8 | **CSRF protection = double-submit cookie** | Pattern OWASP standard, simple |
| D-D.9 | **Pas de DKIM signing natif en v0.1** (cf. D-C.19) | Délégué à l'infra mail externe |
| D-D.10 | **Pas de CGO** : binaire statique pur Go | Compilation simple, image Docker `distroless/static` ou `scratch` |
| D-D.11 | **`slog` standard library** pour logging structuré | Évite les libs tierces (zap, zerolog), Go 1.22+ |
| D-D.12 | **Prometheus pour métriques** (pas OpenTelemetry en v0.1) | Standard de facto, mature, simple |
| D-D.13 | **Migrations forward-only** via goose | Pas de risque de bascule dans un état intermédiaire |
| D-D.14 | **Master secret côté serveur, fourni en environnement** | Pas de stockage en base, posture KMS-friendly pour v0.2 |
| D-D.15 | **`koanf` pour la configuration** multi-source | Plus flexible et léger que viper |
| D-D.16 | **Router `chi`** confirmé (`gorilla/mux` archivé depuis 2022) | Maintenu activement, écosystème de middlewares riche |
| D-D.17 | **Bibliothèques stockées en fichiers disque** (`data/libraries/*.txt`), hash et metadata en DB | Inspection facile, backup rsync, mmap possible ; BLOB en DB cause bloat |
| D-D.18 | **Cache policies en mémoire** avec invalidation explicite par channel Go à chaque update | Lecture extrêmement chaude, update rare ; pattern read-through |
| D-D.19 | **Master secret = variable d'environnement base64** (32 octets aléatoires) | K8s/Docker-friendly, pas de mount supplémentaire |
| D-D.20 | **Sessions stockées en DB v0.1** (SQLite/PostgreSQL) ; Redis cluster reporté à **v0.3** | Volume v0.1 faible ; Redis utile pour scale horizontal multi-instance |
| D-D.21 | **Compression gzip / brotli déléguée au reverse proxy** (Caddy, Traefik, Nginx) | Outils mûrs, binaire Go reste minimaliste |
| D-D.22 | **Limite upload bibliothèque : 10 MB par défaut**, configurable via `SK_MAX_LIBRARY_SIZE_MB` | EFF Diceware ~50 KB, corpus enrichis qq MB, marge confortable |
| D-D.23 | **Endpoint export DPO RGPD** : décision renvoyée au module I (RGPD) ; position préliminaire : endpoint dédié `/admin/dpo-export` | Décision logique du module conformité |
| D-D.24 | **Audit log : 1 table `audit_log` avec colonne JSON `details`** (pas plusieurs tables typées) | Code uniforme, index JSONB (PG) ou FTS5 (SQLite), requêtes flexibles |
| D-D.25 | **Signature chaîne audit** : décision renvoyée au module E (sécurité) ; position préliminaire : HMAC-SHA256 en v0.1, Ed25519 en v0.2 pour vérification asymétrique tiers | Décision sécurité, détaillée dans le module dédié |

---

## 9. Open questions

**Toutes les questions ouvertes ont été tranchées le 16 mai 2026** par Pascal-Louis Darmon après recommandation de Daneel. Les 10 décisions correspondantes sont consignées en §8 sous les références D-D.16 à D-D.25. Le PRD D est intégralement validé en v1.0.

**Deux questions ont été renvoyées à d'autres modules** :
— L'endpoint d'export DPO RGPD (ancienne 9.8) sera détaillé en module I.
— Le choix HMAC-SHA256 vs Ed25519 pour la chaîne d'audit (ancienne 9.10) sera détaillé en module E. Position préliminaire en attendant : HMAC-SHA256 en v0.1, Ed25519 en v0.2.

---

## 10. References

- **Module A** — bundle JS servi statiquement par le backend
- **Module B** — clients HTTP du backend (page publique, page de révélation)
- **Module C** — interface admin servie par le backend
- **Module E** — détaille le mécanisme HMAC chaîné de l'audit log
- **Module F** — détaille les protocoles SIEM
- **Module G** — formalise toute l'API REST exposée
- **Module H** — détaille le packaging Docker, Helm, env vars
- **Module L** — détaille la stratégie de tests Go
- **Go standard library** — `net/http`, `log/slog`, `text/template`, `html/template`, `crypto/rand`, `crypto/aes`
- **chi router** — [github.com/go-chi/chi](https://github.com/go-chi/chi)
- **sqlc** — [sqlc.dev](https://sqlc.dev)
- **koanf** — [github.com/knadh/koanf](https://github.com/knadh/koanf)
- **goose** — [github.com/pressly/goose](https://github.com/pressly/goose)
- **Prometheus Go client** — [github.com/prometheus/client_golang](https://github.com/prometheus/client_golang)
- **pquerna/otp** — [github.com/pquerna/otp](https://github.com/pquerna/otp)
- **go-webauthn** — [github.com/go-webauthn/webauthn](https://github.com/go-webauthn/webauthn)
- **OWASP CSRF Prevention Cheat Sheet** — pattern double-submit cookie

---

## 11. Évolution de ce document

| Version | Date | Auteur | Changements |
|---|---|---|---|
| 1.0 | 2026-05-16 | P.-L. Darmon (Daneel) | **Version validée** — 10 décisions tranchées (D-D.16 à D-D.25) : chi confirmé, fichiers disque + hash DB pour bibliothèques, cache policies mémoire avec invalidation channel, master secret env base64, sessions en DB v0.1 + Redis v0.3, compression reverse proxy, limite upload 10 MB, audit log 1 table JSON. Deux questions renvoyées : DPO export en module I, signature audit en module E |
| 0.1 | 2026-05-16 | P.-L. Darmon (Daneel) | Création initiale — stack technique Go entière, 81 FR répartis en 11 sous-sections, schéma packages Mermaid, séquence cycle de vie demande utilisateur, 15 décisions techniques tranchées, 10 questions ouvertes |

---

*Document maintenu dans le repo `SCHED75-ORG/SealKeeper` sous `docs/prd/D-backend.md`.*
