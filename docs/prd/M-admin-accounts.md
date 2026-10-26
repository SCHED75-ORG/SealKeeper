# Module M — Comptes d'administration

**Statut** : validé
**Version** : 1.0
**Dernière mise à jour** : 2026-05-17
**Auteur** : Pascal-Louis Darmon (assisté par Daneel / Claude)
**Dépendances** : module C (console admin) — alimente E (audit) et I (RGPD)

---

## 1. Purpose

Ce module spécifie la **gestion des comptes administrateurs** de SealKeeper en tant que sous-système dédié — extraction et formalisation des points épars dans le module C §3.1 et §3.2. Il couvre :

* le **bootstrap** du tout premier compte,
* la **politique de mot de passe ANSSI B3** que l'instance applique à tout admin,
* la **page d'auto-administration** d'un opérateur connecté (renommage, changement de mot de passe),
* la **gestion multi-admin** (création, désactivation, suppression d'autres opérateurs),
* les **garde-fous** anti-lockout,
* la **piste d'audit** émise par chaque mutation.

**Principe directeur.** Le compte admin est un *credential pivot* — il commande la totalité de l'instance. Sa robustesse doit dominer celle des secrets que SealKeeper distribue à ses utilisateurs ; pour cette raison, le niveau ANSSI B3 (≥ 100 bits d'entropie) est imposé en plancher sur **tout** mot de passe d'admin, qu'il soit saisi à l'inscription ou lors d'un changement ultérieur.

---

## 2. Actors and use cases

| Acteur | Interaction principale |
|---|---|
| **Admin principal** | Premier opérateur seedé via `admin@localhost`. Renomme son compte vers son adresse réelle dès la mise en service. |
| **Admin technique** | Compte secondaire créé depuis `/admin/admins` ; couvre les astreintes hors-bureaux de l'admin principal. |
| **Admin sortant** | Compte désactivé puis supprimé lors d'un départ ; ses entrées d'audit restent. |
| **Bootstrap** | Premier démarrage : le serveur seed `admin@localhost`, affiche un mot de passe aléatoire dans les logs (FR-C.1). |

**Cas d'usage canoniques.**

| Scénario | Étapes |
|---|---|
| Mise en service initiale | `docker run` → relecture des logs → login `admin@localhost` → setup forcé (mot de passe B3 + TOTP + codes de récupération) → renommage vers `rssi@entreprise.com` depuis `/admin/account` |
| Création d'un admin technique | `/admin/admins` → *Add* → email → bouton *Create admin* → bandeau jaune *« Bootstrap password »* à transmettre par un canal de confiance (téléphone, papier) → l'opérateur destinataire se connecte → setup forcé |
| Rotation périodique du mot de passe | `/admin/account` → champ *New password* → soumission → l'application vérifie le plancher B3 et émet un audit `admin.password_changed` |
| Départ d'un opérateur | `/admin/admins` → *Disable* (révoque les sessions actives) → puis *Delete* en saisissant l'email du compte en confirmation |
| Garde-fou *last active admin* | L'unique admin actif tente *Disable* ou *Delete* sur lui-même → refus avec slug `self_disable` / `self_delete` ; tentative similaire sur un autre admin alors qu'il n'en reste qu'un actif → refus `last_active` |

---

## 3. Functional requirements

### 3.1 Bootstrap

| ID | Exigence | Niveau |
|---|---|---|
| FR-M.1 | Au premier démarrage, le serveur **seed exactement un compte admin** (`admin@localhost`) avec un mot de passe aléatoire de 20 caractères mélangeant lower / upper / digits / symboles (alphabet sans glyphes ambigus) | MUST |
| FR-M.2 | Le mot de passe est journalisé une seule fois au niveau INFO avec un marqueur clair *« BOOTSTRAP ADMIN PASSWORD »*, puis purgé de la RAM | MUST |
| FR-M.3 | En mode `eval` exclusivement, la variable d'environnement `SK_BOOTSTRAP_ADMIN_PASSWORD` (≥ 12 caractères) remplace l'aléa du bootstrap — usage limité aux scripts de capture d'écran et démos répétables | SHOULD |

### 3.2 Politique de mot de passe ANSSI B3

| ID | Exigence | Niveau |
|---|---|---|
| FR-M.4 | Tout mot de passe d'administrateur **doit atteindre ANSSI B3** : **entropie de devinette estimée ≥ 100 bits** (`AdminPasswordMinEntropyBits`). Préalables bloquants : ≥ 16 caractères (`AdminPasswordMinLength`), mélange d'au moins **3 des 4 classes** (minuscule, majuscule, chiffre, symbole) et absence de la liste des mots de passe courants. Longueur et classes ne garantissent **pas** à elles seules le seuil (`Password1234567!` les satisfait et reste très en dessous) : le seuil est vérifié par l'estimateur `EstimatePasswordEntropy`, de type zxcvbn — découpage du mot de passe en segments au coût minimal, chaque caractère « libre » coûtant log2 de la taille de l'alphabet observé, chaque motif prévisible (mot de passe courant, mot de dictionnaire y compris variantes de casse et leetspeak, nom du produit, de l'instance ou email de l'opérateur, année, séquence, marche clavier, répétition) le prix qu'il coûte à un attaquant qui connaît le motif. Seuls les 72 premiers octets comptent (limite d'entrée bcrypt) | MUST |
| FR-M.5 | La validation est faite côté serveur, via `internal/admin.ValidateAdminPassword`. Côté navigateur, l'attribut `minlength="16"` du `<input type="password">` offre un premier filtre, jamais une garantie | MUST |
| FR-M.6 | Le rejet renvoie un `*admin.WeakPasswordError` (`errors.Is(err, admin.ErrPasswordTooWeak)`) portant l'entropie estimée et des **codes de faiblesse** (`too_short`, `few_classes`, `common`, `dictionary`, `context`, `year`, `sequence`, `keyboard`, `repeat`, `entropy`). L'UI affiche la phrase associée à chaque code (*« minimum 16 characters »*, *« contains a dictionary word »*…) ; ni le message ni l'URL ne citent jamais un fragment du mot de passe | MUST |

> **Remarque.** Les mots de passe de bootstrap (FR-M.1) et de création serveur-générée (FR-M.13) **ne sont pas soumis** au validateur B3 : leur entropie est garantie par la construction (20 caractères pseudo-aléatoires depuis un alphabet de 64+ glyphes ≥ 120 bits). Le validateur s'applique **uniquement** au moment où un humain choisit lui-même son mot de passe (setup wizard ou `/admin/account`).

### 3.3 Auto-administration

| ID | Exigence | Niveau |
|---|---|---|
| FR-M.7 | Une page `/admin/account` expose au minimum : changement d'email, changement de mot de passe, raccourci vers `/admin/security` (FIDO2) | MUST |
| FR-M.8 | Le changement d'email accepte tout email canonique (lower-cased, trim) ; le grammaire est volontairement laxiste (hostname nu autorisé pour `admin@localhost`). La déliverabilité réelle est de la responsabilité du relais SMTP | MUST |
| FR-M.9 | Le changement d'email échoue avec `ErrAlreadyExists` lorsque l'adresse est déjà sur un autre compte | MUST |
| FR-M.10 | Le changement de mot de passe applique FR-M.4..6 et exige la **confirmation par double saisie** ; en cas d'incohérence le serveur répond `password_mismatch` | MUST |

### 3.4 Gestion multi-admin

| ID | Exigence | Niveau |
|---|---|---|
| FR-M.11 | Une page `/admin/admins` liste tous les comptes admin avec : email, statut (`active` / `disabled` / `pending setup`), date de dernière connexion | MUST |
| FR-M.12 | Tout admin connecté peut **créer** un autre admin en fournissant simplement l'email cible. Le serveur génère un mot de passe initial de 20 caractères et le révèle **une seule fois** dans un bandeau juste après la création | MUST |
| FR-M.13 | Le nouvel admin hérite des bits `force_password_change` et `force_totp_enroll` ; il est obligatoirement passé par le setup wizard à sa première connexion (FR-C.3 / FR-C.4) | MUST |
| FR-M.14 | La **désactivation** est une opération soft : la colonne `disabled_at` est posée, les sessions actives sont rejetées au prochain `LookupSession`, mais le compte reste dans la table et conserve son historique | MUST |
| FR-M.15 | La **réactivation** consiste à effacer `disabled_at` ; le compte garde son mot de passe et son TOTP existants | SHOULD |
| FR-M.16 | La **suppression** est une opération hard (DELETE) ; les `admin_sessions` du compte tombent par effet CASCADE ; les entrées d'audit consignées sous ce compte restent inchangées. La suppression exige une **double confirmation** : saisie de l'email cible dans un champ texte | MUST |

### 3.5 Garde-fous

| ID | Exigence | Niveau |
|---|---|---|
| FR-M.17 | **Self-disable interdit.** Un admin connecté ne peut pas se désactiver lui-même ; tentative → slug `self_disable` | MUST |
| FR-M.18 | **Self-delete interdit.** Idem pour la suppression ; tentative → slug `self_delete` | MUST |
| FR-M.19 | **Last-active-admin protégé.** Disable et Delete refusent si l'opération laisserait zéro admin actif dans la base (`admin.ErrLastActiveAdmin`). Le slug retourné est `last_active` | MUST |
| FR-M.20 | **Mode démo en lecture seule.** Lorsque `SK_DEMO_MODE=true`, la création d'un nouvel admin est refusée silencieusement (`demo_readonly`). La désactivation et la suppression restent permises, dans la mesure où elles ne contournent jamais FR-M.17..19 | SHOULD |

### 3.6 Piste d'audit

| ID | Exigence | Niveau |
|---|---|---|
| FR-M.21 | Toute mutation émet une entrée dans la chaîne d'audit (module E) : `admin.email_changed`, `admin.password_changed`, `admin.created`, `admin.enabled`, `admin.disabled`, `admin.deleted` | MUST |
| FR-M.22 | Le détail JSON de chaque entrée contient au minimum l'`admin_id` cible et l'acteur (l'admin qui a exécuté la mutation) ; le **mot de passe en clair n'apparaît jamais** dans l'audit log, ni dans la colonne `details_json` ni dans aucun autre champ | MUST |

---

## 4. Non-functional requirements

| Type | Cible |
|---|---|
| **Sécurité** | bcrypt cost 10 minimum sur le hash stocké ; pas de pepper supplémentaire car la base est déjà chiffrée au repos par le déploiement |
| **Disponibilité** | Le dernier admin actif est insupprimable, garantissant qu'aucune mauvaise manipulation ne ferme l'accès à la console |
| **Observabilité** | Chaque mutation passe par `auditAppend` ; la chaîne d'audit est SHA-256 hash-chained (module E) et vérifiable à tout moment via `/admin/audit` |
| **Performance** | La page `/admin/admins` reste tenable jusqu'à ~10 000 comptes en `ORDER BY id` sans pagination — au-delà, le module ré-ouvre la question (v0.3) |

---

## 5. Decisions

| ID | Décision | Justification |
|---|---|---|
| D-M.1 | **Pas de hiérarchie RBAC** en v0.1 — tous les admins sont équivalents | Aligne sur D-C.1 (module C) : surface réduite, audit suffit pour la traçabilité ; introduire des rôles attendra une demande terrain |
| D-M.2 | **Mot de passe initial révélé une fois, jamais ré-affiché** | Force le partage out-of-band et empêche un opérateur intermédiaire d'exfiltrer le credential a posteriori |
| D-M.3 | **Pas de récupération de mot de passe par email** | Implémenter "forgot password" sur la surface admin ouvrirait un vecteur de prise de contrôle si un attaquant compromettait la boîte mail. L'admin oublieux passe par la CLI serveur (`sealkeeper admin reset-password`) — opération hors-bande, journalisée |
| D-M.4 | **Plancher B3 hard-codé**, pas configurable | Une instance qui abaisse son propre seuil annule le bénéfice de SealKeeper ; le couple (16 chars, 3 classes) est un minimum non négociable |
| D-M.5 | **Email lenient** (hostname nu accepté) | Empêcher `admin@localhost` de fonctionner aurait été plus rigide qu'utile ; la deliverability réelle est de toute façon validée par le relais SMTP |
| D-M.6 | **Self-actions interdites** (FR-M.17..19) | Le piège classique « disable my-own-account » est un cas réel observé en clientèle ; la garde-fou est gratuit |

---

## 6. Open questions

| ID | Question | Statut |
|---|---|---|
| Q-M.1 | Faut-il un compte **audit-only en lecture seule** distinct des super-admins ? | Renvoyé à v0.2 — la séparation RSSI / RBAC granulaire arrivera avec le module *roles* |
| Q-M.2 | Faut-il révoquer toutes les sessions de l'admin renommé ? | Décidé : non. Le renommage est cosmétique côté audit, la session active reste valide. La rotation de mot de passe, en revanche, conserve la session en cours (cookie déjà émis) mais invalide les *autres* sessions du même admin si plusieurs navigateurs sont connectés (📋 v0.2) |
| Q-M.3 | Imposer une **expiration périodique** du mot de passe (FR-C.10 du module C ne le mentionne pas) ? | Décidé : non en v0.1. L'expérience montre que la rotation forcée pousse aux mots de passe faibles ; on préfère un plancher d'entropie élevé immuable |

---

## 7. Cross-references

* **Module C — Console admin.** Section §3.1 (bootstrap, lockout) et §3.2 (gestion comptes) fournissent le cadre d'authentification commun ; le présent module M étend §3.2 avec la politique B3 et les routes `/admin/account` + `/admin/admins`.
* **Module E — Audit & sécurité.** Émet les six event types listés en FR-M.21.
* **Module I — Conformité RGPD.** Les emails d'administrateur constituent des données personnelles ; la durée de conservation suit la rétention de la table `admins`, distincte de celle de l'audit log.

---

## 8. Changelog

| Version | Date | Auteur | Notes |
|---|---|---|---|
| 1.0 | 2026-05-17 | P.-L. Darmon (Daneel) | Création du module ; consolide la gestion des comptes admin extraite de C §3.2, formalise la politique B3 (FR-M.4..6) et les garde-fous last-active-admin (FR-M.19) |
| 1.1 | 2026-10-26 | P.-L. Darmon | FR-M.4 / FR-M.6 alignés sur l'implémentation : le seuil B3 est vérifié par l'estimateur d'entropie (`EstimatePasswordEntropy`), longueur + classes ne sont que des préalables ; rejet par codes de faiblesse |
