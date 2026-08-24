# SCIM 2.0 Provisioning — jinbe as Service Provider

**Statut** : draft · **Cible** : Google Workspace & Microsoft Entra ID poussent users + groupes vers jinbe.
**Normes** : RFC 7642 (concepts), RFC 7643 (core schema), RFC 7644 (protocol).

## 1. Décision d'architecture

jinbe expose un endpoint SCIM 2.0 en tant que **Service Provider** (l'IdP est le client). Pas de
polling côté jinbe, pas de connecteur par IdP : un seul protocole standard, les deux IdPs cibles
(Entra, Google) parlent SCIM nativement. Les ressources SCIM sont des **vues** sur le modèle
existant — aucune nouvelle base de données :

| SCIM | jinbe (existant) |
|---|---|
| `User` | Identité Kratos (`src/services/kratos.service.ts` — admin API `createIdentity`, `listIdentities`, `patchIdentity`) |
| `User.userName` / `emails[0]` | `traits.email` (identifiant unique, déjà la clé de `findByEmail`) |
| `User.name.givenName/familyName` | `traits.name.first/last` |
| `User.active` | Kratos `state` (`active` / `inactive`) |
| `User.groups` (readOnly) | `metadata_admin.groups` (source de vérité membership — `src/services/user-groups.service.ts`) |
| `Group` | Groupe RBAC dans Redis hash `rbac:groups` (`src/services/redis-rbac.repository.ts`) |
| `Group.members` | Dérivé : scan des identités dont `metadata_admin.groups` contient le groupe (`getAllIdentitiesWithGroups()`) |

**externalId** : stocké dans `metadata_admin.scim = { externalId, managed: true, idp: '<token-id>', syncedAt }`
pour les users ; pour les groupes, dans le `ResourceMetadata` du groupe (nouveau champ
`scim?: { externalId, managed: true }` à côté du champ `system` existant). Les `id` SCIM sont
l'UUID Kratos (users) et le nom du groupe (groups) — stables, déjà uniques.

## 2. Surface API (RFC 7644)

Préfixe `/scim/v2` enregistré dans `src/server.ts` **hors** du scope `/api` (auth différente,
pas de cookie Kratos). Vérifié contre RFC 7644 + exigences Entra/SailPoint :

| Route | Méthodes | Notes |
|---|---|---|
| `/scim/v2/ServiceProviderConfig` | GET | Obligatoire. Déclare `patch.supported=true`, `filter.supported=true` (maxResults 200), `bulk/sort/etag/changePassword = false`. Entra "Test Connection" attend un 200 ici. |
| `/scim/v2/ResourceTypes`, `/Schemas` | GET | Obligatoires pour découverte (Entra SCIM Validator et SailPoint les exigent). Statique. |
| `/scim/v2/Users` | GET, POST | GET : `filter=userName eq "x"` (lookup Entra/Google avant création — case-insensitive sur attribut et opérateur), pagination `startIndex` (1-based) + `count`, réponse `ListResponse` avec `totalResults/startIndex/itemsPerPage`. POST : `createIdentity` + groupes par défaut `['users']`. |
| `/scim/v2/Users/:id` | GET, PUT, PATCH, DELETE | PATCH ops `add/replace/remove` (au minimum sur `active`, `name.*`, `emails`). DELETE = **soft delete** (voir §4). |
| `/scim/v2/Groups` | GET, POST | Filtre `displayName eq "x"`, pagination. POST crée le groupe dans `rbac:groups` avec services `{}` (le mapping rôles reste console-managed). |
| `/scim/v2/Groups/:id` | GET, PUT, PATCH, DELETE | PATCH `members` : `add` avec `value=<kratosId>`, `remove` avec `path=members[value eq "<id>"]` — les deux formes (Entra utilise le path-filter). Applique via `updateUserGroups` sous `withRedisLock('user-groups:<email>')`. |

Non implémenté (déclaré `false` dans ServiceProviderConfig, ce qui est conforme) : `/Bulk`, `/Me`,
`/.search`, sorting, ETags. Erreurs au format `urn:ietf:params:scim:api:messages:2.0:Error`
(`status`, `scimType` — ex. `uniqueness` sur email en doublon → 409).

Filtre supporté : **uniquement** `userName eq` / `displayName eq` / `externalId eq` (whitelist
parsée, pas de grammaire complète) — c'est ce que les deux IdPs émettent ; tout autre filtre → 501.

## 3. AuthN des appels SCIM

**Décision : bearer token long-lived par IdP, stocké hashé dans Redis** — clé
`rbac:scim:tokens` (hash `{tokenId: JSON({sha256, label, createdBy, createdAt, lastUsedAt})}`),
généré/révoqué depuis kuma Settings, affiché une seule fois.

Pourquoi pas Hydra `client_credentials` (pattern `src/services/api-key.service.ts`) : Entra et
Google Workspace ne font **pas** de flow OAuth vers un token endpoint tiers pour SCIM — ils
demandent un "Secret Token" statique. Le token hashé Redis est le plus simple qui satisfait les
deux IdPs, et suit le pattern de stockage existant. Middleware dédié `scim-auth.ts` (comparaison
constant-time du SHA-256), branché **avant** `identity-extractor` — les routes SCIM ne passent
jamais par le cookie Kratos ni le TokenReview K8s (`src/middleware/identity-extractor.ts` reste intact).
Rate-limit : réutiliser `@fastify/rate-limit` déjà en dépendance. `ServiceProviderConfig/ResourceTypes/Schemas`
restent authentifiés aussi (RFC les autorise sans auth mais rien ne l'impose ; Entra envoie le token).

## 4. Soft delete & conflits

- **DELETE /Users/:id et PATCH active=false** → `updateIdentity(state: 'inactive')` + révocation
  sessions (`revokeAllIdentitySessions`). Jamais `deleteIdentity` : l'audit trail
  (`src/services/audit-event.service.ts`) et la provenance des grants référencent l'email.
  Réactivation = PATCH `active=true`.
- **DELETE /Groups/:id** → retire le groupe de tous les membres (`removeGroupFromAllUsers` existe
  déjà) puis supprime l'entrée `rbac:groups`. Refusé (403) si `metadata.system === true`.

**Politique de conflit — décision : SCIM gagne sur l'identité, la console garde le RBAC.**
- User/groupe créé ou adopté par SCIM → marqué `scim.managed=true`. Adoption : POST sur un
  email/displayName existant non-managé → 409 par défaut ; l'IdP fait alors un GET+PATCH qui
  adopte la ressource (écrit `externalId` + `managed`).
- Sur une ressource SCIM-managed : traits identité, `active` et **membership des groupes
  SCIM-managed** sont en lecture seule côté console (kuma Users/Groups affichent un badge
  "Managed by IdP", champs désactivés ; jinbe rejette les writes console avec 409
  `SCIM_MANAGED`). Le mapping groupe→services/rôles (`GroupDefinition`) reste 100 %
  console-managed : SCIM ne transporte pas d'entitlements, seulement le membership.
- Groupes console-only : invisibles pour SCIM sauf adoption explicite. Un user peut cumuler
  groupes SCIM et groupes console ; les PATCH members SCIM ne touchent que les groupes managed.
- Échappatoire : super_admin peut "détacher" une ressource (drop `scim.managed`) — audité `high`.

## 5. Audit & notifications

Chaque write SCIM émet un événement via `auditEventService` (catégorie `access`, actor =
`scim:<tokenLabel>` — nouveau type d'actor machine, comme les ServiceAccounts) et un
`notificationService.emit({entity_type:'user', action})` (outbox `notifications:outbox` existant,
`src/services/notifications/`).

## 6. Rollout — 3 phases

**Phase 1 — Users (≈ 5 j·h)** : middleware token + `/ServiceProviderConfig|ResourceTypes|Schemas`
+ `/Users` CRUD complet (filter, pagination, PATCH active, soft delete) + marquage `scim.managed`.
Suffit pour du user provisioning Entra/Google sans groupes.

**Phase 2 — Groups + lock console (≈ 6 j·h)** : `/Groups` CRUD + PATCH members (les deux formes
de path), politique de conflit dans `user-groups.service.ts` / `rbac.service.ts`, badge + lock
dans kuma (Users.tsx, Groups.tsx), gestion des tokens dans kuma Settings.

**Phase 3 — Conformance + durcissement (≈ 4 j·h)** : passes validateurs IdP (§7), rate-limit,
métriques Prometheus (`prom-client` déjà présent), doc d'onboarding IdP.

Nouveaux fichiers : `src/routes/scim.routes.ts`, `src/services/scim.service.ts` (mapping +
filter parser), `src/middleware/scim-auth.ts`, `src/services/scim-token.service.ts`,
tests miroirs sous `src/**/__tests__` (vitest existant). Kuma : section Settings "SCIM
provisioning" + badges Users/Groups.

## 7. Stratégie de test

1. **Unit (vitest)** : mapping User↔identity, parser de filtre (whitelist + injection), PATCH
   semantics (add/remove/replace, path-filters members), pagination bounds, adoption/conflits 409.
2. **Entra** : (a) **Microsoft SCIM Validator** — https://scimvalidator.microsoft.com/ (modes
   default attributes / discover schema, activer "Enable Group Tests") ; (b) vraie app Entra
   "non-gallery" en mode provisioning : Test Connection (GET ServiceProviderConfig + get-user)
   puis on-demand provisioning d'un user et d'un groupe.
3. **Okta** (vérifié : la suite existe) : **Okta SCIM 2.0 SPEC test** + **CRUD tests**, suites
   Runscope/BlazeMeter importables — requises pour l'OIN, utiles ici comme batterie de conformité
   même sans publication. Réf : developer.okta.com "Test your SCIM API".
4. **Google Workspace** : pas de validateur public — test manuel via une app SAML custom +
   auto-provisioning sur un domaine de test.
5. **Non-régression** : suite RBAC existante inchangée ; test dédié "SCIM ne touche jamais
   `GroupDefinition.services`".

## 8. Risques

- `Group.members` dérivé par scan des identités : O(n) par GET Groups. Acceptable (< 10k users,
  `getAllIdentitiesWithBindings` a déjà un cache) ; sinon index inverse Redis en phase 3.
- Entra retente agressivement sur 5xx : idempotence requise sur POST (même externalId → 409 propre).
- Deux writers sur `metadata_admin.groups` (console + SCIM) : toujours sous
  `withRedisLock('user-groups:<email>')` — déjà le pattern de `removeGroupFromAllUsers`.

Sources : [RFC 7643](https://datatracker.ietf.org/doc/html/rfc7643) · [RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644) · [Entra SCIM tutorial](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups) · [Entra SCIM Validator](https://scimvalidator.microsoft.com/) · [Okta SCIM tests](https://developer.okta.com/docs/guides/scim-provisioning-integration-test/main/)
