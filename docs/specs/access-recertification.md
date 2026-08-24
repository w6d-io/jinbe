# Access Recertification Campaigns

**Statut** : draft · **Objectif** : campagnes périodiques de revue des accès (qui garde quoi),
avec décision tracée, révocation automatique à échéance et rapport exportable.
**Conformité** : ISO 27001 A.9.2.5 (review of user access rights) / SOC 2 CC6.2–CC6.3.

## 1. Positionnement

La page kuma **AccessReview** (`kuma/src/pages/AccessReview.tsx`, backend
`jinbe/src/services/access-review.service.ts`) est un **instantané** read-only "qui peut faire
quoi" avec scoring de risque. La recertification est le processus complémentaire : transformer
cet instantané en **items de décision assignés à des reviewers, avec deadline et conséquence**.
Décision : nouvelle feature à part (service + routes + page), qui **réutilise** l'access-review
comme contexte d'aide à la décision (tier/flags affichés sur chaque item), sans le modifier.

## 2. Modèle de données

```
Campaign {
  id: string (nanoid)            name: string
  scope: {                       // filtre de génération d'items
    groups?: string[]            // défaut: tous les groupes rbac:groups
    services?: string[]          // → groupes dont la GroupDefinition référence ces services
    orgs?: string[]              // → membres des rosters rbac:org_admins de ces orgs
  }
  reviewerPolicy: 'group-owners' | 'org-admins' | 'explicit'
  reviewers?: string[]           // emails, si explicit (fallback des 2 autres politiques)
  schedule: { kind: 'one-shot' } | { kind: 'cron', expr: string }   // expr node-cron
  deadline: string               // ISO, ou durée relative pour les cron (ex: 'P14D')
  onExpiry: 'revoke' | 'flag'
  status: 'draft'|'active'|'closing'|'completed'|'archived'
  createdBy, createdAt, closedAt?
}

ReviewItem {
  id: string                     campaignId: string
  subject: string                // email du user revu
  entitlement: { kind: 'group-membership', group: string }
                                 // extensible: 'org-admin' (roster rbac:org_admins) en phase 3
  reviewer: string               // email assigné
  decision: 'pending'|'approved'|'revoked'
  decidedBy?, decidedAt?, comment?
  outcome?: 'kept'|'auto-revoked'|'flagged'|'revoke-applied'   // rempli à la clôture
  context: { tier, flags[], lastActive }   // snapshot access-review au moment de la génération
}
```

`reviewerPolicy` résolu à la **génération** (pas à la lecture) : `org-admins` → roster Redis
`rbac:org_admins` de l'org du scope ; `group-owners` → nouveau champ optionnel `owners: string[]`
sur `ResourceMetadata` du groupe (`redis-rbac.repository.ts`), fallback `reviewers` explicites.
Garde-fou : un reviewer ne peut pas décider un item dont il est le sujet — l'item est réassigné
au fallback (sinon flag `self-review` bloquant, cohérent avec le flag `self-granted` existant).

## 3. Stockage Redis (pattern du repo)

Même style que le keyspace documenté en tête de `src/services/redis-rbac.repository.ts` :

```
rbac:recert:campaigns                → Hash { campaignId: JSON(Campaign) }
rbac:recert:items:{campaignId}      → Hash { itemId: JSON(ReviewItem) }
rbac:recert:inbox:{reviewerEmail}   → Set  [ "{campaignId}:{itemId}" ]   (index inverse inbox)
rbac:recert:reports                 → Hash { campaignId: JSON(CompletionReport) }  (immuable)
```

Écritures d'items sous `withRedisLock('recert:{campaignId}')` (`src/services/redis-lock.ts`) —
même pattern que `user-groups`. Pas de TTL : les rapports sont des preuves d'audit ; purge
manuelle via `archived` + export préalable. Inclus dans le bundle export/import RBAC ? **Non**
(phase 1) — données de processus, pas de configuration ; à réévaluer phase 3.

## 4. Flux

1. **Création (kuma)** — nouvelle page **Recertification** (route `/recertification`) : wizard
   scope → reviewers → schedule/deadline → onExpiry, avec preview du nombre d'items. `draft`
   puis `activate`.
2. **Génération des items (jinbe)** — à l'activation (et à chaque tick cron) :
   `kratosService.getAllIdentitiesWithGroups()` (walk groupes→membres via `metadata_admin.groups`),
   intersection avec le scope, un item par (user, groupe), enrichi du snapshot
   `accessReviewService.getAccessReview()` (tier/flags), reviewers résolus, inbox peuplées.
3. **Inbox reviewer (kuma)** — onglet "My reviews" de la page Recertification :
   `GET /api/admin/recert/inbox` (l'email vient du `UserContext` posé par
   `src/middleware/identity-extractor.ts`). Décision item par item ou bulk approve, commentaire
   obligatoire sur `revoked`. Contexte affiché : tier/flags (réutilise `TIER_META`/`FLAG_META`
   d'`AccessReview.tsx` — à extraire dans un module partagé).
4. **Audit** — chaque décision → `auditEventService.emit` (catégorie `access`, kind `change`,
   target `recert:{campaignId}:{itemId}`, severity `warn` sur revoke). L'auto-revoke à échéance
   est émis avec actor système, comme les jobs existants.
5. **Deadline job** — `node-cron` (déjà en dépendance, pattern
   `src/services/backup-scheduler.service.ts` : `cron.schedule(expr, …, { timezone: 'UTC' })`) :
   un scheduler unique scanne les campagnes actives chaque heure. Deadline atteinte →
   `status: 'closing'` ; items `pending` traités selon `onExpiry` :
   - `revoke` : retrait du groupe via `updateUserGroups` (Kratos), outcome `auto-revoked` ;
   - `flag` : outcome `flagged` (apparaît dans le rapport + badge AccessReview).
   Les items `revoked` par un reviewer sont appliqués **immédiatement** à la décision (pas à la
   clôture) — décision : une révocation validée ne doit pas attendre la deadline.
   Multi-replica : job sous `withRedisLock('recert:scheduler')`.
6. **Rapport de complétion** — figé dans `rbac:recert:reports` à la clôture : compteurs
   (approved/revoked/auto-revoked/flagged, taux de complétion par reviewer), liste intégrale des
   items avec décideur/date/commentaire, et mapping conformité en en-tête (ISO 27001 A.9.2.5,
   SOC 2 CC6.2 "access authorization" / CC6.3 "access modification & removal"). Export CSV + JSON
   signés par le hash du rapport (`GET /report?format=csv`).

## 5. Notifications

Réutilise l'outbox existante `src/services/notifications/` (Redis stream `notifications:outbox`,
consumer groups, retry/backoff — déjà en place). Contrainte constatée : `EntityEvent.entity_type`
est limité à `'user' | 'organization' | 'role'` et le seul transport est `http-notifier.ts`
(webhook générique) — **pas d'email natif**. Décisions :
- étendre `entity_type` avec `'recertification'` (changement de type, trivial) ;
- événements émis : `campaign.activated` (vers les reviewers), `reminder` (J-7/J-1 via le
  scheduler), `campaign.closed` (vers le créateur) ;
- l'email effectif est délégué au consommateur webhook en phase 1/2 ; un `Notifier` SMTP ou
  Kratos-courier est un chantier séparé (phase 3, optionnel).

## 6. API (préfixe `/api/admin/recert`, auth admin via `require-admin.ts`, permission `rbac:write`)

```
POST   /campaigns                 créer (draft)          GET  /campaigns, /campaigns/:id
POST   /campaigns/:id/activate    générer items          POST /campaigns/:id/close  (clôture manuelle)
DELETE /campaigns/:id             draft/archived only
GET    /campaigns/:id/items       (filtres decision/reviewer, pagination)
GET    /inbox                     items pending du caller (toute identité authentifiée, pas admin)
POST   /items/:campaignId/:itemId/decision   { decision, comment? }   (reviewer assigné ou admin)
GET    /campaigns/:id/report      ?format=json|csv
```

## 7. Rollout — 3 phases

**Phase 1 — Cœur one-shot (≈ 6 j·h)** : modèle + keyspace + `recert.service.ts` + routes
campaigns/items/decision (reviewers explicites uniquement), génération d'items, application
immédiate des revokes, audit. Page kuma Recertification (liste + wizard + inbox). Pas de cron,
pas de deadline automatique : clôture manuelle.

**Phase 2 — Deadline, scheduler, notifications (≈ 5 j·h)** : `recert-scheduler.service.ts`
(node-cron + lock), `onExpiry` revoke/flag, campagnes cron récurrentes, reviewerPolicy
`org-admins` (roster existant) et `group-owners` (champ `owners`), events outbox + reminders,
rapport de complétion + export CSV.

**Phase 3 — Conformité & confort (≈ 4 j·h)** : entitlement `org-admin` (revue des rosters
`rbac:org_admins`), badge "flagged in last campaign" dans AccessReview, bulk decisions kuma,
notifier email optionnel, page Audit filtrable sur `recert:*`.

Nouveaux fichiers — jinbe : `src/services/recert.service.ts`, `src/services/recert-scheduler.service.ts`,
`src/services/redis-recert.repository.ts`, `src/routes/recert.routes.ts` (+ enregistrement
`src/server.ts`, prefix `/admin/recert`). Kuma : `src/pages/Recertification.tsx`, hooks dans
`src/api/hooks.ts` + `mutations.ts`, extraction `TIER_META/FLAG_META` vers `src/components/ui`.

## 8. Stratégie de test

1. **Unit (vitest)** : résolution de scope (groups/services/orgs → items attendus), résolution
   reviewers + garde-fou self-review, transitions d'état campagne, idempotence de la génération
   (re-activation d'un cron ne duplique pas les items pending).
2. **Intégration Redis** : keyspace, locks concurrents (deux décisions simultanées sur le même
   item → une seule gagne), inbox cohérente après décision.
3. **Deadline job** : horloge simulée (vi.useFakeTimers) — auto-revoke retire réellement le
   groupe dans un Kratos mocké, `flag` ne touche pas le membership, replica double sous lock
   n'applique qu'une fois.
4. **E2E audit** : chaque décision et auto-revoke visible dans le stream d'audit avec
   actor/target corrects ; rapport CSV relu et comparé aux items.
5. **Conformité** : jeu de données de démo + rapport généré, relu contre la checklist
   A.9.2.5/CC6.2-CC6.3 (le rapport doit répondre seul à "qui a revu quoi, quand, décision,
   conséquence appliquée").

## 9. Risques

- Révoquer le dernier groupe d'un user le laisse sans accès : conserver le groupe par défaut
  `users` hors scope de révocation (whitelist), comme le défaut de `kratos.service.ts`.
- Groupes SCIM-managed (cf. `docs/specs/scim-provisioning.md`) : la révocation console serait
  écrasée au prochain sync IdP → sur ces items, `revoke` produit un outcome `flagged` + notification
  "révoquer côté IdP", jamais un write local.
- Volume d'items (users × groupes) : génération paresseuse paginée côté lecture ; hash Redis par
  campagne borne le blast radius.
