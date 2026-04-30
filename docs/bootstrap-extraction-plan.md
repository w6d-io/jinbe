# Jinbe Bootstrap Extraction — Implementation Plan

Status: planning complete, audited, ready to implement
Owner: Maxime Bachelet
Reviewed against: `gitlab.w6d.io/infra/opal-policies` (master, sha 8a1a335) and `auth-w6d` Helm chart

---

## 1. Goal

Extract all RBAC bootstrap logic out of the jinbe API server (`src/server.ts` lines 166–526) into:

1. A pure module `src/bootstrap/` (functions, no I/O wiring)
2. A standalone CLI entrypoint `src/cli/bootstrap.ts` (same Docker image)
3. A Helm post-install/post-upgrade Job (`charts/auth/templates/jinbe/bootstrap-job.yaml`)
4. A Redis idempotency marker `rbac:bootstrap:state`
5. A startup gate in the API server that waits for the marker

Outcome: server process no longer mutates RBAC config at startup. Cluster has a single, ordered bootstrap step with explicit success/failure semantics.

---

## 2. Verified facts (do not re-verify during implementation)

### OPA policy (rbac.rego master)

- `super_admins` group with only `global:[super_admin]` is sufficient — the `allow { user_permissions["*"] }` rule (line 200) short-circuits route matching when any role contributes `"*"`. The seed at `server.ts:172` is correct as-is. Do NOT add `jinbe:[admin]` or `kuma:[admin]` to super_admins.
- Routes in `route_map` without a `permission` field are public — `allow { rule := matching_rules[_]; not rule.permission }` (line 207). `/api/health` and `/api/whoami` rely on this.
- Wildcard `"*"` is matched only via the `user_permissions["*"]` rule (line 200) — explicit, not implicit.

### Helm naming (release `auth-w6d`)

| Logical | K8s service | RBAC service id | Oathkeeper rule(s) targeting it |
|---|---|---|---|
| jinbe API | `auth-w6d-jinbe` | `jinbe` | kuma-api-preflight, kuma-api, jinbe-preflight, jinbe-public, jinbe-api |
| admin UI | `auth-w6d-admin-ui` | **`kuma`** (intentional split) | kuma-app |
| kratos public | `auth-w6d-kratos-public` | — | kratos-public |
| kratos admin | `auth-w6d-kratos-admin` | — | — |
| login UI | `auth-w6d-kratos-login-ui` | — | selfservice-ui, kuma-settings |
| opal server | `auth-w6d-opal-server` | — | — |
| opal client (OPA) | `auth-w6d-opal-client` | — | — |
| opa-authz-proxy | `auth-w6d-opa-authz-proxy` | — | (referenced in oathkeeper config remote_json) |
| redis | `auth-w6d-redis-master` | — | — |
| global (virtual) | n/a | `global` | — |

The `kuma` ↔ `admin-ui` mismatch is intentional. Document in `seed-kuma.ts` and in `values.yaml`.

### All oathkeeper upstream URLs verified — no mismatches.

---

## 3. Architecture

### Bootstrap CLI is the same image, different command

| Pod | Command | When |
|---|---|---|
| API Deployment | `node dist/server.js` | always running |
| Bootstrap Job | `node dist/cli/bootstrap.js` | post-install, post-upgrade hooks |

Single Dockerfile, single image, no duplication.

### Idempotency marker schema (`rbac:bootstrap:state`)

```json
{
  "version": "v0.3.0",
  "schemaVersion": 1,
  "gitSha": "abc1234",
  "bootstrappedAt": "2026-04-30T12:00:00Z",
  "lastUpgradeAt": "2026-04-30T13:00:00Z",
  "previousSchemaVersion": null,
  "migrations": [
    { "from": null, "to": 1, "appliedAt": "2026-04-30T12:00:00Z", "gitSha": "abc1234" }
  ],
  "builtInsHash": {
    "rules":    "sha256:...",
    "routeMap": "sha256:..."
  }
}
```

Decision logic in CLI:

| Marker state | Action |
|---|---|
| absent | full first-run seed (groups, roles, services, kuma, admin user, rules, route_map) |
| present, schemaVersion matches, builtInsHash matches | exit 0, no work |
| present, schemaVersion matches, builtInsHash differs | re-upsert built-in rules + route_map only |
| present, marker.schemaVersion < SCHEMA_VERSION | run delta migrations from marker.schemaVersion → SCHEMA_VERSION |
| present, marker.schemaVersion > SCHEMA_VERSION | exit 4 (schema downgrade) |
| present but malformed JSON | exit 5 (corruption) |
| `JINBE_BOOTSTRAP_DANGEROUS_RESET=true` AND `JINBE_BOOTSTRAP_RESET_CONFIRM=<gitSha>` matches | clear marker + full re-seed |

### Concurrent run protection

CLI takes a Redis lock at start:
```
SET rbac:bootstrap:lock <hostname>-<pid> NX EX 600
```
On failure (another CLI running): exit 0 with informational log. Released in `finally` via `DEL rbac:bootstrap:lock` after marker write.

### API server startup gate

Replace the inline bootstrap block with:
```
await waitForBootstrap({ timeoutMs: 360_000, intervalMs: 5_000 })
```
Polls `rbac:bootstrap:state`. Distinguishes:
- Redis unreachable → warn-level log, retry
- Marker absent → info-level log, retry
- Marker present, malformed → exit 5
- Timeout (6min) → exit 2

Server only registers `/api/health` AFTER `waitForBootstrap` resolves.
**Deployment must add a `startupProbe` (failureThreshold=72, periodSeconds=5 = 6min budget)** so liveness doesn't kill the pod during the wait.

---

## 4. Code layout

### New module: `src/bootstrap/`

| File | Source range (server.ts) | Purpose |
|---|---|---|
| `index.ts` | — | Orchestrator `runBootstrap(opts)`, exports `SCHEMA_VERSION` |
| `types.ts` | — | `RunBootstrapOptions`, `BootstrapMarker`, `BootstrapConfig` |
| `marker.ts` | new | Read/write `rbac:bootstrap:state`, detect schema mismatches |
| `lock.ts` | new | Redis SETNX lock with TTL |
| `wait-deps.ts` | new | Wait for Redis PING + Kratos /health/ready |
| `hash.ts` | new | Canonical-JSON sha256 for `builtInsHash` |
| `seed-rbac.ts` | 170–194 | Initial groups/roles/services seed |
| `build-rules.ts` | 209–343 | Pure: env → `OathkeeperRule[]` (one builder per rule ID) |
| `upsert-rules.ts` | 345–351 | Merge built-in + custom, write to Redis |
| `build-route-map.ts` | 356–428 | Pure: built-in route list constant |
| `merge-route-map.ts` | 429–436 | Read existing, append missing routes |
| `seed-kuma.ts` | 440–472 | Kuma service + propagation (wrapped in MULTI/EXEC) |
| `seed-admin.ts` | 474–498 | Create Kratos admin identity (handle 409 explicitly) |

### New CLI: `src/cli/bootstrap.ts`

Imports and invokes `runBootstrap(config)`. Reads env once, validates, builds `BootstrapConfig`, passes to orchestrator. Never mixes I/O with logic.

### Modified files

- `src/server.ts` — remove lines 166–526, add `waitForBootstrap()` call before `fastify.listen()`. Health route registered after wait.
- `src/config/env.ts` — add zod entries: `ADMIN_EMAIL` (email), `ADMIN_PASSWORD` (min 12), `ADMIN_NAME` (string), `RELEASE_NAME` (string), FQDN regex on `AUTH_DOMAIN`/`APP_DOMAIN`/`API_DOMAIN`. Drop `OPAL_RBAC_BRANCH` (unused).
- `src/services/redis-rbac.repository.ts` — add `getBootstrapMarker`, `setBootstrapMarker`, `clearBootstrapMarker`, `acquireBootstrapLock`, `releaseBootstrapLock`.
- `package.json` — add scripts:
  - `bootstrap`: `node dist/cli/bootstrap.js`
  - `bootstrap:dev`: `tsx src/cli/bootstrap.ts`
- `tsconfig.json` — confirm `src/cli/**/*` and `src/bootstrap/**/*` included.

### New tests under `src/__tests__/bootstrap/`

- `marker.test.ts` — roundtrip, malformed, downgrade detection
- `lock.test.ts` — concurrent acquire denied; release cleans up; expired lock recovered
- `seed-rbac.test.ts` — empty Redis seeds 5 groups; populated Redis no-ops
- `build-rules.test.ts` — 9 tests, one per rule ID (selfservice-ui through jinbe-api)
- `upsert-rules.test.ts` — custom rules preserved on built-in re-upsert
- `build-route-map.test.ts` — snapshot of full 70-route list
- `merge-route-map.test.ts` — user-modified permission preserved; new built-in route added
- `seed-kuma.test.ts` — APP_DOMAIN absent throws; transactional propagation rolls back on partial failure
- `seed-admin.test.ts` — 409 swallowed; 500 throws; missing email throws
- `orchestrator.test.ts` — full happy path; force flag with mismatched SHA aborts; downgrade exits 4

CI: add `madge --circular src/` to detect import cycles.

### New script

`scripts/seed-bootstrap-marker.sh` — pre-flight migration helper. Reads current jinbe image SHA from cluster, writes the marker JSON to Redis. Idempotent (overwrites existing marker only with `--force`). Used once during the cut-over deploy on dev/prod.

---

## 5. Helm chart changes

### `charts/auth/templates/_helpers.tpl`

Add `auth.jinbe.env` define producing the full env list (extracted from current `templates/jinbe/deployment.yaml` lines 33–97). Strip these env vars (not needed by the bootstrap CLI):
- `PORT`, `HOST`
- `OPA_URL`, `OPAL_SERVER_URL`, `OPA_DATA_URL` (runtime-only)
- `CORS_ORIGIN`, `ENABLE_SWAGGER`, `INTERNAL_TRUSTED_HOSTS` (HTTP middleware)
- `DATABASE_URL` (Mongo — bootstrap doesn't touch it)
- `OPAL_RBAC_BRANCH` (dead env — also remove from Deployment)

Keep for both Deployment and Job:
- `NODE_ENV`, `APP_NAME`, `LOG_LEVEL`, `RELEASE_NAME` (new)
- `REDIS_URL`, `KRATOS_PUBLIC_URL`, `KRATOS_ADMIN_URL`, `JINBE_INTERNAL_URL`
- `LOGIN_UI_URL`, `ADMIN_UI_URL`
- `AUTH_DOMAIN`, `APP_DOMAIN`, `API_DOMAIN`
- `ENCRYPTION_KEY` (Vault)
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME` (Vault recommended for ADMIN_PASSWORD)
- `extraEnv` map (rate-limit overrides etc.)

Add `auth.jinbe.podAnnotations` define that merges `.Values.jinbe.podAnnotations` with the required Vault annotations (vault-addr, vault-role, vault-skip-verify). Both Deployment pod template and Job pod template include it via `{{- include "auth.jinbe.podAnnotations" . | nindent 8 }}`.

### `charts/auth/templates/jinbe/deployment.yaml`

Changes:
- Replace inline env with `{{- include "auth.jinbe.env" . | nindent 12 }}`
- Replace inline podAnnotations with `{{- include "auth.jinbe.podAnnotations" . | nindent 8 }}`
- Add `startupProbe`:
  ```yaml
  startupProbe:
    httpGet:
      path: /api/health
      port: http
    periodSeconds: 5
    failureThreshold: 72   # 6 minutes
  ```
- Keep liveness/readiness as-is.

### New: `charts/auth/templates/jinbe/bootstrap-job.yaml`

Stable name `auth-w6d-jinbe-bootstrap` (no `.Release.Revision` — broken under ArgoCD, see Audit A3). Dual annotations for ArgoCD + Helm:

```yaml
{{- if .Values.jinbe.bootstrap.enabled }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "auth.jinbe.fullname" . }}-bootstrap
  labels:
    {{- include "auth.jinbe.labels" . | nindent 4 }}
  annotations:
    helm.sh/hook: post-install,post-upgrade
    helm.sh/hook-weight: "5"
    helm.sh/hook-delete-policy: before-hook-creation
    argocd.argoproj.io/hook: PostSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  template:
    metadata:
      labels:
        {{- include "auth.jinbe.labels" . | nindent 8 }}
      annotations:
        {{- include "auth.jinbe.podAnnotations" . | nindent 8 }}
    spec:
      restartPolicy: OnFailure
      {{- if and .Values.jinbe.enabled .Values.jinbe.serviceAccount.create }}
      serviceAccountName: {{ include "auth.jinbe.serviceAccountName" . }}
      {{- end }}
      containers:
        - name: bootstrap
          image: "{{ .Values.jinbe.image.repository }}:{{ .Values.jinbe.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.jinbe.image.pullPolicy }}
          command: ["node", "dist/cli/bootstrap.js"]
          env:
            {{- include "auth.jinbe.env" . | nindent 12 }}
          {{- with .Values.jinbe.bootstrap.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
{{- end }}
```

Notes:
- `backoffLimit: 0` — single attempt; failures preserve logs for inspection.
- No `ttlSecondsAfterFinished` — Helm hook lifecycle handles cleanup.
- `before-hook-creation` only — keeps last failed Job in cluster until next deploy.

### `charts/auth/values.yaml` additions

```yaml
jinbe:
  bootstrap:
    enabled: true
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 200m
        memory: 256Mi
```

### ArgoCD sync waves

Add annotations on key resources (only if not already present in subcharts):
- Redis StatefulSet: `argocd.argoproj.io/sync-wave: "-2"`
- Kratos StatefulSet: `argocd.argoproj.io/sync-wave: "-1"`
- Jinbe Bootstrap Job: handled by `argocd.argoproj.io/hook: PostSync`
- Jinbe Deployment: `argocd.argoproj.io/sync-wave: "1"`
- OPAL server: `argocd.argoproj.io/sync-wave: "2"`

---

## 6. Required env vars and validation

### Bootstrap-mandatory (CLI exits 1 if missing)

- `REDIS_URL`
- `KRATOS_ADMIN_URL`
- `JINBE_INTERNAL_URL`
- `AUTH_DOMAIN` — must be FQDN
- `APP_DOMAIN` — must be FQDN
- `LOGIN_UI_URL`
- `ADMIN_UI_URL`
- `ENCRYPTION_KEY` — Vault-injected, min 32 chars
- `RELEASE_NAME` (new, for log correlation)

### First-bootstrap-only mandatory (CLI exits 1 if marker absent AND any missing)

- `ADMIN_EMAIL` — valid email
- `ADMIN_PASSWORD` — min 12 chars
- `ADMIN_NAME` (optional, defaults to "Admin")

### Subsequent runs (marker present)

- ADMIN_* env optional — skipped silently if marker exists

### Removed

- `OPAL_RBAC_BRANCH` (dead env, never read)

---

## 7. Phased execution

| Phase | Scope | Files touched | Behavior change | Risk |
|---|---|---|---|---|
| 1 | Extract bootstrap into `src/bootstrap/` module. server.ts still calls inline. | src/bootstrap/* | none | none |
| 2 | Add CLI entrypoint, npm scripts. Test locally against docker-compose Redis. | src/cli/bootstrap.ts, package.json | none (unused) | low |
| 3 | Add marker + lock + waitForBootstrap. server.ts ignores marker (still does inline as fallback). | redis-rbac.repository.ts, src/bootstrap/marker.ts, src/bootstrap/lock.ts | none | none |
| 4 | Add Helm bootstrap-job template + extract `_helpers.tpl` env define. `helm template` lint. | charts/auth/templates/jinbe/*, _helpers.tpl, values.yaml | added Job runs but server still bootstraps inline (double-write OK, idempotent) | low |
| 5 | Pre-flight: run `scripts/seed-bootstrap-marker.sh` on dev cluster. Verify marker readable. Deploy phase-4 image. | (operations) | none | low |
| 6 | **Cut-over commit:** remove inline bootstrap from server.ts. Add `startupProbe` to Deployment. Bump schemaVersion to 1. | server.ts, deployment.yaml | server now requires marker to start | medium |
| 7 | Cleanup: remove dead `bootstrapWithRetry`, retry wrapper, dead `OPAL_RBAC_BRANCH` env. | server.ts, deployment.yaml | none | none |
| 8 | Tests: add `src/__tests__/bootstrap/*`. Add `madge --circular` to CI. | tests, CI config | none | none |

Phases 1–4 land in one PR (back-compat). Phase 6 is the cut-over PR — coordinated with the live-cluster manual marker seed (Phase 5).

---

## 8. Live-cluster migration (zero-downtime)

Existing dev/prod has data in Redis. Migration steps:

1. **Scale API to 0** (avoids race between old pod's inline bootstrap and manual marker SET):
   ```bash
   kubectl -n auth-w6d scale deploy/auth-w6d-jinbe --replicas=0
   ```
2. **Run pre-flight script** to seed marker:
   ```bash
   ./scripts/seed-bootstrap-marker.sh auth-w6d
   ```
   Writes `rbac:bootstrap:state` with `manualMigration: true` flag.
3. **Bump image to phase-6 tag** in `gitops/auth-w6d/values.yaml`. Commit + push.
4. ArgoCD reconciles → bootstrap Job runs → sees marker → exits 0 → API Deployment scales up.
5. New API pod starts → `waitForBootstrap()` sees marker immediately → registers `/api/health` → readiness probe passes.
6. Verify: `kubectl logs job/auth-w6d-jinbe-bootstrap` shows "skipping (marker present)".

If the marker seeding is forgotten:
- Bootstrap Job runs full first-time seed
- `seed-rbac` sees existing groups → no-op (idempotent)
- `seed-admin` → Kratos returns 409 → handled explicitly in new code
- `seed-kuma` → kuma already exists check → no-op
- Net: still safe, but emits noisier logs and writes an "initial" marker that lacks the manual-migration audit trail. Prefer the explicit pre-flight.

---

## 9. Failure modes and recovery

| Failure | Behavior | Recovery |
|---|---|---|
| Redis unreachable during CLI | wait-deps retries 60s, then exit 2 | Fix Redis, re-trigger Job (`kubectl delete job ...; argocd app sync`) |
| Kratos unreachable during CLI | wait-deps retries 60s, then exit 2 | Same |
| Lock contention (concurrent Job) | exit 0 with info log | None — design intent |
| Schema downgrade (marker.schemaVersion > SCHEMA_VERSION) | exit 4 | Roll forward; never run older bootstrap on newer data |
| Schema upgrade (marker.schemaVersion < SCHEMA_VERSION) | run delta migrations, write new marker | Automatic |
| `builtInsHash` mismatch only | re-upsert built-in rules + route_map (preserves custom rules + user permission overrides) | Automatic |
| Marker JSON corrupt | exit 5 | Manual intervention: delete + re-run with `JINBE_BOOTSTRAP_DANGEROUS_RESET=true` + `JINBE_BOOTSTRAP_RESET_CONFIRM=<image-sha>` |
| Helm rollback fires post-upgrade hook | Job sees current marker, detects rollback if previousSchemaVersion > marker.schemaVersion | Logs warn, updates `lastUpgradeAt` only, does not re-seed |
| API pod startup probe times out (6min) | pod CrashLoopBackOff → alert | Investigate Job logs first; fix root cause; restart pod |
| Bootstrap Job times out (`activeDeadlineSeconds: 600`) | Job marked failed, pod stays for log inspection (no auto-cleanup) | `kubectl logs` → diagnose → fix → re-trigger sync |

---

## 10. Net code reduction

- `src/server.ts`: -360 lines (inline bootstrap + retry wrapper)
- `src/bootstrap/`: +~600 lines spread over 13 files (one concern per file, testable)
- `src/cli/bootstrap.ts`: +~80 lines (env validation + orchestrator call + exit codes)
- Tests: +~800 lines (was ~zero coverage of bootstrap)
- `_helpers.tpl`: +~80 lines (env define + podAnnotations define)
- `bootstrap-job.yaml`: +~50 lines
- `deployment.yaml`: -50 lines (env extracted) + 8 lines (startupProbe)
- `scripts/seed-bootstrap-marker.sh`: +~30 lines

Net: more total lines but dramatically lower complexity per file and full test coverage on a previously untested critical path.

---

## 11. Security guards

1. `ADMIN_PASSWORD` default `'changeme123!'` removed (currently in server.ts:476). CLI exits 1 if absent on first bootstrap.
2. `JINBE_BOOTSTRAP_DANGEROUS_RESET=true` requires second guard `JINBE_BOOTSTRAP_RESET_CONFIRM=<gitSha-of-running-image>` to match. Emits CRITICAL audit log on use.
3. Lock TTL bounded (600s) — stuck CLI cannot deadlock the system indefinitely.
4. FQDN regex on domain inputs prevents URL/typo injection into oathkeeper rule generation.
5. CLI runs with the same Vault-scoped ServiceAccount as the API — no new RBAC surface in the cluster.
6. Marker JSON bounded in size — Redis key holds at most a few KB.

---

## 12. Open items deferred to v2

- Fine-grained schema migrations (the `migrations[]` array in the marker is recorded but not yet *applied* — currently any schemaVersion bump just re-runs built-in rules + route_map). True per-version migration handlers are out of scope for v1.
- Marker backup/restore script (`marker-export.sh`, `marker-import.sh`) for cross-cluster cloning.
- Bootstrap status surfaced via `/api/health` response (`bootstrap.lastRunAt`, `bootstrap.schemaVersion`).
- Dry-run mode (`--dry-run`) on the CLI — useful in CI to validate env without writes.

---

## 13. Acceptance criteria

- [ ] `npm test` passes on the jinbe repo with the new bootstrap test suite (≥80% line coverage on `src/bootstrap/**`).
- [ ] `madge --circular src/` reports no cycles.
- [ ] `helm template charts/auth -f gitops/auth-w6d/values.yaml -f dev-aws-1/auth-w6d/values.yaml` renders without errors.
- [ ] Bootstrap Job runs to completion on a fresh `kind` cluster within 90s.
- [ ] On the existing dev cluster, post-cut-over the Bootstrap Job exits 0 and reports "marker present, skipping".
- [ ] After a `kubectl delete pod` on the API, new pod boots within 30s (marker already present).
- [ ] Removing the marker key (`redis-cli DEL rbac:bootstrap:state`) and triggering a sync recreates the same RBAC state byte-for-byte (verified via `redis-cli KEYS rbac:* | xargs -L1 redis-cli GET` diff before/after).
- [ ] No `process.env` reads inside `src/bootstrap/**` except in the CLI entrypoint and config loader.
