<h1 align="center">Jinbe</h1>

<p align="center"><strong>The RBAC control plane for self-hosted auth.</strong></p>

<p align="center">
  Identity groups · service roles · route permissions · OPA bundles · Oathkeeper rules — one API.
</p>

<p align="center">
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="https://nodejs.org/"><img alt="Node ≥ 22" src="https://img.shields.io/badge/node-%E2%89%A522-339933?logo=node.js&logoColor=white"></a>
  <a href="https://www.typescriptlang.org/"><img alt="TypeScript" src="https://img.shields.io/badge/typescript-strict-3178C6?logo=typescript&logoColor=white"></a>
  <a href="https://fastify.dev/"><img alt="Fastify" src="https://img.shields.io/badge/fastify-4-000000?logo=fastify&logoColor=white"></a>
  <img alt="Tests" src="https://img.shields.io/badge/tests-450%2B%20passing-brightgreen">
  <a href="https://www.conventionalcommits.org/"><img alt="Conventional Commits" src="https://img.shields.io/badge/conventional%20commits-1.0.0-FE5196?logo=conventionalcommits&logoColor=white"></a>
  <a href="./CONTRIBUTING.md"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen"></a>
</p>

<p align="center">
  <sub>Self-hosted alternative to managed OAuth platforms · MIT · Production-grade · Multi-tenant ready</sub>
</p>

---

Jinbe is the management layer that glues [Ory Kratos](https://www.ory.sh/kratos/) (identity), [Ory Oathkeeper](https://www.ory.sh/oathkeeper/) (API gateway), [OPAL](https://github.com/permitio/opal) (policy distribution) and [OPA](https://www.openpolicyagent.org/) (policy engine) into a single, programmable RBAC system. Together, that stack is a self-hosted alternative to managed OAuth and SSO products like Auth0, Okta or Cognito — without the per-MAU bill, without vendor lock-in, and without giving up control of identity data.

Where the others are protocol servers, Jinbe is the **API + audit + policy authorship layer** on top. One HTTP surface for users, groups, services, roles, route-permissions, Oathkeeper rules, and OPA bundles. Everything is versioned in Redis, streamed through OPAL, and audited to a stream you can ship anywhere.

---

## What you get

| Concern | What Jinbe does |
|---|---|
| **Identity groups** | Reads / writes `metadata_admin.groups` on Kratos identities |
| **Service roles** | Stores `role → permission` maps per registered service in Redis |
| **Route permissions** | Maps HTTP `method + path` to a required permission |
| **Oathkeeper rules** | Serves access rules dynamically over HTTP — no ConfigMap reload |
| **OPA policy sync** | Exposes an OPA bundle endpoint; OPAL pulls and distributes it |
| **Multi-tenant scoping** | Org-scoped user management endpoints (`/api/organizations/:orgId/...`) |
| **Privilege-escalation guards** | 422-gated assignment of admin-power groups, with optional MFA enforcement |
| **Audit log** | Every mutation and authz decision appended to a Redis Stream |
| **Backup / restore** | Bundle export + import for full RBAC + identity snapshots |
| **Bootstrap** | Seeds default groups, roles and Oathkeeper rules on first start |

---

## Architecture

```
            Browser / API client
                    │
                    ▼
            Oathkeeper proxy  ◄── access rules ──  Jinbe  /api/oathkeeper/rules
                    │                                  │
       cookie_session ──► Kratos                       │  RBAC data (Redis)
       remote_json    ──► OPA                          │
                              ▲                        │
                          OPAL client                  │
                              │                        │
                          OPAL server ◄── Jinbe  /api/opa/bundle
                              │
                              ▼
                       Upstream service
                  (sees X-User-Id, X-User-Email, X-User-Groups)
```

### Request flow

1. Browser hits Oathkeeper.
2. Oathkeeper checks the session via Kratos `/sessions/whoami`.
3. Oathkeeper asks OPA at `/v1/data/rbac/allow` with `{ subject, email, groups, path, method }`.
4. OPA decides using RBAC data that OPAL last pushed.
5. On allow, Oathkeeper forwards the request with identity headers injected.
6. Jinbe is the source of truth — it serves both the Oathkeeper rule feed and the OPA data bundle.

---

## Stack requirements

| Component | Role | Min version |
|---|---|---|
| [Ory Kratos](https://www.ory.sh/kratos/docs/) | Identity & session | v1.x |
| [Ory Oathkeeper](https://www.ory.sh/oathkeeper/docs/) | Gateway / access proxy | v0.40+ |
| [OPAL Server + Client](https://docs.opal.ac/) | Policy + data distribution | v0.7+ |
| [OPA](https://www.openpolicyagent.org/) | Policy evaluation | v0.60+ |
| Redis | RBAC store + audit stream | v7+ |

Jinbe doesn't replace any of these. It's the API and the audit on top.

---

## Quick start (local)

```bash
git clone https://github.com/<org>/jinbe
cd jinbe
cp .env.example .env       # edit ENCRYPTION_KEY at minimum
docker compose up -d       # Redis + OPA + Jinbe
```

- API → http://localhost:3000
- Swagger → http://localhost:3000/docs
- Healthz → http://localhost:3000/health

For a full stack (Kratos + Oathkeeper + OPAL + OPA + Redis + Jinbe), see [Helm chart](#helm-chart).

### Minimal required env

| Variable | Purpose |
|---|---|
| `ENCRYPTION_KEY` | ≥ 32 chars. Encrypts stored DB credentials. |
| `REDIS_URL` | RBAC store + audit stream. Defaults to `redis://redis:6379`. |
| `KRATOS_PUBLIC_URL` / `KRATOS_ADMIN_URL` | Ory Kratos endpoints. |
| `OPA_URL` | Where the admin middleware queries OPA. |

The full list lives in [.env.example](./.env.example) — every variable is documented.

### First-run bootstrap admin

```bash
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=<at-least-12-characters>
ADMIN_NAME=Admin
```

These are only consulted on the very first start (empty Redis). On subsequent restarts, bootstrap is a no-op.

---

## API overview

### Auth
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/whoami` | Current session identity |

### Users (global admin)
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/users` | List Kratos identities. Response includes `credentials.{totp,webauthn,lookup_secret}` so admin UIs can render 2FA state. |
| `GET / PUT` | `/api/admin/users/:email/groups` | Get or set a user's groups. See [security gates](#security-gates). |

### Users (org-scoped)
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/organizations/:orgId/users` | List users in an org |
| `POST` | `/api/organizations/:orgId/users` | Create user in an org |
| `GET / PUT / DELETE` | `/api/organizations/:orgId/users/:id` | Per-user operations |
| `GET / PUT` | `/api/organizations/:orgId/users/:id/groups` | Org-scoped group management. Caller's authorization is resolved via OPA against the target org — no global admin needed. |

### Groups
| Method | Path | Description |
|---|---|---|
| `GET / POST` | `/api/admin/rbac/groups` | List / create groups |
| `PUT / DELETE` | `/api/admin/rbac/groups/:name` | Update / delete a group |

### Services
| Method | Path | Description |
|---|---|---|
| `GET / POST` | `/api/admin/rbac/services` | List / register a service (creates default roles + Oathkeeper rule) |
| `DELETE` | `/api/admin/rbac/services/:name` | Delete service + all associated data |
| `GET / PUT` | `/api/admin/rbac/services/:name/roles` | Read / replace service role-permission map |
| `GET / PUT` | `/api/admin/rbac/services/:name/routes` | Read / replace route-permission map |

### Access rules
| Method | Path | Description |
|---|---|---|
| `GET / POST` | `/api/admin/rbac/access-rules` | List / create Oathkeeper access rules |
| `PUT / DELETE` | `/api/admin/rbac/access-rules/:id` | Update / delete an access rule |
| `GET` | `/api/oathkeeper/rules` | **Feed Oathkeeper points its `repositories` at this URL.** |

### Audit
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/audit/events` | Audit event stream |
| `GET` | `/api/admin/rbac/history` | Mutation history |

### Bundle
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/rbac/bundle/export` | Export full RBAC + identities snapshot |
| `POST` | `/api/admin/rbac/bundle/import` | Import a bundle (replaces RBAC, upserts identities) |

### OPA / OPAL
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/opa/bundle` | OPA policy bundle (tar.gz) |
| `GET` | `/api/admin/rbac/opal-datasource` | OPAL external data source config |

---

## Security gates

`PUT /api/admin/users/:email/groups` (and the org-scoped equivalent) enforce two non-bypassable rules whenever a *newly added* group grants admin power:

| Status | `error` | Trigger |
|---|---|---|
| `422` | `privilege_escalation_blocked` | The actor doesn't hold the authority to grant that level. Global path: actor isn't a `super_admin`. Org-scoped path: actor doesn't hold `*` permission for the target org. |
| `422` | `mfa_required` | The *target* user has no second factor configured (TOTP / WebAuthn / lookup secret) but is being added to a system + admin-power group. |

**Why 422 and not 403:** ingress-nginx `custom-http-errors` rewrites 4xx / 5xx through a default backend that strips the response body and CORS headers. 422 isn't in that list, so the body and `Access-Control-Allow-Origin` reach the browser — clients can render meaningful toasts instead of "Failed to fetch."

**Fail-closed identity resolution:** if Kratos cannot resolve the target user, the request returns `404 Not Found`. Previously the admin path silently returned `200` with `id: null`, which bypassed the MFA gate when Kratos was degraded. That hole is now closed.

---

## Bootstrap behaviour

On first start with an empty Redis:

1. Creates default groups: `super_admins`, `admins`, `devs`, `viewers`, `users`.
2. Creates default roles for `global` and `jinbe` services.
3. Seeds Oathkeeper access rules templated from `AUTH_DOMAIN`, `APP_DOMAIN`, `API_DOMAIN`.
4. Creates the bootstrap admin identity in Kratos (if `ADMIN_EMAIL` is set).
5. Retries up to 15× in background if Redis or Kratos are not ready yet.

Subsequent restarts are idempotent — bootstrap is skipped when the bootstrap marker is present.

A pre-flight helper for migrating an existing cluster (originally bootstrapped under an older inline code path) is in [`scripts/seed-bootstrap-marker.sh`](./scripts/seed-bootstrap-marker.sh).

---

## Helm chart

A Helm chart is published separately and bundles the full stack (Kratos, Oathkeeper, OPAL, OPA, Redis, Jinbe) so a fresh cluster can come up with one `helm install`.

### Minimum viable values

```yaml
global:
  domain: example.com   # used to derive auth.<domain>, app.<domain>, api.<domain>

jinbe:
  enabled: true
  env:
    ENCRYPTION_KEY: "" # REQUIRED — ≥ 32 chars
```

That's it. Every other URL is templated from the Helm release name + namespace + `global.domain` (see [auto-computed below](#auto-computed-by-the-chart)).

### Full env catalog

#### Required

| Variable | Notes |
|---|---|
| `ENCRYPTION_KEY` | ≥ 32 chars. Encrypts stored DB credentials at rest. |

#### First-boot bootstrap admin (optional — only consulted with an empty Redis)

| Variable | Default | Notes |
|---|---|---|
| `ADMIN_EMAIL` | unset | If set, creates a Kratos identity with this email on first boot. |
| `ADMIN_PASSWORD` | unset | ≥ 12 chars. Required if `ADMIN_EMAIL` is set. |
| `ADMIN_NAME` | `Admin` | Display name for the bootstrap admin. |

#### Auto-computed by the chart

Every value in this group can be overridden via `jinbe.env.<NAME>` but you almost never need to. The chart templates them from the Helm release.

| Variable | Auto-computed as |
|---|---|
| `REDIS_URL` | `redis://<release>-redis-master:6379` |
| `KRATOS_PUBLIC_URL` | `http://<release>-kratos-public:80` |
| `KRATOS_ADMIN_URL` | `http://<release>-kratos-admin:80` |
| `OPA_URL` | `http://<release>-opal-client:8181` |
| `OPAL_SERVER_URL` | `http://<release>-opal-server:7002` |
| `OPA_DATA_URL` | `http://<release>-opal-client:8181` |
| `OPA_AUTHZ_REMOTE` | `http://<release>-opa-authz-proxy:8080/v1/data/rbac/allow` |
| `JINBE_INTERNAL_URL` | `http://<release>-jinbe:8080` (URL opal-server uses to fetch RBAC data) |
| `LOGIN_UI_URL` | `http://<release>-kratos-login-ui:80` |
| `ADMIN_UI_URL` | `http://<release>-admin-ui:80` |
| `AUTH_DOMAIN` | `global.authDomain` or `auth.<global.domain>` |
| `APP_DOMAIN` | `global.appDomain` or `app.<global.domain>` |
| `API_DOMAIN` | same as `APP_DOMAIN` |
| `SERVICE_DEFAULT_NAMESPACE` | `.Release.Namespace` |
| `SERVICE_DEFAULT_DOMAIN` | same as `APP_DOMAIN` |
| `SERVICE_DEFAULT_PORT` | `8080` |
| `CORS_ORIGIN` | `https://<APP_DOMAIN>,https://<AUTH_DOMAIN>` |
| `RELEASE_NAME` | `.Release.Name` |
| `APP_VERSION` | `image.tag` or `Chart.AppVersion` |
| `COMMIT_SHA` | same as `APP_VERSION` |

#### Server runtime (override only if you need to)

| Variable | Default | Notes |
|---|---|---|
| `NODE_ENV` | `production` | |
| `PORT` | `3000` | Container listens on this port. |
| `HOST` | `0.0.0.0` | |
| `BASE_URL` | unset | Absolute external URL of the API. Drives `links` in responses. |
| `LOG_LEVEL` | `info` | `fatal\|error\|warn\|info\|debug\|trace`. |
| `ENABLE_SWAGGER` | `false` (chart) / `true` (raw) | Toggles `/docs`. Disabled by default in chart for production. |
| `APP_NAME` | `jinbe` | Identifier passed to OPA for fine-grained authorization. |

#### CORS

| Variable | Default | Notes |
|---|---|---|
| `CORS_ORIGIN` | auto (chart) / `*` (raw) | Comma-separated allow-list. |
| `CORS_CREDENTIALS` | `false` | Set `true` to enable `Access-Control-Allow-Credentials`. |
| `DISABLE_CORS` | `true` (chart `extraEnv`) / `false` (raw) | Set `true` when an upstream proxy (ingress-nginx / Oathkeeper) emits its own CORS headers — prevents browsers rejecting duplicate `Access-Control-Allow-Origin`. |

#### Rate limiting

| Variable | Default | Notes |
|---|---|---|
| `RATE_LIMIT_MAX` | `100` | Requests per window. |
| `RATE_LIMIT_TIME_WINDOW` | `60000` | Window in milliseconds. |

#### Redis

| Variable | Default | Notes |
|---|---|---|
| `REDIS_URL` | auto | See above. |
| `REDIS_PASSWORD` | unset | If your Redis requires AUTH. |
| `REDIS_DB` | `0` | Logical DB index. |
| `REDIS_AUDIT_STREAM` | `auth:audit:events` | Stream key for audit events. |

#### Database (optional — only for `/clusters`, `/databases`, `/backups` features)

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | unset | MongoDB connection string. If unset, those features are inert. |

#### Backup tool (optional — only if the `/backups` feature is exposed)

| Variable | Default | Notes |
|---|---|---|
| `BACKUP_IMAGE_MONGO` | unset | Private-registry image for the mongo backup container. |
| `BACKUP_IMAGE_POSTGRES` | unset | Private-registry image for the postgres backup container. |
| `BACKUP_GCP_PROJECT_ID` | unset | GCP project ID injected into the backup job env (for GCS output). |

#### Dev / debugging (never enable in production)

| Variable | Default | Notes |
|---|---|---|
| `DEV_BYPASS_AUTH` | `false` | Skip Kratos session check; injects a fake user. Only effective when `NODE_ENV=development`. |
| `DEV_USER_EMAIL` | unset | Email used for the dev fake user. |

#### Bootstrap reset (DANGEROUS — CLI only, never used at runtime)

| Variable | Default | Notes |
|---|---|---|
| `JINBE_BOOTSTRAP_DANGEROUS_RESET` | `false` | Set `true` to wipe-and-reseed via the CLI. |
| `JINBE_BOOTSTRAP_RESET_CONFIRM` | unset | Must equal the running image SHA. Guard against accidental fat-fingered resets. |

### Full example

```yaml
global:
  domain: mycorp.com

jinbe:
  enabled: true
  image:
    repository: ghcr.io/<your-org>/jinbe
    tag: ""                          # defaults to Chart.AppVersion
  env:
    ENCRYPTION_KEY: ""               # REQUIRED — ≥ 32 chars
    ADMIN_EMAIL: admin@mycorp.com    # optional — bootstrap admin
    ADMIN_PASSWORD: ""               # ≥ 12 chars
    ADMIN_NAME: Admin
    DATABASE_URL: ""                 # optional — only for /clusters, /databases, /backups
    LOG_LEVEL: info
    ENABLE_SWAGGER: "false"
  extraEnv:
    DISABLE_CORS: "true"             # leave CORS to ingress-nginx
```

Everything else is auto-derived. Override any `auto-computed` value via `jinbe.env.<NAME>` if your topology differs.

---

## Development

```bash
npm install
npm run dev          # hot reload via tsx watch
npm test             # vitest, ~450 tests
npm run typecheck    # tsc --noEmit
npm run lint
```

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for branch naming, commit format, and the release flow (`develop` → `main` → tag).

---

## License

MIT
