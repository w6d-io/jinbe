# Jinbe

RBAC control plane for [Ory](https://www.ory.sh/) auth stacks.

Jinbe sits between [Kratos](https://www.ory.sh/kratos/) (identity), [Oathkeeper](https://www.ory.sh/oathkeeper/) (API gateway) and [OPA](https://www.openpolicyagent.org/) (policy engine) to give you a unified API for managing who can do what, across which services.

---

## What it does

| Concern | How |
|---|---|
| **Identity groups** | Reads/writes `metadata_admin.groups` on Kratos identities |
| **Service roles** | Stores role→permission maps per service in Redis |
| **Route permissions** | Maps HTTP method+path to a required permission |
| **Oathkeeper rules** | Serves access rules dynamically via HTTP (no ConfigMap reload) |
| **OPA policy sync** | Exposes an OPA bundle endpoint; [OPAL](https://github.com/permitio/opal) pulls and distributes it |
| **Audit log** | Appends every mutation and auth decision to a Redis Stream |
| **Bundle export/import** | Full snapshot of RBAC config + identities for backup and restore |
| **Bootstrap** | Seeds default groups, roles, and access rules on first start — no manual init |

---

## Architecture

```
Browser / API client
        │
        ▼
  Oathkeeper proxy  ◄── access rules ──  Jinbe /api/oathkeeper/rules
        │                                       │
        │  cookie_session ──► Kratos            │  RBAC data (Redis)
        │  remote_json    ──► OPA               │
        │                      ▲                │
        │                   OPAL client         │
        │                      │                │
        │                   OPAL server ◄── Jinbe /api/opa/bundle
        │
        ▼
   Upstream service  (receives X-User-Id, X-User-Email, X-User-Groups headers)
```

### Request flow

1. Browser hits Oathkeeper proxy
2. Oathkeeper checks session with Kratos (`/sessions/whoami`)
3. Oathkeeper asks OPA (`/v1/data/rbac/allow`) with subject, email, groups, path, method
4. OPA evaluates policy using RBAC data last pushed by OPAL
5. On allow: request forwarded with identity headers injected
6. Jinbe serves the RBAC data that feeds OPA via OPAL's data source endpoint

---

## Stack requirements

| Component | Role | Min version |
|---|---|---|
| [Ory Kratos](https://www.ory.sh/kratos/docs/) | Identity & session management | v1.x |
| [Ory Oathkeeper](https://www.ory.sh/oathkeeper/docs/) | API gateway / access proxy | v0.40+ |
| [OPAL Server + Client](https://docs.opal.ac/) | Policy & data distribution | v0.7+ |
| [OPA](https://www.openpolicyagent.org/docs/latest/) | Policy evaluation engine | v0.60+ |
| Redis | RBAC data store + audit stream | v7+ |

Jinbe does **not** replace any of these — it is the glue that keeps them in sync.

---

## Quick start

```bash
cp .env.example .env   # fill in required values
docker compose up -d   # starts Redis + OPA
# API → http://localhost:3000
# Swagger → http://localhost:3000/docs
```

Required env vars:

| Variable | Description |
|---|---|
| `ENCRYPTION_KEY` | 32-char key for encrypting sensitive values at rest |
| `REDIS_URL` | Redis connection string (`redis://localhost:6379`) |
| `KRATOS_PUBLIC_URL` | Kratos public API (`http://kratos-public:80`) |
| `KRATOS_ADMIN_URL` | Kratos admin API (`http://kratos-admin:80`) |
| `OPA_URL` | OPA REST API (`http://opa:8181`) |

Bootstrap admin on first start:

```bash
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=ChangeMe123!
ADMIN_NAME=Admin
```

---

## API overview

### Auth
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/whoami` | Current session identity |

### Groups
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/rbac/groups` | List all groups |
| `POST` | `/api/admin/rbac/groups` | Create group |
| `PUT` | `/api/admin/rbac/groups/:name` | Update group service→roles mapping |
| `DELETE` | `/api/admin/rbac/groups/:name` | Delete group |

### Services
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/rbac/services` | List services |
| `POST` | `/api/admin/rbac/services` | Register service (creates default roles + Oathkeeper rule) |
| `DELETE` | `/api/admin/rbac/services/:name` | Delete service and all associated data |
| `GET/PUT` | `/api/admin/rbac/services/:name/roles` | Get or update service roles |
| `GET/PUT` | `/api/admin/rbac/services/:name/routes` | Get or update route→permission map |

### Access rules (Oathkeeper)
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/rbac/access-rules` | List all access rules |
| `POST` | `/api/admin/rbac/access-rules` | Create access rule |
| `PUT` | `/api/admin/rbac/access-rules/:id` | Update access rule |
| `DELETE` | `/api/admin/rbac/access-rules/:id` | Delete access rule |
| `GET` | `/api/oathkeeper/rules` | **Oathkeeper rule feed** — set as `repositories` in Oathkeeper config |

### Users
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/users` | List Kratos identities |
| `GET/PUT` | `/api/admin/users/:email/groups` | Get or set user groups |

### Audit
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/audit/events` | Audit event stream |
| `GET` | `/api/admin/rbac/history` | Mutation history |

### Bundle (backup & restore)
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/admin/rbac/bundle/export` | Export full RBAC + identities snapshot |
| `POST` | `/api/admin/rbac/bundle/import` | Import bundle (replaces RBAC, upserts identities) |

### OPA / OPAL
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/opa/bundle` | OPA policy bundle (tar.gz) |
| `GET` | `/api/admin/rbac/opal-datasource` | OPAL external data source config |

---

## Helm chart

Jinbe is distributed as part of the [w6d-io/charts](https://github.com/w6d-io/charts) `auth` chart, which bundles the full stack (Kratos, Oathkeeper, OPAL, OPA, Redis, Jinbe).

```yaml
jinbe:
  enabled: true
  image:
    repository: ghcr.io/w6d-io/jinbe
    tag: ""           # defaults to chart appVersion
  env:
    ENCRYPTION_KEY: ""   # required — 32 chars
    ADMIN_EMAIL: ""      # optional — creates admin on first boot
    ADMIN_PASSWORD: ""
```

---

## Bootstrap behaviour

On first start with an empty Redis:

1. Creates default groups: `super_admins`, `admins`, `devs`, `viewers`, `users`
2. Creates default roles for `global` and `jinbe` services
3. Seeds Oathkeeper access rules derived from `AUTH_DOMAIN`, `APP_DOMAIN`, `API_DOMAIN`
4. Creates admin identity in Kratos (if `ADMIN_EMAIL` is set)
5. Retries up to 15× in background if Redis or Kratos is not ready yet

Subsequent restarts are idempotent — bootstrap is skipped if groups already exist.

---

## Development

```bash
npm install
npm run dev          # hot reload via tsx watch
npm test             # vitest
npm run typecheck    # tsc --noEmit
npm run lint
```

---

## License

MIT
