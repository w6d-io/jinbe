# Where organisations are kept

jinbe owns organisations (`ORGANISATION_SOURCE=directory`, the default) through a single interface,
`src/services/organisation-store.ts`. There are two stores behind it, and every route, the OPA
policy bundle and the OPAL feeds read the same shapes whichever one is running.

| `ORGANISATION_STORE` | Memberships, org roles, groups | Organisation records and entitlements | Default when |
|---|---|---|---|
| `kratos` | The Kratos identity (see below) | Redis | `ORGANISATION_DATABASE_URL` is not set |
| `postgres` | `organisation_members` and `group_members` rows (the identity is kept in step) | `organisations` and `organisation_deployments` | `ORGANISATION_DATABASE_URL` is set |

The organisation routes answer `503 organisation_directory_unavailable` with `reason: not_configured`
in one case only: `ORGANISATION_STORE=postgres` is set and there is no URL. The console then says
what to set.

## The kratos store

Each fact has one home, and nothing is written twice.

**On the identity**, the same place every service that reads an identity already looks:

| Field | Holds |
|---|---|
| `organization_id` | the primary organisation (Kratos's own column) |
| `metadata_admin.organizations` | every other organisation |
| `metadata_admin.organization_roles` | `{orgId: [role]}`, for anything beyond plain membership |
| `metadata_admin.groups` | the groups |

The OPAL `/bindings` feed builds `user_organizations`, `user_organization_primary` and
`group_membership` from these fields, so what OPA enforces (including
`rbac.delegation.manageable_orgs`) is exactly what is stored. It is not a copy.

**In Redis**, beside the rest of the RBAC model (org grants, the org-admin roster, the
org → service map), which is unchanged:

| Key | Holds |
|---|---|
| `rbac:organisations` | id → `{id, name, tenant, attributes}`. `tenant` is the slug and `attributes` the settings. |
| `rbac:organisation_deployments` | id → `{application: enabled}`, the entitlements. The policy bundle's `ory.entitlements` is built from it. |

### Writes

- **Locking.** Every write to an identity goes through `KratosService.updateAdminState`. It takes a Redis lock (`rbac:lock:identity:<id>`) and re-reads the identity inside the lock. It then sends one JSON Patch that names only the keys that changed, so the primary organisation and the list always move together. Kratos v26.2 has no etag, and its PATCH refuses `test`, so this lock is the compare-and-set. The group editor (`updateUserGroups`) and the metadata editor go through the same path, which means a group change and a membership change made at the same moment both land.
- **Fan-out.** After every organisation or membership write, the directory cache is dropped on every replica, the home screens recount, and `rbacService.invalidateBundle` schedules the OPAL push. A change is enforced immediately, not at the next poll.
- **Unknown organisations.** Adding somebody to an organisation the registry does not hold is refused (404 `organisation_not_found`). Somebody already in an older organisation that predates the registry can still be edited.
- **Deleting.** Deleting an organisation that still has members is refused (409 `organisation_in_use`, with the count).

### Reads

The kratos store adds no cache of its own. It reads through the shared cache layer (`src/cache/swr.ts`), and every write drops the affected entries on every replica before it returns.

- **Someone's organisations, on a scoped request:** `kratos.identity` via `getIdentityCached`. `patchIdentity` drops it on each membership write.
- **Someone's current groups before a group change, and the write itself:** the identity is read fresh, never from a cache.
- **Everybody** (the members of an organisation, the policy bundle's `ory.membership`, the stats): read from the one directory walk (`kratos.directory`). Reads that decide something (the policy bundle, whether anyone still belongs, an import's replace) allow a snapshot at most 5 s old, the same bound as the OPAL feed. Display reads allow `DERIVED_MAX_AGE_MS` (30 s).
- **The registry:** `org.registry` and `org.deployments`, each a single cached entry, dropped on every registry write.

### API

| Method | Route | Needs |
|---|---|---|
| `GET` | `/api/admin/organizations` | `admin.organisation:read` |
| `POST` | `/api/admin/organizations` `{name, tenant?}` | `admin.organisation:write` |
| `PATCH` | `/api/admin/organizations/:id` `{name?, tenant?, applications?}` (applications is a whole set) | `admin.organisation:write` |
| `DELETE` | `/api/admin/organizations/:id` (only when empty) | `admin.organisation:write` |

Members and org admins use the existing routes: `/api/organizations/:id/users…` and
`/api/admin/rbac/org-admin-map`.

## Moving from postgres to kratos

Nothing deployed today keeps organisations in Postgres. This path is for a deployment that does.

1. **Export from Postgres.** This only reads.

   ```sh
   ORGANISATION_STORE=postgres node dist/cli/export-organisations.js > organisations.json
   ```

   The document holds every organisation with its deployments and members (with roles), plus every
   subject's groups as `group_members` records them. That table is the one the engine decided with
   in the postgres store.

2. **Report against the kratos store.** Point it at the same Kratos and Redis. Nothing is written;
   it prints what would change, including each subject whose groups differ.

   ```sh
   ORGANISATION_STORE=kratos node dist/cli/import-organisations.js organisations.json
   ```

3. **Apply.**

   ```sh
   ORGANISATION_STORE=kratos node dist/cli/import-organisations.js organisations.json --apply
   ```

   - The registry records and deployments are written to Redis.
   - Each organisation's members are made exactly the exported set on the identities, with their roles.
   - Each exported subject's groups are made exactly the exported set.
   - Every write is keyed on its id, so a rerun after a failure finishes the job, and a second run changes nothing.
   - Nothing absent from the document is deleted.

4. **Switch jinbe over.** Set `ORGANISATION_STORE=kratos` (or unset `ORGANISATION_DATABASE_URL`) and
   roll it out. The Postgres database can be kept as a backup and dropped later.

To go back, run the same two commands with the stores swapped. `export-organisations` also works as
a backup of the kratos store's registry.
