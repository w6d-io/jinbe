import type { RouteRule } from './types.js'
import { GENERATED_ROUTE_MAP } from '../policy/route-map.generated.js'

/**
 * The hand-kept rows of jinbe's route map, for one release beside the generated ones (see the end of
 * this file): public and self-authenticated routes, and the legacy variants already stored in Redis.
 *
 * Routes without a `permission` field are public (OPA policy: routes
 * with no permission requirement allow all authenticated users).
 *
 * Routes with `permission` are gated by the OPA policy comparing
 * the user's aggregated permissions against the route's required permission.
 *
 * `org_param` names the path param carrying the org id: the route is then that
 * org's only (members of it, permission from site ∪ org_grants of it). The
 * policy infers it under /api/organizations/; it is set explicitly anyway.
 */
const HAND_ROUTES: readonly RouteRule[] = [
  // Public routes
  { method: 'GET',    path: '/api/health' },
  { method: 'GET',    path: '/api/whoami' },
  { method: 'GET',    path: '/docs/:any*' },
  // The caller's own two-step status (second-factor/status.ts), asked by kuma on its own host. Marked
  // public: a signed-in caller below aal2 must still reach it (per-site and platform 2FA gate every
  // other signed-in row), or the console cannot tell them to enrol.
  { method: 'GET',    path: '/api/public/second-factor', public: true },

  // SCIM 2.0 provisioning (IdP → jinbe). Public at the OPA layer so the
  // gateway forwards them — the routes enforce their OWN bearer-token auth
  // (middleware/scim-auth.ts, hashed tokens, fail-closed 401). Same pattern
  // as /api/webhooks/kratos: gateway-public, self-authenticated.
  { method: 'GET',    path: '/scim/v2/:any*' },
  { method: 'POST',   path: '/scim/v2/Users' },
  { method: 'PUT',    path: '/scim/v2/Users/:id' },
  { method: 'PATCH',  path: '/scim/v2/Users/:id' },
  { method: 'DELETE', path: '/scim/v2/Users/:id' },

  // Admin user management
  { method: 'GET',    path: '/api/admin/users',                     permission: 'admin:read' },
  { method: 'POST',   path: '/api/admin/users',                     permission: 'admin:create' },
  { method: 'GET',    path: '/api/admin/users/:id',                 permission: 'admin:read' },
  { method: 'PUT',    path: '/api/admin/users/:id',                 permission: 'admin:update' },
  { method: 'DELETE', path: '/api/admin/users/:id',                 permission: 'admin:delete' },
  { method: 'PATCH',  path: '/api/admin/users/:id/state',           permission: 'admin:update' },
  { method: 'PATCH',  path: '/api/admin/users/:id/metadata',        permission: 'admin:update' },
  { method: 'PATCH',  path: '/api/admin/users/:id/organization',    permission: 'admin:update' },
  { method: 'GET',    path: '/api/admin/users/:id/sessions',        permission: 'admin:read' },
  { method: 'DELETE', path: '/api/admin/users/:id/sessions',        permission: 'admin:delete' },
  { method: 'DELETE', path: '/api/admin/sessions/:sessionId',       permission: 'admin:delete' },
  { method: 'GET',    path: '/api/admin/users/:email/groups',       permission: 'admin:read' },
  { method: 'PUT',    path: '/api/admin/users/:email/groups',       permission: 'admin:update' },
  { method: 'POST',   path: '/api/admin/users/:id/recovery-email',  permission: 'admin:update' },
  { method: 'GET',    path: '/api/admin/users/:id/access',          permission: 'admin:read' },
  { method: 'GET',    path: '/api/admin/users/search',              permission: 'admin:read' },
  { method: 'GET',    path: '/api/admin/users/lookup',              permission: 'admin:read' },
  { method: 'POST',   path: '/api/admin/users/:id/login-link',      permission: 'admin:update' },
  { method: 'GET',    path: '/api/admin/users/:id/second-factors',  permission: 'admin:read' },
  { method: 'POST',   path: '/api/admin/users/:id/second-factors/reset', permission: 'admin:update' },

  // User management, one permission per action (support role). ADDED beside the admin:* rows above,
  // never replacing them: OPA allows on ANY matching rule, so administrators keep every route and a
  // role holding only these reaches exactly these. jinbe re-enforces each in the app layer
  // (routes/user-management.routes.ts) — the gateway is not the only way in.
  { method: 'GET',    path: '/api/admin/users',                     permission: 'users:read' },
  { method: 'GET',    path: '/api/admin/users/search',              permission: 'users:read' },
  { method: 'GET',    path: '/api/admin/users/lookup',              permission: 'users:read' },
  { method: 'POST',   path: '/api/admin/users',                     permission: 'users:create' },
  { method: 'GET',    path: '/api/admin/users/:id',                 permission: 'users:read' },
  { method: 'PUT',    path: '/api/admin/users/:id',                 permission: 'users:update' },
  { method: 'PUT',    path: '/api/admin/users/:id',                 permission: 'users:update_email' },
  { method: 'DELETE', path: '/api/admin/users/:id',                 permission: 'users:delete' },
  { method: 'PUT',    path: '/api/admin/users/:email/groups',       permission: 'users:assign_group' },
  { method: 'GET',    path: '/api/admin/users/:id/sessions',        permission: 'sessions:read' },
  { method: 'DELETE', path: '/api/admin/users/:id/sessions',        permission: 'sessions:revoke' },
  { method: 'DELETE', path: '/api/admin/sessions/:sessionId',       permission: 'sessions:revoke' },
  { method: 'POST',   path: '/api/admin/users/:id/recovery-email',  permission: 'users:recovery' },
  { method: 'POST',   path: '/api/admin/users/:id/login-link',      permission: 'users:send_login_link' },
  { method: 'GET',    path: '/api/admin/users/:id/second-factors',  permission: 'users:read' },
  { method: 'POST',   path: '/api/admin/users/:id/second-factors/reset', permission: 'users:reset_second_factor' },

  // RBAC management
  { method: 'GET',    path: '/api/admin/rbac/users',                permission: 'admin:read' },
  { method: 'GET',    path: '/api/admin/rbac/groups',               permission: 'admin:read' },
  { method: 'POST',   path: '/api/admin/rbac/groups',               permission: 'admin:create' },
  { method: 'PUT',    path: '/api/admin/rbac/groups/:name',         permission: 'admin:update' },
  { method: 'DELETE', path: '/api/admin/rbac/groups/:name',         permission: 'admin:delete' },
  { method: 'GET',    path: '/api/admin/rbac/services',             permission: 'admin:read' },
  { method: 'GET',    path: '/api/admin/rbac/services/:name/roles', permission: 'admin:read' },
  { method: 'PUT',    path: '/api/admin/rbac/services/:name/routes', permission: 'admin:update' },
  // Lists what another user holds: only holders of `*` (super_admin, global admin) carry admin:write.
  { method: 'POST',   path: '/api/admin/rbac/access-check',         permission: 'admin:write' },

  // Audit
  // audit/v1 (AUD-9). No gateway permission: an org admin holds no platform permission to test here,
  // and /me/logins is every user's own. jinbe resolves the scope itself (platform audit:read /
  // admin:read → all; org admin → their orgs, org filter injected server-side) and refuses the rest.
  { method: 'GET',    path: '/api/audit/events' },
  { method: 'GET',    path: '/api/audit/events/:eventId' },
  { method: 'GET',    path: '/api/audit/facets' },
  { method: 'GET',    path: '/api/audit/summary' },
  { method: 'GET',    path: '/api/audit/users/:id/timeline' },
  { method: 'GET',    path: '/api/audit/me/logins' },
  { method: 'GET',    path: '/api/audit/tail' },
  { method: 'POST',   path: '/api/audit/exports' },
  { method: 'GET',    path: '/api/audit/exports/:id' },
  { method: 'GET',    path: '/api/audit/exports/:id/download' },
  { method: 'GET',    path: '/api/audit/saved-queries' },
  { method: 'POST',   path: '/api/audit/saved-queries' },
  { method: 'DELETE', path: '/api/audit/saved-queries/:id' },

  // Organization users
  { method: 'GET',    path: '/api/organizations/:organizationId/users',     permission: 'admin:read', org_param: 'organizationId' },
  { method: 'POST',   path: '/api/organizations/:organizationId/users',     permission: 'admin:create', org_param: 'organizationId' },
  { method: 'GET',    path: '/api/organizations/:organizationId/users/:id', permission: 'admin:read', org_param: 'organizationId' },
  { method: 'PUT',    path: '/api/organizations/:organizationId/users/:id', permission: 'admin:update', org_param: 'organizationId' },
  { method: 'DELETE', path: '/api/organizations/:organizationId/users/:id', permission: 'admin:delete', org_param: 'organizationId' },

  // Delegated org-admin reachability. These coexist with the admin:* rules
  // above — the OPA policy allows a request if the caller satisfies ANY matching
  // rule, and the org-scoped clause resolves `org:manage_users` in the org's
  // OWN service (from the :organizationId segment). jinbe then independently
  // re-enforces the specific org (manageable_orgs) + per-group containment.
  //
  // NOTE: org:manage_users gates ALL verbs here (incl. DELETE/PUT user), so an
  // org admin may create/update/DELETE users in their own org — jinbe does not
  // gate these per-verb beyond manageable_orgs. That is deliberate ("manage
  // users" = CRUD within the org); org_admin's finer users:* perms don't
  // independently restrict the verb.
  { method: 'GET',    path: '/api/organizations/:organizationId/users',            permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'POST',   path: '/api/organizations/:organizationId/users',            permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'GET',    path: '/api/organizations/:organizationId/users/:id',        permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'PUT',    path: '/api/organizations/:organizationId/users/:id',        permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'DELETE', path: '/api/organizations/:organizationId/users/:id',        permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'GET',    path: '/api/organizations/:organizationId/users/:id/groups', permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'PUT',    path: '/api/organizations/:organizationId/users/:id/groups', permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'PUT',    path: '/api/organizations/:organizationId/users/:id/membership', permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'GET',    path: '/api/organizations/:organizationId/assignable-groups', permission: 'org:manage_users', org_param: 'organizationId' },

  // Org grants (J-1): the org's admin hands out their org's groups. The gateway admits the roster
  // admin on org:manage_users; jinbe re-checks org admin and asks OPA can_grant per group.
  { method: 'GET',    path: '/api/organizations/:organizationId/grants',           permission: 'org:manage_users', org_param: 'organizationId' },
  { method: 'PUT',    path: '/api/organizations/:organizationId/users/:id/grants', permission: 'org:manage_users', org_param: 'organizationId' },

  // API keys of ONE org (J-3, story 7): its org admin, super_admin, or a member holding
  // org:manage_api_keys there (site ∪ org_grants of that org). jinbe re-enforces the same.
  { method: 'GET',    path: '/api/organizations/:organizationId/api-keys',           permission: 'org:manage_api_keys', org_param: 'organizationId' },
  { method: 'POST',   path: '/api/organizations/:organizationId/api-keys',           permission: 'org:manage_api_keys', org_param: 'organizationId' },
  { method: 'GET',    path: '/api/organizations/:organizationId/api-keys/scopes',    permission: 'org:manage_api_keys', org_param: 'organizationId' },
  { method: 'GET',    path: '/api/organizations/:organizationId/api-key-policy',     permission: 'org:manage_api_keys', org_param: 'organizationId' },
  { method: 'PUT',    path: '/api/organizations/:organizationId/api-key-policy',     permission: 'org:manage_api_keys', org_param: 'organizationId' },
  { method: 'GET',    path: '/api/organizations/:organizationId/api-keys/:clientId', permission: 'org:manage_api_keys', org_param: 'organizationId' },
  { method: 'DELETE', path: '/api/organizations/:organizationId/api-keys/:clientId', permission: 'org:manage_api_keys', org_param: 'organizationId' },

  // Self-service: any authenticated caller may ask which orgs they administer.
  // Returns only the caller's own manageable_orgs; jinbe 401s an anonymous call.
  { method: 'GET',    path: '/api/me/organizations' },
  // What the caller may do (kuma draws only the allowed actions). Answers about the caller only.
  { method: 'GET',    path: '/api/me/permissions' },
  // The caller's own personal API keys (404 unless MCP is on: DELEGATED_TOKENS_ENABLED + Settings → AI assistants). About the caller only;
  // jinbe refuses machine and delegated callers, and checks the org policy and scopes itself.
  { method: 'GET',    path: '/api/me/api-keys' },
  { method: 'GET',    path: '/api/me/api-keys/scopes' },
  { method: 'POST',   path: '/api/me/api-keys' },
  { method: 'DELETE', path: '/api/me/api-keys/:clientId' },
  // Is MCP on (env ceiling + the administrator's switch) and where is its server — for kuma Connections.
  { method: 'GET',    path: '/api/mcp/status' },
] as const

/**
 * What the bootstrap merges into Redis: the hand rows, then the rows generated from the routes jinbe
 * declares (policy/route-map.ts), each (method, path, permission) once. Additive: the merge never
 * deletes, so a holder of a legacy name keeps every route it reached.
 */
export const JINBE_BUILT_IN_ROUTES: readonly RouteRule[] = (() => {
  const seen = new Set<string>()
  return [...HAND_ROUTES, ...GENERATED_ROUTE_MAP].filter((r) => {
    const key = `${r.method} ${r.path} ${r.permission ?? ''}`
    return seen.has(key) ? false : (seen.add(key), true)
  })
})()
