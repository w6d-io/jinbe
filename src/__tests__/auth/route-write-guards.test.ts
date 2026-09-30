import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { declaredRoutes, resetDeclaredRoutes, type DeclaredRoute } from '../../policy/declared-routes.js'

/**
 * No route that changes something may be satisfiable by a READ permission, or by a session alone.
 *
 * Read off the table the running service declares (policy/declared-routes.ts), which is collected
 * from the guards Fastify actually attached — so a write added behind a plugin's `admin:read` gate,
 * or with no guard at all, fails the build here rather than shipping. That is how RBAC groups, roles
 * and route maps ended up editable by a read-only administrator (a privilege escalation).
 *
 * A route may be listed below only when it is safe for a reason the table cannot see; each says why.
 * An entry that no longer matches a route fails too, so the list cannot rot into a blanket pass.
 */

const READ_VERBS = new Set(['GET', 'HEAD', 'OPTIONS'])

/** A permission that only grants reading. */
const readOnly = (permission: string) => /:(read|list)$/.test(permission)

const EXCEPTIONS: Record<string, string> = {
  // ── Writes nothing (computeOnly: a POST only because the input is a body) ─────────────────────
  'POST /api/admin/sites/zones/suggest': 'computes a suggested zone for a host; writes nothing',
  'POST /api/admin/sites/match': 'which gateway rule and route a request would hit (gatekit); writes nothing',
  'POST /api/admin/sites/render': 'renders a header/claims template as Oathkeeper would (gatekit); writes nothing',
  'POST /api/admin/sites/:name/verify': 'reads the rollout, asks the policy and sends anonymous GET/HEAD probes to the public URL; writes nothing (1 per site per 30 s)',
  'POST /api/admin/gateway/preview': 'validates a proposed gateway configuration; writes nothing',

  // ── The caller's own objects ───────────────────────────────────────────────────────────────────
  'POST /api/audit/saved-queries': "the caller's own saved query; a shared one is refused outside the caller's audit scope",
  'DELETE /api/audit/saved-queries/:id': "deletes only the caller's own saved query (keyed on the caller)",
  'POST /api/me/api-keys': "the caller's own personal key, scopes capped at what they hold; refused to delegated callers",
  'DELETE /api/me/api-keys/:clientId': "revokes the caller's own personal key; refused to delegated callers",

  // ── Decided in the handler, against the item ───────────────────────────────────────────────────
  'POST /api/admin/recert/items/:campaignId/:itemId/decision':
    'the assigned reviewer, or else admin:write (requireSuperAdmin in the handler); self-review blocked',

  // ── Machine callers with their own credential (no session) ─────────────────────────────────────
  'POST /api/mcp/token-info': 'auth-mcp only: allowed ServiceAccount actor token; answers about a token',
  'POST /api/mcp/personal-keys/exchange': 'auth-mcp only: actor token + the personal key secret itself',
  'POST /api/webhooks/kratos': 'Kratos after-hooks, authenticated by the shared webhook secret',
  'POST /api/webhooks/kratos/guard': 'Kratos before-hooks, authenticated by the shared webhook secret',
  'POST /api/public/sign-in-protection/gate/self-service/:flow': 'the gateway judging an anonymous sign-in submit; by design pre-auth',
  'POST /scim/v2/Users': 'SCIM bearer token (scim-auth)',
  'PUT /scim/v2/Users/:id': 'SCIM bearer token (scim-auth)',
  'PATCH /scim/v2/Users/:id': 'SCIM bearer token (scim-auth)',
  'DELETE /scim/v2/Users/:id': 'SCIM bearer token (scim-auth)',
}

/**
 * Every route the session gate lets through with NO session, and what guards it instead. A route
 * reachable with no credential at all shipped once already (`GET /api/opa/bundle`, every address's
 * groups for anyone in the cluster), so a new one fails here until somebody says what guards it.
 */
const NO_SESSION: Array<[RegExp, string]> = [
  [/^\/api\/(health|whoami|telemetry)$/, 'truly public: liveness, the caller\'s own identity, the telemetry address'],
  [/^\/api\/public\//, 'login-ui before sign-in: branding and settings, rate limited; access-reason and mine read the visitor\'s own cookie'],
  [/^\/docs(\/|$)/, 'API documentation (ENABLE_SWAGGER)'],
  [/^\/api\/admin\/rbac\/(bindings|opal-datasource|opal\/)/, 'OPAL feeds: requireOpalClient (OPAL client token)'],
  [/^\/api\/opa\/(policy|status)$/, 'OPA engines: machineOnly (machine token, hashed at rest)'],
  [/^\/api\/opa\/propagation$/, 'machine token, or an administrator (admin:read)'],
  [/^\/api\/directory\//, 'machine token checked by the plugin hook'],
  [/^\/api\/mcp\/(token-info|personal-keys\/exchange)$/, 'auth-mcp: allowed ServiceAccount actor token'],
  [/^\/api\/mcp\/status$/, 'checks the session itself; answers only whether MCP is on'],
  [/^\/api\/oathkeeper\/rules$/, 'Oathkeeper rules sync (in-cluster; every upstream — owner decision pending)'],
  [/^\/api\/webhooks\/kratos(\/guard)?$/, 'Kratos hooks: shared webhook secret'],
  [/^\/scim\/v2\//, 'SCIM bearer token (scim-auth)'],
]

const key = (r: DeclaredRoute) => `${r.method} ${r.path}`

function weak(r: DeclaredRoute): boolean {
  if (READ_VERBS.has(r.method)) return false
  if (r.class !== 'authorized') return true
  return readOnly(r.permission ?? '')
}

let app: FastifyInstance
let rows: DeclaredRoute[]

beforeAll(async () => {
  process.env.NODE_ENV = 'development'
  process.env.DEV_BYPASS_AUTH = 'true'
  process.env.ENCRYPTION_KEY = 'x'.repeat(32)
  process.env.DEV_USER_EMAIL = 'dev@localhost.io'
  resetDeclaredRoutes()
  const { buildServer } = await import('../../server.js')
  app = await buildServer()
  rows = declaredRoutes()
}, 30_000)

afterAll(async () => { await app?.close() })

describe('every write route asks for more than reading', () => {
  it('no non-GET route is satisfiable by a read-only permission or a session alone', () => {
    const offenders = rows.filter((r) => weak(r) && !(key(r) in EXCEPTIONS))
      .map((r) => `${key(r)} → ${r.class}${r.permission ? ` ${r.permission}` : ''}`)
    expect(offenders, 'guard these with a write permission, or add a justified EXCEPTIONS entry').toEqual([])
  })

  it('every exception still names a weak route (no stale entries)', () => {
    const weakKeys = new Set(rows.filter(weak).map(key))
    expect(Object.keys(EXCEPTIONS).filter((k) => !weakKeys.has(k))).toEqual([])
  })

  it('every route reachable without a session is one whose own guard is named', () => {
    const unexplained = rows.filter((r) => r.class === 'public' && !NO_SESSION.some(([p]) => p.test(r.path))).map(key)
    expect(unexplained).toEqual([])
    expect(rows.find((r) => r.path === '/api/opa/bundle')).toBeUndefined()
  })

  it('the table is the running service, not an empty one', () => {
    expect(rows.filter((r) => !READ_VERBS.has(r.method)).length).toBeGreaterThan(100)
  })

  it('pins the permissions of the writes this check was written for', () => {
    const permission = (method: string, path: string) => rows.find((r) => r.method === method && r.path === path)?.permission
    for (const [method, path] of [
      ['POST', '/api/admin/rbac/groups'], ['PUT', '/api/admin/rbac/groups/:name'], ['DELETE', '/api/admin/rbac/groups/:name'],
      ['PUT', '/api/admin/rbac/services/:name/roles'], ['PUT', '/api/admin/rbac/services/:name/routes'],
      ['PUT', '/api/admin/rbac/org-service-map'], ['DELETE', '/api/admin/rbac/org-service-map/:organizationId'],
      ['POST', '/api/admin/recert/campaigns'], ['POST', '/api/admin/recert/campaigns/:id/close'],
    ]) expect(permission(method, path), `${method} ${path}`).not.toMatch(/:read$|^admin:/)
    for (const [method, path, want] of [
      ['POST', '/api/admin/rbac/groups', 'groups:write'], ['PUT', '/api/admin/rbac/services/:name/roles', 'groups:write'],
      ['PUT', '/api/admin/rbac/org-service-map', 'groups:write'], ['POST', '/api/admin/recert/campaigns/:id/close', 'recert:manage'],
      ['PATCH', '/api/admin/users/:id/state', 'users:disable'], ['PATCH', '/api/admin/users/:id/metadata', 'users.metadata:write'],
      ['PATCH', '/api/admin/users/:id/organization', 'org.members:write'],
      ['PUT', '/api/organizations/:organizationId/users/:id/grants', 'org.members:write'],
    ]) expect(permission(method, path), `${method} ${path}`).toBe(want)
    for (const r of rows.filter((r) => /^\/api\/(clusters|databases|backups|backup-items|database-apis)(\/|$)/.test(r.path))) {
      expect(r.permission, key(r)).toBe('*')
    }
  })
})
