import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { declaredRoutes, resetDeclaredRoutes, type DeclaredRoute } from '../../policy/declared-routes.js'
import { CATALOG, PERMISSIONS, PLATFORM_PERMISSIONS, isCatalogPermission, scopeOf } from '../../policy/catalog.js'
import { ROLES } from '../../policy/roles.js'
import { routeMapRows } from '../../policy/route-map.js'
import { GENERATED_ROUTE_MAP } from '../../policy/route-map.generated.js'

/**
 * CI rules 1, 3, 4 and 5 of staff-rbac-proposal §3, over the route table the running service declares.
 * (Rule 2, writes need more than reading, is route-write-guards.test.ts.)
 */

/**
 * Catalogue permissions no route DECLARES, because a route's own guard asks for them — each says
 * where. An entry that a route starts declaring, or that stops existing, fails.
 */
const CHECKED_INSIDE_A_GUARD: Record<string, string> = {
  'org.audit:read': 'audit/query/scope.ts — the org part of the audit scope (the audit routes are scoped by their own guard)',
  'sites.signup:write': 'sites/apply.service.ts assertMayWidenSignUp — publishing a version that opens or widens public sign-up (on top of sites:apply)',
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
  await app.ready()
  rows = declaredRoutes().filter((r) => r.method !== 'HEAD')
}, 30_000)
afterAll(async () => { await app?.close() })

const key = (r: DeclaredRoute) => `${r.method} ${r.path}`

describe('every route declares what it needs (rule 1)', () => {
  it('a catalogue permission, or why it needs none', () => {
    const undecided = rows.filter((r) => !r.path.startsWith('/docs'))
      .filter((r) => !(r.permission && isCatalogPermission(r.permission)) && !r.access)
      .map(key)
    expect(undecided).toEqual([])
  })

  it('an org permission exactly on a route naming an org parameter, a platform one everywhere else', () => {
    const wrong = rows.filter((r) => r.permission).filter((r) => (scopeOf(r.permission!) === 'org') !== !!r.org).map(key)
    expect(wrong).toEqual([])
  })
})

describe('the catalogue and the routes agree (rule 4)', () => {
  it('every catalogue permission is required by at least one route, or named here with where it is checked', () => {
    const used = new Set(rows.map((r) => r.permission))
    const unused = PERMISSIONS.filter((p) => !used.has(p))
    expect(unused.sort()).toEqual(Object.keys(CHECKED_INSIDE_A_GUARD).sort())
  })
})

describe('step-up comes from the catalogue (rule 5)', () => {
  it('every route whose permission says stepUp has requireRecentMfa in its chain', () => {
    const missing = rows.filter((r) => r.permission && isCatalogPermission(r.permission) && CATALOG[r.permission].stepUp && !r.stepUp).map(key)
    expect(missing).toEqual([])
  })
})

describe('the route_map is generated from the declarations alone (rule 3)', () => {
  it('the committed file is what the running route table generates — run `npm run gen:route-map`', () => {
    expect(GENERATED_ROUTE_MAP).toEqual(routeMapRows(declaredRoutes()))
  })

  it('every generated row is a live route', () => {
    const live = new Set(rows.map(key))
    expect(GENERATED_ROUTE_MAP.map((r) => `${r.method} ${r.path}`).filter((k) => !live.has(k))).toEqual([])
  })

  it('one row per operation: no alias, no legacy name, no catch-all, no method wildcard', () => {
    // A second row only for what the route's own guard also accepts (config.alsoAccepts), or for the
    // org counterpart of a route scoped by its own guard (scope any_org).
    const keys = GENERATED_ROUTE_MAP.map(key)
    const repeated = [...new Set(keys.filter((k, i) => keys.indexOf(k) !== i))].sort()
    expect(repeated).toEqual(rows.filter((r) => r.alsoAccepts?.length || r.scopedBy).map(key).sort())
    for (const r of GENERATED_ROUTE_MAP) {
      expect(r.method).not.toBe('*')
      expect(r.path).not.toMatch(/:any\*|\*$/)
      if (r.permission) expect(isCatalogPermission(r.permission), `${key(r)} ${r.permission}`).toBe(true)
    }
  })

  it('every operation the gateway may admit has its row; machine routes without edge have none', () => {
    const have = new Set(GENERATED_ROUTE_MAP.map(key))
    const admitted = rows.filter((r) => !r.path.startsWith('/docs') && !(r.access === 'machine' && !r.edge))
    expect(admitted.map(key).filter((k) => !have.has(k))).toEqual([])
    const hidden = rows.filter((r) => r.access === 'machine' && !r.edge).map(key)
    expect(hidden.filter((k) => have.has(k))).toEqual([])
    for (const k of ['GET /api/admin/rbac/bindings', 'POST /api/webhooks/kratos', 'GET /api/oathkeeper/rules']) expect(have.has(k), k).toBe(false)
    expect(GENERATED_ROUTE_MAP.find((r) => key(r) === 'POST /scim/v2/Users')).toMatchObject({ public: true })
  })

  it('org rows carry org_param, a parameter of their path under /api/organizations/:organizationId', () => {
    for (const r of GENERATED_ROUTE_MAP.filter((x) => x.permission)) {
      expect(scopeOf(r.permission!) === 'org', key(r)).toBe(!!r.org_param || r.scope === 'any_org')
      if (r.org_param) expect(r.path).toMatch(/^\/api\/organizations\/:organizationId\//)
    }
    const at = (method: string, path: string) => GENERATED_ROUTE_MAP.filter((r) => r.method === method && r.path === path)
    expect(at('GET', '/api/organizations/:organizationId/users')).toEqual([
      { method: 'GET', path: '/api/organizations/:organizationId/users', permission: 'org.members:read', org_param: 'organizationId' },
    ])
    expect(at('GET', '/api/admin/sites').map((r) => r.permission)).toEqual(['sites:read'])
    expect(at('GET', '/api/catalog')).toEqual([{ method: 'GET', path: '/api/catalog' }])
    // Scoped by its own guard: the platform permission, or its org counterpart held in any org — never a bare signed-in row.
    expect(at('GET', '/api/audit/events')).toEqual([
      { method: 'GET', path: '/api/audit/events', permission: 'audit:read' },
      { method: 'GET', path: '/api/audit/events', permission: 'org.audit:read', scope: 'any_org' },
    ])
    expect(at('POST', '/api/audit/exports').map((r) => r.permission)).toEqual(['audit:export', 'org.audit:read'])
    for (const r of rows.filter((x) => x.scopedBy)) expect(at(r.method, r.path).some((x) => !x.permission), key(r)).toBe(false)
  })

  it('super_admin holds every platform permission any row asks for', () => {
    const held = new Set<string>(ROLES.super_admin.permissions)
    for (const r of GENERATED_ROUTE_MAP.filter((x) => x.permission && !x.org_param && !x.scope)) expect(held.has(r.permission!), key(r)).toBe(true)
    expect([...held].sort()).toEqual([...PLATFORM_PERMISSIONS].sort())
  })
})

describe('GET /api/catalog', () => {
  it('lists every permission with its scope, metadata and routes, the staff roles and the org roles', async () => {
    const res = await app.inject({ url: '/api/catalog' })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.permissions.map((p: { name: string }) => p.name)).toEqual(PERMISSIONS)
    const apply = body.permissions.find((p: { name: string }) => p.name === 'sites:apply')
    expect(apply).toMatchObject({ scope: 'platform', area: 'sites', sensitivity: 'high', stepUp: true, fourEyes: 'prod', delegable: 'direct' })
    expect(apply.routes).toContainEqual({ method: 'POST', path: '/api/admin/sites/:name/apply' })
    expect(body.roles.find((r: { name: string }) => r.name === 'support')).toMatchObject({ group: 'staff-support', everyOrg: [] })
    expect(body.orgRoles.map((r: { name: string }) => r.name)).toContain('jinbe:owner')
    expect(body.aliases).toBeUndefined()
  })
})

describe('GET /api/whoami', () => {
  it('returns the effective catalogue permissions beside the names held', async () => {
    const body = (await app.inject({ url: '/api/whoami' })).json()
    // The dev bypass acts as DEV_ROLE (super_admin by default): every platform permission, by name.
    expect([...body.permissions].sort()).toEqual([...PLATFORM_PERMISSIONS].sort())
    expect(body.effective_permissions).toEqual(PLATFORM_PERMISSIONS)
  })
})
