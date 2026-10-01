import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { declaredRoutes, resetDeclaredRoutes, type DeclaredRoute } from '../../policy/declared-routes.js'
import { routeRowsV2 } from '../../authz-v2/route-rows.js'
import { GENERATED_ROUTE_MAP_V2 } from '../../authz-v2/route-map.generated.js'
import { CATALOG_V2, scopeOf } from '../../authz-v2/catalogue.js'
import { platformRoleDefinitions } from '../../authz-v2/roles.js'
import { setActiveModel } from '../../authz-v2/model.js'

/**
 * authz v2 CI (design §3.5) over the route table the running service declares: the v2 map is the
 * declarations and nothing else; org scope ⇔ org parameter; every catalogue permission is used and
 * held by super_admin; no wildcard; retired and machine routes have no gateway row.
 */

/** v2 permissions no route row carries, each with where it is checked instead. */
const CHECKED_BY_A_GUARD: Record<string, string> = {
  // The audit routes are scoped by their own guard (row without a permission); it reads this per org.
  'org.audit:read': 'audit/query/scope.ts (the org part of the audit scope)',
  'audit:read': 'audit/query/scope.ts (the platform part of the audit scope)',
  'audit:export': 'audit/query/scope.ts (exports)',
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
afterAll(async () => {
  setActiveModel('v1')
  await app?.close()
})

const key = (r: { method: string; path: string }) => `${r.method} ${r.path}`

describe('the v2 route map is generated from the declarations alone', () => {
  it('the committed file is what the running route table generates — run `npm run gen:route-map`', () => {
    expect(GENERATED_ROUTE_MAP_V2).toEqual(routeRowsV2(declaredRoutes()))
  })

  it('one row per operation: no alias, no legacy name, no catch-all, no method wildcard', () => {
    // A second row only for what the route's own guard also accepts (config.alsoAccepts).
    const keys = GENERATED_ROUTE_MAP_V2.map(key)
    const repeated = [...new Set(keys.filter((k, i) => keys.indexOf(k) !== i))].sort()
    expect(repeated).toEqual(rows.filter((r) => r.alsoAccepts?.length).map(key).sort())
    for (const r of GENERATED_ROUTE_MAP_V2) {
      expect(r.method).not.toBe('*')
      expect(r.path).not.toMatch(/:any\*|\*$/)
      if (r.permission) expect(CATALOG_V2[r.permission], `${key(r)} ${r.permission}`).toBeDefined()
    }
  })

  it('every row is a live route of the v2 model', () => {
    const live = new Set(rows.filter((r) => r.model !== 'v1').map(key))
    expect(GENERATED_ROUTE_MAP_V2.map(key).filter((k) => !live.has(k))).toEqual([])
  })

  it('every v2 operation that the gateway may admit has its row', () => {
    const admitted = rows.filter((r) => r.model !== 'v1' && !r.path.startsWith('/docs') && !(r.access === 'machine' && !r.edge))
    const have = new Set(GENERATED_ROUTE_MAP_V2.map(key))
    expect(admitted.map(key).filter((k) => !have.has(k))).toEqual([])
  })

  it('machine routes without edge, and routes retired by v2, have no row', () => {
    const have = new Set(GENERATED_ROUTE_MAP_V2.map(key))
    const hidden = rows.filter((r) => (r.access === 'machine' && !r.edge) || r.model === 'v1').map(key)
    expect(hidden.filter((k) => have.has(k))).toEqual([])
    for (const k of ['GET /api/admin/rbac/bindings', 'GET /api/admin/rbac/opal/v2', 'POST /api/webhooks/kratos', 'GET /api/admin/rbac/org-admin-map', 'PUT /api/organizations/:organizationId/users/:id/grants']) {
      expect(have.has(k), k).toBe(false)
    }
    expect(GENERATED_ROUTE_MAP_V2.find((r) => key(r) === 'POST /scim/v2/Users')).toMatchObject({ public: true })
  })
})

describe('org scope ⇔ org parameter', () => {
  it('a row carries an org permission exactly when it names org_param, and org_param is a path parameter', () => {
    for (const r of GENERATED_ROUTE_MAP_V2.filter((x) => x.permission)) {
      expect(scopeOf(r.permission!) === 'org', key(r)).toBe(!!r.org_param)
      if (r.org_param) expect(r.path.split('/')).toContain(`:${r.org_param}`)
    }
  })

  it('org-scoped routes live under /api/organizations/:organizationId only', () => {
    for (const r of GENERATED_ROUTE_MAP_V2.filter((x) => x.org_param)) expect(r.path).toMatch(/^\/api\/organizations\/:organizationId\//)
  })
})

describe('the catalogue and the v2 routes agree', () => {
  it('every v2 permission is carried by a row, or checked by a named guard', () => {
    const used = new Set(GENERATED_ROUTE_MAP_V2.map((r) => r.permission).filter(Boolean))
    const unused = Object.keys(CATALOG_V2).filter((p) => !used.has(p))
    expect(unused.sort()).toEqual(Object.keys(CHECKED_BY_A_GUARD).sort())
  })

  it('super_admin holds every platform permission any row asks for', () => {
    const held = new Set(platformRoleDefinitions().super_admin)
    for (const r of GENERATED_ROUTE_MAP_V2.filter((x) => x.permission && !x.org_param)) expect(held.has(r.permission!), key(r)).toBe(true)
  })
})

describe('routes of one model', () => {
  it('a v2 route answers 404 while v1 decides, before any permission check', async () => {
    setActiveModel('v1')
    const res = await app.inject({ method: 'GET', url: '/api/organizations/7b0c6f3e-6c1a-4c55-9a43-2f6e1c0d9a11/roles' })
    expect(res.statusCode).toBe(404)
    expect(res.json()).toMatchObject({ code: 'route_not_active' })
  })

  it('a route retired by v2 answers 404 once v2 decides', async () => {
    setActiveModel('v2')
    const res = await app.inject({ method: 'GET', url: '/api/admin/rbac/org-admin-map' })
    expect(res.statusCode).toBe(404)
    expect(res.json()).toMatchObject({ code: 'route_retired' })
    setActiveModel('v1')
  })
})
