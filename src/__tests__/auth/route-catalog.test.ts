import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import type { FastifyInstance } from 'fastify'
import { declaredRoutes, resetDeclaredRoutes, type DeclaredRoute } from '../../policy/declared-routes.js'
import { CATALOG, PERMISSIONS, isCatalogPermission } from '../../policy/catalog.js'

/**
 * CI rules 1, 4 and 5 of staff-rbac-proposal §3, over the route table the running service declares.
 * (Rule 2, writes need more than reading, is route-write-guards.test.ts.)
 */

/**
 * Catalogue permissions no route DECLARES, because a route's own guard asks for them on part of its
 * input — each says where. An entry that a route starts declaring, or that stops existing, fails.
 */
const CHECKED_INSIDE_A_GUARD: Record<string, string> = {
  'users:update_email': 'PUT /api/admin/users/:id asks it when the address changes (requireEditPermissions)',
  'groups.members:write': 'PUT /api/admin/users/:email/groups asks it when the diff adds anybody (require-membership-change.ts); POST /api/admin/users when groups are given',
  'users:verify': 'POST /api/admin/users/:id/verification — the endpoint lands with the MCP write wave (mcp-write-wave.md §3)',
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
  it('a catalogue permission, `*` (legacy infrastructure), or why it needs none', () => {
    const undecided = rows.filter((r) => !r.path.startsWith('/docs'))
      .filter((r) => !(r.permission && (r.permission === '*' || isCatalogPermission(r.permission))) && !r.access)
      .map(key)
    expect(undecided).toEqual([])
  })

  it('no route requires a retired name (admin:*, org:manage_*, users:assign_group)', () => {
    expect(rows.filter((r) => r.permission && /^(admin[.:]|org:manage_|users:assign_group)/.test(r.permission)).map(key)).toEqual([])
  })

  it('`*` only guards the legacy infrastructure', () => {
    expect(rows.filter((r) => r.permission === '*' && !/^\/api\/(clusters|databases|backups|backup-items|database-apis)(\/|$)/.test(r.path)).map(key)).toEqual([])
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

describe('GET /api/catalog', () => {
  it('lists every permission with its metadata and the routes needing it, the roles and the aliases', async () => {
    const res = await app.inject({ url: '/api/catalog' })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.permissions.map((p: { name: string }) => p.name)).toEqual(PERMISSIONS)
    const apply = body.permissions.find((p: { name: string }) => p.name === 'sites:apply')
    expect(apply).toMatchObject({ area: 'sites', sensitivity: 'high', stepUp: true, fourEyes: 'prod', delegable: 'direct' })
    expect(apply.routes).toContainEqual({ method: 'POST', path: '/api/admin/sites/:name/apply' })
    expect(body.roles.find((r: { name: string }) => r.name === 'support')).toMatchObject({ group: 'staff-support' })
    expect(body.aliases['admin:read']).toContain('users:read')
  })
})

describe('GET /api/whoami', () => {
  it('returns the effective catalogue permissions beside the names held', async () => {
    const body = (await app.inject({ url: '/api/whoami' })).json()
    // The dev bypass acts as DEV_ROLE (super_admin by default): `*`, which is every leaf.
    expect(body.permissions).toEqual(['*'])
    expect(body.effective_permissions).toEqual(PERMISSIONS)
  })
})
