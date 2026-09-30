import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance } from 'fastify'

// The writes that sat behind the administration API's `admin:read` gate alone — an administrator who
// may only READ could edit a group they were in, or give a role `admin:write`, and so promote
// themselves. Each is driven over HTTP here: the permission, the fresh second factor, and the
// legacy infrastructure API that asked for nothing but a session.

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))

// Handlers are stand-ins: what is under test is whether the request reaches one at all.
const { handled, stubController } = vi.hoisted(() => {
  const handled = { calls: [] as string[] }
  const stubController = (label: string) => new Proxy({}, {
    get: (_t, name) => async (_req: unknown, reply: { send: (b: unknown) => unknown }) => {
      handled.calls.push(label ? `${label}.${String(name)}` : String(name))
      return reply.send(label ? {} : { success: true, message: 'ok', timestamp: 'now' })
    },
  })
  return { handled, stubController }
})
vi.mock('../../../controllers/rbac.controller.js', () => ({ rbacController: stubController('') }))
vi.mock('../../../controllers/cluster.controller.js', () => ({ clusterController: stubController('cluster') }))
vi.mock('../../../controllers/database.controller.js', () => ({ databaseController: stubController('database') }))
vi.mock('../../../controllers/backup.controller.js', () => ({ backupController: stubController('backup') }))
vi.mock('../../../services/recert.service.js', () => ({
  RecertError: class extends Error { statusCode = 400 },
  recertService: {
    createCampaign: vi.fn(async () => { handled.calls.push('recert.create'); return { id: 'c1' } }),
    activateCampaign: vi.fn(async () => { handled.calls.push('recert.activate'); return { id: 'c1' } }),
    closeCampaign: vi.fn(async () => { handled.calls.push('recert.close'); return { id: 'c1' } }),
    deleteCampaign: vi.fn(async () => { handled.calls.push('recert.delete') }),
    getCampaign: vi.fn(async () => ({ campaign: { id: 'c1' }, items: [{ id: 'i1', reviewer: 'someone@example.com' }] })),
    decide: vi.fn(async () => { handled.calls.push('recert.decide'); return { id: 'i1' } }),
  },
}))

import { rbacRoutes } from '../../../routes/rbac.routes.js'
import { recertRoutes } from '../../../routes/recert.routes.js'
import { clusterRoutes } from '../../../routes/cluster.routes.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'
import { delegationRefusal, ineligibleWhy } from '../../../middleware/delegation-gate.js'
import { declaredRoute } from '../../../policy/declared-routes.js'
import { PERMISSIONS } from '../../../policy/catalog.js'

const ORG = '11111111-1111-4111-8111-111111111111'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    const who = request.headers['x-test-user'] as string | undefined
    const fresh = request.headers['x-test-fresh'] === '1'
    if (!who) return
    request.userContext = {
      id: `id-${who}`,
      email: `${who}@example.com`,
      name: who,
      sessionId: `sess-${who}`,
      aal: fresh ? 'aal2' : 'aal1',
      secondFactorAt: fresh ? new Date(Date.now() - 60_000) : null,
      authVia: 'session',
    } as never
  })
  await app.register(rbacRoutes, { prefix: '/api/admin/rbac' })
  await app.register(recertRoutes, { prefix: '/api/admin/recert' })
  await app.register(clusterRoutes, { prefix: '/api/clusters' })
  await app.ready()
})
afterAll(async () => { await app.close() })

beforeEach(() => {
  resetOpaWorld()
  handled.calls = []
  opaWorld.permissions['reader@example.com'] = ['admin:read']
  opaWorld.permissions['writer@example.com'] = ['admin:read', 'admin:write']
  opaWorld.permissions['root@example.com'] = ['*']
  opaWorld.superAdmins.add('root@example.com')
})

const call = (method: string, url: string, who: string, opts: { fresh?: boolean; body?: unknown } = {}) =>
  app.inject({
    method: method as never,
    url,
    headers: { 'x-test-user': who, ...(opts.fresh ? { 'x-test-fresh': '1' } : {}) },
    ...(opts.body !== undefined ? { payload: opts.body as never } : {}),
  })

const RBAC_WRITES: Array<[string, string, unknown]> = [
  ['POST', '/api/admin/rbac/groups', { name: 'ops', services: { jinbe: ['admin'] } }],
  ['PUT', '/api/admin/rbac/groups/ops', { services: { jinbe: ['admin'] } }],
  ['DELETE', '/api/admin/rbac/groups/ops', undefined],
  ['PUT', '/api/admin/rbac/services/jinbe/roles', { roles: { admin: ['admin:write'] } }],
  ['PUT', '/api/admin/rbac/services/jinbe/routes', { rules: [{ method: 'GET', path: '/x', permission: 'admin:read' }] }],
  ['PUT', '/api/admin/rbac/org-service-map', { organizationId: ORG, services: ['jinbe'] }],
  ['DELETE', `/api/admin/rbac/org-service-map/${ORG}`, undefined],
]

describe('RBAC-changing writes', () => {
  it.each(RBAC_WRITES)('%s %s refuses a read-only administrator (403)', async (method, url, body) => {
    const res = await call(method, url, 'reader', { fresh: true, body })
    expect(res.statusCode).toBe(403)
    expect(handled.calls).toEqual([])
  })

  it.each(RBAC_WRITES)('%s %s asks admin:write for a fresh second factor (422)', async (method, url, body) => {
    const res = await call(method, url, 'writer', { body })
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('reauth_required')
    expect(handled.calls).toEqual([])
  })

  it.each(RBAC_WRITES)('%s %s reaches the handler with admin:write and a fresh second factor', async (method, url, body) => {
    const res = await call(method, url, 'writer', { fresh: true, body })
    expect(res.statusCode).toBeLessThan(300)
    expect(handled.calls).toHaveLength(1)
  })

  it('the import preview (it fetches a URL server-side) needs groups:write and its step-up', async () => {
    const body = { source: { content: '{}' } }
    expect((await call('POST', '/api/admin/rbac/services/jinbe/routes/import/preview', 'reader', { body })).statusCode).toBe(403)
    expect((await call('POST', '/api/admin/rbac/services/jinbe/routes/import/preview', 'writer', { body })).statusCode).toBe(422)
    expect((await call('POST', '/api/admin/rbac/services/jinbe/routes/import/preview', 'writer', { fresh: true, body })).statusCode).toBe(200)
  })

  it('reads stay open to admin:read', async () => {
    expect((await call('GET', '/api/admin/rbac/groups', 'reader')).statusCode).toBe(200)
    expect((await call('GET', '/api/admin/rbac/org-service-map', 'reader')).statusCode).toBe(200)
  })
})

describe('recertification campaign writes', () => {
  const WRITES: Array<[string, string, unknown]> = [
    ['POST', '/api/admin/recert/campaigns', { name: 'q3', reviewers: ['a@example.com'], deadline: '2030-01-01', onExpiry: 'flag' }],
    ['POST', '/api/admin/recert/campaigns/c1/activate', undefined],
    ['POST', '/api/admin/recert/campaigns/c1/close', undefined],
    ['DELETE', '/api/admin/recert/campaigns/c1', undefined],
  ]
  it.each(WRITES)('%s %s needs recert:manage / recert:delete (admin:write is their legacy alias)', async (method, url, body) => {
    expect((await call(method, url, 'reader', { body })).statusCode).toBe(403)
    expect(handled.calls).toEqual([])
    // Activation also needs a recent second factor (it generates every review item).
    expect((await call(method, url, 'writer', { fresh: true, body })).statusCode).toBeLessThan(300)
  })

  it('activation without a recent second factor is refused', async () => {
    expect((await call('POST', '/api/admin/recert/campaigns/c1/activate', 'writer')).statusCode).toBe(422)
  })

  it('a decision by somebody who is not the reviewer needs admin:write, not admin:read', async () => {
    const url = '/api/admin/recert/items/c1/i1/decision'
    expect((await call('POST', url, 'reader', { body: { decision: 'approved' } })).statusCode).toBe(403)
    expect(handled.calls).toEqual([])
    expect((await call('POST', url, 'writer', { body: { decision: 'approved' } })).statusCode).toBe(200)
  })
})

describe('legacy infrastructure API', () => {
  it.each([
    ['GET', '/api/clusters', undefined],
    ['POST', '/api/clusters/verify', { config: 'apiVersion: v1' }],
    ['DELETE', '/api/clusters/0123456789abcdef01234567', undefined],
  ])('%s %s refuses anyone short of a super admin, admin:write included', async (method, url, body) => {
    expect((await call(method, url, 'reader', { body })).statusCode).toBe(403)
    expect((await call(method, url, 'writer', { body })).statusCode).toBe(403)
    expect(handled.calls).toEqual([])
  })

  it('lets a super admin through', async () => {
    expect((await call('GET', '/api/clusters', 'root')).statusCode).toBe(200)
  })

  it('answers 503, not 403, when OPA cannot say who is a super admin', async () => {
    opaWorld.down = true
    expect((await call('GET', '/api/clusters', 'root')).statusCode).toBe(503)
  })
})

describe('delegated callers never change the access model', () => {
  // A token carrying every catalogue permission as a scope: what is left refused is refused for all.
  const everyScope = PERMISSIONS as readonly string[]
  const refusal = (method: string, url: string, permission?: string) => delegationRefusal({
    method,
    url,
    routeOptions: { url },
    params: {},
    userContext: { id: 'id-u', email: 'u@example.com', authVia: 'delegated', delegation: { scopes: [...everyScope], clientId: 'mcp' } },
  } as never, permission)

  // Owner decision 2026-09-30: creating and editing groups, their roles and route maps is normal work
  // through a key (the escalation guard and the key's step-up still apply); deleting stays by hand.
  it.each([
    ['POST', '/api/admin/rbac/groups', 'groups:write'],
    ['PUT', '/api/admin/rbac/groups/:name', 'groups:write'],
    ['PUT', '/api/admin/rbac/services/:name/roles', 'groups:write'],
    ['PUT', '/api/admin/rbac/services/:name/routes', 'groups:write'],
    ['POST', '/api/admin/rbac/services/:name/routes/import/preview', 'groups:write'],
    ['PUT', '/api/admin/rbac/org-service-map', 'groups:write'],
  ])('%s %s (%s) passes the gate with a scope granting it', (method, path, permission) => {
    expect(declaredRoute(method, path)?.permission ?? permission).toBe(permission)
    expect(refusal(method, path, permission)).toBeNull()
  })

  it.each([
    ['DELETE', '/api/admin/rbac/groups/:name'],
    ['DELETE', '/api/admin/rbac/org-service-map/:organizationId'],
  ])('%s %s is refused: nothing is deleted through a key', (method, path) => {
    expect(refusal(method, path)).toBe('delegation_ineligible:delete')
  })

  it.each([
    ['POST', '/api/admin/rbac/bundle/import', 'policy.bundle:write'],
    ['POST', '/api/admin/rbac/bundle/backups/restore', 'policy.bundle:write'],
    ['POST', '/api/admin/rbac/bundle/history/:id/rollback', 'policy.bundle:write'],
    ['PUT', '/api/admin/rbac/org-admin-map', 'org.admins:write'],
    ['POST', '/api/admin/recert/campaigns/:id/close', 'recert:manage'],
  ])('%s %s (%s) is always refused, whatever the scopes', (method, path, permission) => {
    expect(declaredRoute(method, path)?.permission ?? permission).toBe(permission)
    expect(refusal(method, path, permission)).toBe(`delegation_ineligible:${permission}`)
  })

  it.each([
    ['GET', '/api/clusters'],
    ['POST', '/api/clusters/:clusterId/jobs'],
    ['GET', '/api/databases/:id'],
    ['PUT', '/api/backup-items/:id'],
  ])('%s %s is on the backstop list', (method, path) => {
    expect(ineligibleWhy(method, path)).not.toBeNull()
  })

  it('reading the model is not refused on that ground', () => {
    expect(ineligibleWhy('GET', '/api/admin/rbac/groups')).toBeNull()
    expect(refusal('GET', '/api/admin/rbac/groups', 'groups:read')).toBeNull()
  })

  it('no scope ever exercises the super-admin wildcard', () => {
    expect(refusal('GET', '/api/clusters', '*')).not.toBeNull()
    expect(refusal('GET', '/api/admin/x', '*')).toBe('delegation_ineligible:*')
  })
})
