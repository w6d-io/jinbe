import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// J-3: API-key routes need THAT org (requireOrgPermission, asking each route's org.keys:* declaration). Keys are
// created by staff from the platform (orgs.keys:write), and a refused scope keeps its explanation on the wire.

const ORG = '11111111-1111-1111-1111-111111111111'

const s = vi.hoisted(() => ({ guardPermission: '' as string | undefined, guardParam: '' as string, platformAsked: [] as string[], held: true }))

vi.mock('../../../middleware/require-org-permission.js', () => ({
  requireOrgPermission: vi.fn((permission?: string, param = 'organizationId') => {
    s.guardPermission = permission
    s.guardParam = param
    return async (request: FastifyRequest, reply: FastifyReply) => {
      if (request.headers['x-test-refuse']) return reply.status(403).send({ error: 'Forbidden', message: 'other org' })
    }
  }),
}))
vi.mock('../../../middleware/require-permission.js', () => ({
  requirePermission: (perm: string) => {
    s.platformAsked.push(perm)
    return async (request: FastifyRequest, reply: FastifyReply) => {
      if (request.headers['x-test-lacks']) return reply.status(403).send({ error: 'Forbidden', message: `requires ${perm}` })
    }
  },
}))
vi.mock('../../../services/organisation-store.js', () => ({
  organisationStoreConfigured: () => true,
  organisationStoreNotConfigured: () => ({ error: 'organisation_directory_unavailable' }),
  organisationsById: vi.fn(async (ids: string[]) => (s.held ? ids.map((id) => ({ id, name: 'Acme', tenant: 'acme', attributes: {} })) : [])),
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))
vi.mock('../../../services/api-key.service.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../services/api-key.service.js')>()
  return {
    ...real,
    apiKeyService: {
      create: vi.fn(async () => {
        throw new real.ApiKeyError(400, 'One or more requested scopes are not allowed', {
          invalid_scopes: ['root'],
          allowed_scopes: ['read', 'write'],
        })
      }),
      list: vi.fn(async () => [{ client_id: 'k1', created_by: 'u2' }]),
      get: vi.fn(async () => ({ client_id: 'k1', created_by: 'u2' })),
    },
  }
})

vi.mock('../../../services/api-key-scopes.js', () => ({
  scopeCatalog: vi.fn(async (org: string) => [{ scope: 'role:payroll:clerk', kind: 'role', sites: ['payroll'], permissions: [`payroll:read-${org.slice(0, 4)}`] }]),
}))

vi.mock('../../../services/api-key-views.js', () => ({
  decorateKeyViews: vi.fn(async (_r: unknown, views: object[]) =>
    views.map((v) => ({ ...v, last_used_at: '2026-09-28T12:00:00.000Z', created_by_email: 'bob@x.io' }))),
}))

import { apiKeyRoutes } from '../../../routes/api-key.routes.js'
import { orgKeysAdminRoutes } from '../../../routes/org-keys-admin.routes.js'
import { declaredRoute } from '../../../policy/declared-routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    // A second factor proven a minute ago: creating a key and changing the policy need a step-up.
    request.userContext = { email: (request.headers['x-email'] as string) || 'admin@x.io', id: 'u1', name: 'A', aal: 'aal2', secondFactorAt: new Date(Date.now() - 60_000), authVia: 'session' } as never
  })
  await app.register(apiKeyRoutes, { prefix: '/api/organizations/:organizationId' })
  await app.register(orgKeysAdminRoutes, { prefix: '/api/admin' })
  await app.ready()
})
afterAll(() => app.close())

describe('API-key routes', () => {
  it("are guarded per org on :organizationId, each by its own org.keys:* declaration", () => {
    expect(s.guardPermission).toBeUndefined()
    expect(s.guardParam).toBe('organizationId')
    const perm = (method: string, path: string) => declaredRoute(method, `/api/organizations/:organizationId${path}`)
    expect(perm('GET', '/api-keys')).toMatchObject({ permission: 'org.keys:read', org: 'organizationId' })
    expect(perm('DELETE', '/api-keys/:clientId')?.permission).toBe('org.keys:revoke')
    expect(perm('PUT', '/api-key-policy')?.permission).toBe('org.keys:write')
    // An organization lists and revokes its keys; it does not create them.
    expect(perm('POST', '/api-keys')).toBeNull()
    expect(perm('GET', '/api-keys/scopes')).toBeNull()
  })

  it('are created by staff from the platform: orgs.keys:write with a step-up; listed with orgs:read', () => {
    expect(declaredRoute('POST', '/api/admin/organizations/:id/api-keys')).toMatchObject({ permission: 'orgs.keys:write', stepUp: true })
    expect(declaredRoute('GET', '/api/admin/organizations/:id/api-keys/scopes')?.permission).toBe('orgs.keys:write')
    expect(declaredRoute('GET', '/api/admin/organizations/:id/api-keys')?.permission).toBe('orgs:read')
    expect(s.platformAsked).toEqual(expect.arrayContaining(['orgs.keys:write', 'orgs:read']))
  })

  it('refuse when the guard refuses (e.g. a service admin of another org)', async () => {
    const res = await app.inject({ url: `/api/organizations/${ORG}/api-keys`, headers: { 'x-test-refuse': '1' } })
    expect(res.statusCode).toBe(403)
  })

  it("lists the org's scope catalog from the platform, each scope with what it stands for", async () => {
    const res = await app.inject({ url: `/api/admin/organizations/${ORG}/api-keys/scopes` })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ scopes: [{ scope: 'role:payroll:clerk', kind: 'role', sites: ['payroll'], permissions: ['payroll:read-1111'] }] })
    expect((await app.inject({ url: `/api/admin/organizations/${ORG}/api-keys/scopes`, headers: { 'x-test-lacks': '1' } })).statusCode).toBe(403)
  })

  it('404 for an organisation that is not held', async () => {
    s.held = false
    try {
      expect((await app.inject({ method: 'POST', url: `/api/admin/organizations/${ORG}/api-keys`, payload: { label: 'ci', scopes: ['x:y'] } })).statusCode).toBe(404)
      expect((await app.inject({ url: `/api/admin/organizations/${ORG}/api-keys` })).statusCode).toBe(404)
    } finally {
      s.held = true
    }
  })

  it('the personal-key policy is 404 while delegated tokens are off', async () => {
    expect((await app.inject({ url: `/api/organizations/${ORG}/api-key-policy` })).statusCode).toBe(404)
    expect((await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/api-key-policy`, payload: { personal_keys: 'forbidden' } })).statusCode).toBe(404)
  })

  it('list and get carry last_used_at and created_by_email', async () => {
    const list = await app.inject({ url: `/api/organizations/${ORG}/api-keys` })
    expect(list.json()).toMatchObject({ total: 1, data: [{ client_id: 'k1', last_used_at: '2026-09-28T12:00:00.000Z', created_by_email: 'bob@x.io' }] })
    const one = await app.inject({ url: `/api/organizations/${ORG}/api-keys/k1` })
    expect(one.json()).toMatchObject({ client_id: 'k1', last_used_at: '2026-09-28T12:00:00.000Z', created_by_email: 'bob@x.io' })
  })

  it('a refused scope keeps details.allowed_scopes in the 400 body', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/admin/organizations/${ORG}/api-keys`,
      payload: { label: 'ci', scopes: ['root'] },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toEqual({
      error: 'Bad Request',
      message: 'One or more requested scopes are not allowed',
      details: { invalid_scopes: ['root'], allowed_scopes: ['read', 'write'] },
    })
  })
})
