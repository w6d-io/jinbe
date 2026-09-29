import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// J-3: API-key routes need THAT org (requireOrgPermission, asking each route's org.keys:* declaration), and a refused
// scope keeps its explanation on the wire.

const ORG = '11111111-1111-1111-1111-111111111111'

const s = vi.hoisted(() => ({ guardPermission: '' as string | undefined, guardParam: '' as string }))

vi.mock('../../../middleware/require-org-permission.js', () => ({
  requireOrgPermission: vi.fn((permission?: string, param = 'organizationId') => {
    s.guardPermission = permission
    s.guardParam = param
    return async (request: FastifyRequest, reply: FastifyReply) => {
      if (request.headers['x-test-refuse']) return reply.status(403).send({ error: 'Forbidden', message: 'other org' })
    }
  }),
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
  scopeCatalog: vi.fn(async (org: string, email: string) => {
    if (email === 'down@x.io') {
      const { AuthzUnavailableError } = await import('../../../authz/opa.js')
      throw new AuthzUnavailableError('opa down')
    }
    return [{ scope: 'payroll:read', sites: ['payroll', `for-${org.slice(0, 4)}`] }]
  }),
}))

vi.mock('../../../services/api-key-views.js', () => ({
  decorateKeyViews: vi.fn(async (_r: unknown, views: object[]) =>
    views.map((v) => ({ ...v, last_used_at: '2026-09-28T12:00:00.000Z', created_by_email: 'bob@x.io' }))),
}))

import { apiKeyRoutes } from '../../../routes/api-key.routes.js'
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
  await app.ready()
})
afterAll(() => app.close())

describe('API-key routes', () => {
  it("are guarded per org on :organizationId, each by its own org.keys:* declaration", () => {
    expect(s.guardPermission).toBeUndefined()
    expect(s.guardParam).toBe('organizationId')
    const perm = (method: string, path: string) => declaredRoute(method, `/api/organizations/:organizationId${path}`)
    expect(perm('GET', '/api-keys')).toMatchObject({ permission: 'org.keys:read', org: 'organizationId' })
    expect(perm('POST', '/api-keys')).toMatchObject({ permission: 'org.keys:write', stepUp: true })
    expect(perm('DELETE', '/api-keys/:clientId')?.permission).toBe('org.keys:revoke')
    expect(perm('PUT', '/api-key-policy')?.permission).toBe('org.keys:write')
  })

  it('refuse when the guard refuses (e.g. a service admin of another org)', async () => {
    const res = await app.inject({ url: `/api/organizations/${ORG}/api-keys`, headers: { 'x-test-refuse': '1' } })
    expect(res.statusCode).toBe(403)
  })

  it("lists this org's scope catalog for the caller, grouped by site, behind the same guard", async () => {
    const res = await app.inject({ url: `/api/organizations/${ORG}/api-keys/scopes` })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ scopes: [{ scope: 'payroll:read', sites: ['payroll', 'for-1111'] }] })
    expect((await app.inject({ url: `/api/organizations/${ORG}/api-keys/scopes`, headers: { 'x-test-refuse': '1' } })).statusCode).toBe(403)
  })

  it('answers 503 policy_unavailable, not an empty catalog, when OPA cannot be asked', async () => {
    const res = await app.inject({ url: `/api/organizations/${ORG}/api-keys/scopes`, headers: { 'x-email': 'down@x.io' } })
    expect(res.statusCode).toBe(503)
    expect(res.json().error).toBe('policy_unavailable')
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
      url: `/api/organizations/${ORG}/api-keys`,
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
