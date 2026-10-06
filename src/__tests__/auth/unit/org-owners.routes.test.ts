import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// PUT /api/admin/organizations/:organizationId/owners: each owner joins through the organisation store
// (which refuses an org it does not hold), and holds jinbe:owner there; a list naming an account that
// does not exist changes nothing.

const ORG = '11111111-1111-4111-8111-111111111111'
const h = vi.hoisted(() => ({
  accounts: new Set<string>(),
  joined: [] as Array<[string, string]>,
  roles: {} as Record<string, string[]>,
}))

vi.mock('../../../middleware/require-permission.js', () => ({ requirePermission: () => async (_r: FastifyRequest, _p: FastifyReply) => {} }))
vi.mock('../../../services/kratos.service.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  kratosService: { getIdentity: vi.fn(async (id: string) => { if (!h.accounts.has(id)) throw new Error('404'); return { id } }) },
}))
vi.mock('../../../services/org-membership.service.js', () => ({ joinOrganisation: vi.fn(async (i: { id: string }, o: string) => { h.joined.push([i.id, o]) }) }))
vi.mock('../../../services/org-roles.repository.js', () => ({
  orgRolesRepository: {
    holdersOf: vi.fn(async () => Object.entries(h.roles).filter(([, r]) => r.includes('jinbe:owner')).map(([id]) => id)),
    getForMember: vi.fn(async (_o: string, id: string) => h.roles[id] ?? []),
    setForMember: vi.fn(async (_o: string, id: string, roles: string[]) => { h.roles[id] = roles; return [] }),
  },
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: vi.fn(async () => {}) } }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => {}) } }))

import { installRouteAccess } from '../../../policy/route-access.js'
import { orgOwnersRoutes } from '../../../routes/org-roles.routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    request.userContext = { id: 'root', email: 'root@x.io', name: 'R', aal: 'aal2', secondFactorAt: new Date(Date.now() - 60_000), authVia: 'session' } as never
  })
  await app.register(orgOwnersRoutes, { prefix: '/api/admin/organizations/:organizationId' })
  await app.ready()
})
afterAll(() => app.close())
beforeEach(() => {
  h.accounts = new Set(['ann', 'bob'])
  h.joined = []
  h.roles = { old: ['jinbe:owner', 'shop:member'] }
})

const put = (owners: string[]) => app.inject({ method: 'PUT', url: `/api/admin/organizations/${ORG}/owners`, payload: { owners } })

describe('PUT …/owners', () => {
  it('joins each owner through the organisation store and moves jinbe:owner to exactly them', async () => {
    const res = await put(['ann', 'bob'])
    expect(res.statusCode).toBe(200)
    expect(h.joined).toEqual([['ann', ORG], ['bob', ORG]])
    expect(h.roles).toEqual({ ann: ['jinbe:owner'], bob: ['jinbe:owner'], old: ['shop:member'] })
  })

  it('a list naming an unknown account changes nothing', async () => {
    const res = await put(['ann', 'ghost'])
    expect(res.statusCode).toBe(404)
    expect(h.joined).toEqual([])
    expect(h.roles).toEqual({ old: ['jinbe:owner', 'shop:member'] })
  })
})
