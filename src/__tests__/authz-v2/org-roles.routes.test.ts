import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { jinbeData } from './fixtures.js'

const ORG = '7b0c6f3e-6c1a-4c55-9a43-2f6e1c0d9a11'
const MEMBER = '0f8b1a52-1111-4c55-9a43-2f6e1c0d9a11'

const data = jinbeData({
  'mm@acme.io': { organizations: [ORG], organizationRoles: { [ORG]: ['jinbe:member_manager'] } },
  'owner@acme.io': { organizations: [ORG], organizationRoles: { [ORG]: ['jinbe:owner'] } },
  'm@acme.io': { organizations: [ORG], organizationRoles: { [ORG]: ['admin'] } },
}, [ORG])

const identity = { id: MEMBER, organization_id: ORG, metadata_admin: { organization_roles: { [ORG]: ['admin'] } } }
const updates: unknown[] = []

vi.mock('../../authz-v2/service.js', () => ({ loadDataV2: vi.fn(async () => data) }))
vi.mock('../../authz/opa.js', async (orig) => ({ ...(await orig<object>()), decide: vi.fn(async () => ({ allow: true, reason: 'ok' })) }))
vi.mock('../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(async (id: string) => (id === MEMBER ? identity : Promise.reject(new Error('404')))),
    updateAdminState: vi.fn(async (_id: string, change: (s: unknown) => unknown) => {
      updates.push(change({ organizationId: ORG, metadataAdmin: structuredClone(identity.metadata_admin) }))
      return identity
    }),
  },
}))
vi.mock('../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: vi.fn(async () => {}) } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => {}) } }))

const { installRouteAccess } = await import('../../policy/route-access.js')
const { orgRolesRoutes } = await import('../../routes/org-roles.routes.js')
const { setActiveModel } = await import('../../authz-v2/model.js')

let app: FastifyInstance
let as = 'mm@acme.io'

beforeEach(async () => {
  updates.length = 0
  setActiveModel('v2')
  app = Fastify()
  installRouteAccess(app as never)
  app.addHook('onRequest', async (request) => {
    ;(request as unknown as { userContext: object }).userContext = { id: 'u1', email: as, aal: 'aal2', authVia: 'session' }
  })
  await app.register(orgRolesRoutes, { prefix: '/api/organizations/:organizationId' })
  await app.ready()
})
afterAll(() => setActiveModel('v1'))

describe('org roles under v2', () => {
  it('lists the org roles, marking what the caller may assign', async () => {
    const res = await app.inject({ method: 'GET', url: `/api/organizations/${ORG}/roles` })
    expect(res.statusCode).toBe(200)
    const roles = res.json().roles as Array<{ role: string; assignable: boolean }>
    expect(roles.filter((r) => r.assignable).map((r) => r.role)).toEqual(['jinbe:member_manager'])
    expect(roles.map((r) => r.role)).toContain('jinbe:owner')
  })

  it('refuses to add a role the caller does not hold there (holding rule)', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${MEMBER}/roles`, payload: { roles: ['jinbe:owner'] } })
    expect(res.statusCode).toBe(403)
    expect(res.json().refused).toEqual([{ role: 'jinbe:owner', reason: 'grant_exceeds_own' }])
    expect(updates).toEqual([])
  })

  it('writes an allowed role, keeping v1 names on the identity untouched', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${MEMBER}/roles`, payload: { roles: ['jinbe:member_manager'] } })
    expect(res.statusCode).toBe(200)
    expect(updates).toEqual([{ organizationId: ORG, metadataAdmin: { organization_roles: { [ORG]: ['admin', 'jinbe:member_manager'] } } }])
  })

  it('an owner may hand out owner', async () => {
    as = 'owner@acme.io'
    const res = await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${MEMBER}/roles`, payload: { roles: ['jinbe:owner'] } })
    expect(res.statusCode).toBe(200)
    as = 'mm@acme.io'
  })

  it('404 for a person who is not a member', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/0f8b1a52-2222-4c55-9a43-2f6e1c0d9a11/roles`, payload: { roles: [] } })
    expect(res.statusCode).toBe(404)
  })

  it('404 route_not_active while v1 decides', async () => {
    setActiveModel('v1')
    const res = await app.inject({ method: 'GET', url: `/api/organizations/${ORG}/roles` })
    expect(res.statusCode).toBe(404)
  })
})
