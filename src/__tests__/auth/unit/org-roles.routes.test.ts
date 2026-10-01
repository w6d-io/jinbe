import { describe, it, expect, vi, beforeEach } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

const ORG = '7b0c6f3e-6c1a-4c55-9a43-2f6e1c0d9a11'
const MEMBER = '0f8b1a52-1111-4c55-9a43-2f6e1c0d9a11'
const OUTSIDER = '0f8b1a52-2222-4c55-9a43-2f6e1c0d9a11'

const stored: Record<string, Record<string, string[]>> = {}
const orgRoleDefs = {
  owner: ['org.audit:read', 'org.keys:read', 'org.keys:revoke', 'org.keys:write', 'org.members:read', 'org.members:write'],
  member_manager: ['org.members:read', 'org.members:write'],
  viewer: ['org.keys:read', 'org.members:read'],
}

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getOrgSites: vi.fn(async () => ({})),
    getOrgRoles: vi.fn(async (svc: string) => (svc === 'jinbe' ? orgRoleDefs : null)),
  },
}))
vi.mock('../../../services/org-roles.repository.js', () => ({
  orgRolesRepository: {
    getForMember: vi.fn(async (org: string, id: string) => stored[org]?.[id] ?? []),
    setForMember: vi.fn(async (org: string, id: string, roles: string[]) => { (stored[org] ??= {})[id] = [...roles].sort(); return [] }),
    holdersOf: vi.fn(async () => []),
  },
}))
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(async (id: string) => (id === MEMBER ? { id, organization_id: ORG, metadata_admin: {} } : id === OUTSIDER ? { id, organization_id: null, metadata_admin: {} } : Promise.reject(new Error('404')))),
    updateAdminState: vi.fn(),
  },
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: vi.fn(async () => {}) } }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => {}) } }))

const { installRouteAccess } = await import('../../../policy/route-access.js')
const { orgRolesRoutes } = await import('../../../routes/org-roles.routes.js')
const { opaWorld, resetOpaWorld } = await import('../../helpers/opa-authz-mock.js')

let app: FastifyInstance
let as = 'mm@acme.io'

beforeEach(async () => {
  resetOpaWorld()
  for (const k of Object.keys(stored)) delete stored[k]
  opaWorld.orgPermissions['mm@acme.io'] = { [ORG]: ['org.members:read', 'org.members:write'] }
  opaWorld.orgPermissions['owner@acme.io'] = { [ORG]: orgRoleDefs.owner }
  opaWorld.decide = (q) => (opaWorld.orgPermissions[q.email]?.[ORG] ?? []).length > 0
  as = 'mm@acme.io'
  app = Fastify()
  installRouteAccess(app as never)
  app.addHook('onRequest', async (request) => {
    ;(request as unknown as { userContext: object }).userContext = { id: 'u1', email: as, aal: 'aal2', authVia: 'session' }
  })
  await app.register(orgRolesRoutes, { prefix: '/api/organizations/:organizationId' })
  await app.ready()
})

describe('org roles, stored by jinbe', () => {
  it('lists the org roles, marking what the caller may assign (holding rule)', async () => {
    const res = await app.inject({ method: 'GET', url: `/api/organizations/${ORG}/roles` })
    expect(res.statusCode).toBe(200)
    const roles = res.json().roles as Array<{ role: string; assignable: boolean }>
    expect(roles.filter((r) => r.assignable).map((r) => r.role)).toEqual(['jinbe:member_manager'])
    expect(roles.map((r) => r.role)).toEqual(['jinbe:member_manager', 'jinbe:owner', 'jinbe:viewer'])
  })

  it('refuses to add a role the caller does not hold there, naming what is missing', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${MEMBER}/roles`, payload: { roles: ['jinbe:owner'] } })
    expect(res.statusCode).toBe(403)
    expect(res.json().refused).toEqual([{ role: 'jinbe:owner', reason: 'grant_exceeds_own', missing: ['org.audit:read', 'org.keys:read', 'org.keys:revoke', 'org.keys:write'] }])
    expect(stored).toEqual({})
  })

  it('writes an allowed role, by identity id, and reads it back', async () => {
    expect((await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${MEMBER}/roles`, payload: { roles: ['jinbe:member_manager'] } })).statusCode).toBe(200)
    expect(stored[ORG][MEMBER]).toEqual(['jinbe:member_manager'])
    const res = await app.inject({ method: 'GET', url: `/api/organizations/${ORG}/users/${MEMBER}/roles` })
    expect(res.json()).toEqual({ id: MEMBER, roles: ['jinbe:member_manager'] })
  })

  it('an owner may hand out owner; removing needs nothing more', async () => {
    as = 'owner@acme.io'
    expect((await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${MEMBER}/roles`, payload: { roles: ['jinbe:owner'] } })).statusCode).toBe(200)
    as = 'mm@acme.io'
    expect((await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${MEMBER}/roles`, payload: { roles: [] } })).statusCode).toBe(200)
    expect(stored[ORG][MEMBER]).toEqual([])
  })

  it('an unknown role and a role of an unentitled site are refused', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${MEMBER}/roles`, payload: { roles: ['jinbe:god', 'payroll:editor'] } })
    expect(res.json().refused).toEqual([{ role: 'jinbe:god', reason: 'unknown_role' }, { role: 'payroll:editor', reason: 'unknown_role' }])
  })

  it('404 for a person who is not a member; the org gate refuses a caller holding nothing there', async () => {
    expect((await app.inject({ method: 'PUT', url: `/api/organizations/${ORG}/users/${OUTSIDER}/roles`, payload: { roles: [] } })).statusCode).toBe(404)
    as = 'nobody@x.io'
    expect((await app.inject({ method: 'GET', url: `/api/organizations/${ORG}/roles` })).statusCode).toBe(403)
  })
})
