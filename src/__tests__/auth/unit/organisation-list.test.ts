import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// GET /api/admin/organizations: every organisation with who owns it (identity ids holding
// jinbe:owner there) and the sites it is entitled to — a platform admin naming owners sees them first.

const ORG = '11111111-1111-4111-8111-111111111111'
const OTHER = '22222222-2222-4222-8222-222222222222'

vi.mock('../../../authz/opa.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../authz/opa.js')>()),
  rights: vi.fn(async () => ({ groups: [], roles: [], permissions: ['orgs:read'] })),
}))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))
vi.mock('../../../services/organisation-store.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../services/organisation-store.js')>()),
  organisationStoreConfigured: () => true,
  allOrganisations: vi.fn(async () => [{ id: ORG, name: 'Acme', tenant: 'acme' }, { id: OTHER, name: 'Globex', tenant: 'globex' }]),
  allEntitlements: vi.fn(async () => new Map([[ORG, ['billing']]])),
}))
vi.mock('../../../services/org-roles.repository.js', () => ({
  orgRolesRepository: { getAll: vi.fn(async () => ({ [ORG]: { 'id-b': ['jinbe:owner'], 'id-a': ['jinbe:owner', 'payroll:clerks'], 'id-c': ['jinbe:viewer'] } })) },
}))
vi.mock('../../../services/redis-rbac.repository.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../services/redis-rbac.repository.js')>()
  return { ...real, redisRbacRepository: { ...real.redisRbacRepository, getOrgSites: vi.fn(async () => ({ [ORG]: ['payroll'] })) } }
})

import { installRouteAccess } from '../../../policy/route-access.js'
import { adminRoutes } from '../../../routes/admin.routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => { request.userContext = { id: 'subject-ann', email: 'ann@example.com', name: 'Ann' } as never })
  await app.register(async (api) => { await api.register(adminRoutes, { prefix: '/admin' }) }, { prefix: '/api' })
  await app.ready()
})
afterAll(() => app.close())

describe('GET /api/admin/organizations', () => {
  it('names each organisation\'s owners and entitled sites (nothing for an org with neither)', async () => {
    const res = await app.inject({ url: '/api/admin/organizations' })
    expect(res.statusCode).toBe(200)
    expect(res.json().organizations).toEqual([
      { id: ORG, name: 'Acme', tenant: 'acme', applications: ['billing'], owners: ['id-a', 'id-b'], sites: ['payroll'] },
      { id: OTHER, name: 'Globex', tenant: 'globex', applications: [], owners: [], sites: [] },
    ])
  })
})
