import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance } from 'fastify'

// PATCH and DELETE /api/admin/organizations/:id — change an organisation, delete an empty one.
// Guarded by admin.organisation:write (asked of OPA), answered the same by either store.

const ACME = '11111111-1111-4111-8111-111111111111'

const s = vi.hoisted(() => ({
  holds: true,
  configured: true,
  record: null as null | { id: string; name: string; tenant: string; attributes: Record<string, unknown> },
  deployments: [] as Array<{ application: string; enabled: boolean }>,
  members: 0,
  audits: [] as Array<Record<string, unknown>>,
}))

const rbacStore = vi.hoisted(() => ({ orgSites: {} as Record<string, string[]>, forgotten: [] as string[] }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { setOrgSites: vi.fn(async (o: string, sites: string[]) => { if (sites.length) rbacStore.orgSites[o] = sites; else delete rbacStore.orgSites[o] }) },
}))
vi.mock('../../../services/org-roles.repository.js', () => ({ orgRolesRepository: { forgetOrg: vi.fn(async (o: string) => { rbacStore.forgotten.push(o) }) } }))
// What else an organisation leaves behind: sign-up entitlements and domains, direct grants, invitations.
const left = vi.hoisted(() => ({
  signUp: [] as string[],
  grants: { 'subject-ann': [{ id: 'g1', scope: '11111111-1111-4111-8111-111111111111' }], 'subject-bob': [{ id: 'g2', scope: 'platform' }] } as Record<string, Array<{ id: string; scope: string }>>,
  forgotGrants: [] as Array<[string, string]>,
  invitations: [] as string[],
  sites: [{ site: { name: 'shop', orgs: ['11111111-1111-4111-8111-111111111111'] } }, { site: { name: 'wiki', orgs: [] } }],
}))
vi.mock('../../../sites/signup/store.js', () => ({ signUpStore: { forgetOrg: vi.fn(async (o: string) => { left.signUp.push(o) }) } }))
vi.mock('../../../services/direct-grants.repository.js', () => ({
  directGrantsRepository: { getAll: vi.fn(async () => left.grants), forgetOrg: vi.fn(async (s: string, o: string) => { left.forgotGrants.push([s, o]) }) },
}))
vi.mock('../../../services/org-invitations.js', () => ({ orgInvitations: { forgetOrg: vi.fn(async (o: string) => { left.invitations.push(o) }) }, invitationLink: () => null }))
vi.mock('../../../sites/repository.js', () => ({ sitesRepository: { list: vi.fn(async () => left.sites) } }))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: vi.fn(async () => {}) } }))
vi.mock('../../../services/kratos.service.js', async (importOriginal) => ({ ...(await importOriginal<object>()), kratosService: {} }))
vi.mock('../../../services/org-membership.service.js', () => ({ joinOrganisation: vi.fn() }))
vi.mock('../../../authz/opa.js', () => ({
  rights: vi.fn(async () => ({ groups: [], roles: [], permissions: s.holds ? ['orgs:write', 'orgs:delete'] : [] })),
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn(async (e: Record<string, unknown>) => { s.audits.push(e) }) },
}))
vi.mock('../../../services/organisation-store.js', async () => {
  const types = await vi.importActual<typeof import('../../../services/organisation-store/types.js')>(
    '../../../services/organisation-store/types.js',
  )
  return {
    ...types,
    organisationStoreConfigured: () => s.configured,
    organisationStoreNotConfigured: () => ({ error: 'organisation_directory_unavailable', reason: 'not_configured', message: 'x' }),
    createOrganisation: vi.fn(),
    updateOrganisation: vi.fn(async (id: string, change: Record<string, unknown>) => {
      if (!s.record || s.record.id !== id) throw new types.OrganisationNotFoundError(id)
      s.record = { ...s.record, ...change }
      return s.record
    }),
    setDeployments: vi.fn(async (_id: string, d: Array<{ application: string; enabled: boolean }>) => {
      s.deployments = d
    }),
    deploymentsOf: vi.fn(async () => s.deployments),
    deleteOrganisation: vi.fn(async (id: string) => {
      if (!s.record || s.record.id !== id) throw new types.OrganisationNotFoundError(id)
      if (s.members > 0) throw new types.OrganisationInUseError(id, s.members)
      s.record = null
    }),
  }
})

import { organisationAdminRoutes } from '../../../routes/organisation-admin.routes.js'
import { errorHandler } from '../../../middleware/error-handler.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.setErrorHandler(errorHandler)
  app.addHook('onRequest', async (request) => {
    // A second factor proven a minute ago: deleting an organisation needs a step-up.
    request.userContext = { id: 'subject-sam', email: 'sam@example.com', name: 'Sam', aal: 'aal2', secondFactorAt: new Date(Date.now() - 60_000), authVia: 'session' } as never
  })
  await app.register(organisationAdminRoutes, { prefix: '/api/admin' })
  await app.ready()
})
afterAll(() => app.close())
beforeEach(() => {
  s.holds = true
  s.configured = true
  s.record = { id: ACME, name: 'Acme', tenant: 'acme', attributes: {} }
  s.deployments = []
  s.members = 0
  s.audits = []
})

const patch = (body: unknown, id = ACME) => app.inject({ method: 'PATCH', url: `/api/admin/organizations/${id}`, payload: body as object })
const del = (id = ACME) => app.inject({ method: 'DELETE', url: `/api/admin/organizations/${id}` })

describe('PATCH /api/admin/organizations/:id', () => {
  it('renames; applications are gone (they decided nothing)', async () => {
    const res = await patch({ name: 'Acme Inc' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ id: ACME, name: 'Acme Inc', tenant: 'acme' })
    expect((await patch({ applications: ['fleet'] })).statusCode).toBe(400)
    expect(s.audits[0]).toMatchObject({ type: 'organization.updated', target: { type: 'organization', id: ACME } })
  })

  it('refuses an empty change, an unknown field and a bad tenant', async () => {
    expect((await patch({})).statusCode).toBe(400)
    expect((await patch({ owner: 'x' })).statusCode).toBe(400)
    expect((await patch({ tenant: 'Not A Tenant' })).statusCode).toBe(400)
  })

  it('answers an organisation that is not held with 404', async () => {
    const res = await patch({ name: 'x' }, '99999999-9999-4999-8999-999999999999')
    expect(res.statusCode).toBe(404)
    expect(res.json()).toMatchObject({ error: 'organisation_not_found' })
  })

  it('refuses a caller without orgs:write / orgs:delete', async () => {
    s.holds = false
    expect((await patch({ name: 'x' })).statusCode).toBe(403)
    expect(s.record?.name).toBe('Acme')
  })

  it('says not configured only when there is truly no store', async () => {
    s.configured = false
    const res = await patch({ name: 'x' })
    expect(res.statusCode).toBe(503)
    expect(res.json()).toMatchObject({ reason: 'not_configured' })
  })
})

describe('DELETE /api/admin/organizations/:id', () => {
  it('deletes an organisation nobody belongs to', async () => {
    const res = await del()
    expect(res.statusCode).toBe(204)
    expect(s.record).toBeNull()
    expect(s.audits[0]).toMatchObject({ type: 'organization.deleted' })
    // Its entitlements and org role assignments leave the RBAC store with it, and the rest it left.
    expect(rbacStore.forgotten).toHaveLength(1)
    expect(left.signUp).toEqual([ACME])
    expect(left.forgotGrants).toEqual([['subject-ann', ACME]])
    expect(left.invitations).toEqual([ACME])
    // Site intents still naming it are flagged.
    expect(s.audits[0]).toMatchObject({ details: { sitesNamingIt: ['shop'] } })
  })

  it('refuses while members remain, and says how many', async () => {
    s.members = 2
    const res = await del()
    expect(res.statusCode).toBe(409)
    expect(res.json()).toMatchObject({ error: 'organisation_in_use', members: 2 })
    expect(s.record).not.toBeNull()
  })

  it('refuses a caller without orgs:write / orgs:delete', async () => {
    s.holds = false
    expect((await del()).statusCode).toBe(403)
    expect(s.record).not.toBeNull()
  })
})
