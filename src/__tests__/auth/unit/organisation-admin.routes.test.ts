import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
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

vi.mock('../../../authz/opa.js', () => ({ holdsInJinbe: vi.fn(async () => s.holds) }))
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
  app.setErrorHandler(errorHandler)
  app.addHook('onRequest', async (request) => {
    request.userContext = { id: 'subject-sam', email: 'sam@example.com', name: 'Sam' } as never
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
  it('renames, and sets the applications as a whole set', async () => {
    const res = await patch({ name: 'Acme Inc', applications: ['fleet', 'fleet', 'billing'] })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ id: ACME, name: 'Acme Inc', tenant: 'acme', applications: ['fleet', 'billing'] })
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

  it('refuses a caller without admin.organisation:write', async () => {
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
  })

  it('refuses while members remain, and says how many', async () => {
    s.members = 2
    const res = await del()
    expect(res.statusCode).toBe(409)
    expect(res.json()).toMatchObject({ error: 'organisation_in_use', members: 2 })
    expect(s.record).not.toBeNull()
  })

  it('refuses a caller without admin.organisation:write', async () => {
    s.holds = false
    expect((await del()).statusCode).toBe(403)
    expect(s.record).not.toBeNull()
  })
})
