import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// J-1: GET /api/admin/users/:id/access — site access and org access side by side, for the console.

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'

const s = vi.hoisted(() => ({
  identity: null as null | Record<string, unknown>,
  orgs: [] as string[],
  grants: {} as Record<string, Record<string, string[]>>,
  rosters: {} as Record<string, string[]>,
  grantsFail: false,
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(async (id: string) => {
      if (!s.identity || s.identity.id !== id) throw Object.assign(new Error('Identity not found'), { statusCode: 404 })
      return s.identity
    }),
  },
  KratosApiError: class extends Error {},
}))
vi.mock('../../../services/org-membership.service.js', () => ({
  organisationsOf: vi.fn(async () => s.orgs),
}))
vi.mock('../../../services/organisation-store.js', () => ({
  organisationStoreConfigured: () => true,
  organisationsById: vi.fn(async (ids: string[]) => ids.filter((id) => id === ACME).map((id) => ({ id, name: 'Acme' }))),
}))
vi.mock('../../../services/org-grants.repository.js', () => ({
  orgGrantsRepository: {
    getAll: vi.fn(async () => {
      if (s.grantsFail) throw new Error('ECONNREFUSED')
      return s.grants
    }),
  },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => ({
      'kuma-admins': { kuma: ['admin'] },
      'fleet-viewers': { fleet: ['viewer'], kuma: ['reader'] },
      super_admins: { global: ['super_admin'] },
    })),
    getOrgAdminMap: vi.fn(async () => s.rosters),
  },
}))

// Stand-in for the platform permission gate: refuses when the test marks the caller as lacking it,
// and records which permission the route asked for.
const gate = vi.hoisted(() => ({ asked: [] as string[] }))
vi.mock('../../../middleware/require-platform-permission.js', () => ({
  requirePlatformPermission: (perm: string) => {
    gate.asked.push(perm)
    return async (request: { headers: Record<string, unknown> }, reply: { status: (c: number) => { send: (b: unknown) => unknown } }) => {
      if (request.headers['x-test-lacks']) return reply.status(403).send({ error: 'Forbidden', message: `requires ${perm}` })
    }
  },
}))

import { userAccessRoutes } from '../../../routes/user-access.routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  await app.register(userAccessRoutes, { prefix: '/api/admin' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  s.identity = {
    id: 'id-bob',
    traits: { email: 'Bob@acme.test' },
    metadata_admin: { groups: ['kuma-admins', 'fleet-viewers'] },
  }
  s.orgs = [ACME, GLOBEX]
  s.grants = { [ACME]: { 'bob@acme.test': ['fleet-viewers'] } }
  s.rosters = { [GLOBEX]: ['bob@acme.test'] }
  s.grantsFail = false
})

describe('GET /api/admin/users/:id/access', () => {
  it('answers site groups + roles per service, and each org with admin flag and grants', async () => {
    const res = await app.inject({ url: '/api/admin/users/id-bob/access' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({
      site: {
        groups: ['kuma-admins', 'fleet-viewers'],
        byService: { kuma: ['admin', 'reader'], fleet: ['viewer'] },
      },
      orgs: [
        { orgId: ACME, name: 'Acme', admin: false, grants: ['fleet-viewers'] },
        { orgId: GLOBEX, name: GLOBEX, admin: true, grants: [] },
      ],
    })
  })

  it('is gated on admin:read in the app layer, not only at the gateway', async () => {
    expect(gate.asked).toContain('admin:read')
    const res = await app.inject({ url: `/api/admin/users/u-1/access`, headers: { 'x-test-lacks': '1' } })
    expect(res.statusCode).toBe(403)
  })

  it('404 for an unknown user', async () => {
    s.identity = null
    expect((await app.inject({ url: '/api/admin/users/nobody/access' })).statusCode).toBe(404)
  })

  it('503 when the grants cannot be read — never an empty org view', async () => {
    s.grantsFail = true
    expect((await app.inject({ url: '/api/admin/users/id-bob/access' })).statusCode).toBe(503)
  })
})
