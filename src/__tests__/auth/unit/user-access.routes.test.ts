import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../../policy/route-access.js'
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
  methods: ['totp'] as string[] | null,
  config: {} as Record<string, string>,
  // OPA's answers, keyed on the address as the bindings key it.
  manageable: {} as Record<string, string[]>,
  members: {} as Record<string, string[]>,
  opaDown: false,
  asked: [] as string[],
}))

vi.mock('../../../authz/opa.js', () => ({
  manageableOrgs: vi.fn(async (email: string) => {
    s.asked.push(email)
    if (s.opaDown) throw new Error('OPA unreachable')
    return s.manageable[email] ?? []
  }),
  memberOrgs: vi.fn(async (email: string) => {
    if (s.opaDown) throw new Error('OPA unreachable')
    return s.members[email] ?? []
  }),
  rights: vi.fn(async () => ({ groups: [], roles: [], permissions: ['sites:read', 'groups:write'] })),
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(async (id: string) => {
      if (!s.identity || s.identity.id !== id) throw Object.assign(new Error('Identity not found'), { statusCode: 404 })
      return s.identity
    }),
    mfaMethodsOf: vi.fn(async () => {
      if (!s.methods) throw new Error('kratos down')
      return s.methods
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
    getConfig: vi.fn(async () => s.config),
    getRoles: vi.fn(async (scope: string) => ({
      global: { super_admin: ['*'] }, kuma: { admin: ['*'], reader: ['kuma:read'] }, fleet: { viewer: ['fleet:read'] },
    } as Record<string, Record<string, string[]>>)[scope] ?? null),
  },
}))
vi.mock('../../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => unknown) => fn() }))
// Stand-in for the platform permission gate: refuses when the test marks the caller as lacking it,
// and records which permission the route asked for.
const gate = vi.hoisted(() => ({ asked: [] as string[] }))
vi.mock('../../../middleware/require-permission.js', () => ({
  requirePermission: (perm: string) => {
    gate.asked.push(perm)
    return async (request: { headers: Record<string, unknown> }, reply: { status: (c: number) => { send: (b: unknown) => unknown } }) => {
      if (request.headers['x-test-lacks']) return reply.status(403).send({ error: 'Forbidden', message: `requires ${perm}` })
    }
  },
}))

import { userAccessRoutes } from '../../../routes/user-access.routes.js'
import { resetSecondFactorSettingsCache } from '../../../second-factor/settings.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
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
  s.methods = ['totp']
  s.config = {}
  resetSecondFactorSettingsCache()
  s.manageable = { 'Bob@acme.test': [GLOBEX] }
  s.members = { 'Bob@acme.test': [ACME, GLOBEX] }
  s.opaDown = false
  s.asked = []
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
        { orgId: ACME, name: 'Acme', admin: false, rostered: false, grants: ['fleet-viewers'] },
        { orgId: GLOBEX, name: GLOBEX, admin: true, rostered: true, grants: [] },
      ],
      // kuma-admins holds kuma's '*', so its switch defaults on; fleet-viewers only reads.
      secondFactor: {
        required: true,
        requiredBecause: ['kuma-admins'],
        enrolled: true,
        methods: ['totp'],
        currentAal: null,
        factorAgeMin: null,
        stepUpFresh: null,
        stepUpPermissions: ['groups:write'],
      },
    })
    // OPA is asked with the address as the bindings key it (as typed), not a lowercased copy.
    expect(s.asked).toEqual(['Bob@acme.test'])
  })

  it('admin is what the guard decides (manageable_orgs), not the roster', async () => {
    // Rostered, but OPA does not list the org: the org routes refuse, so admin is false.
    s.manageable = { 'Bob@acme.test': [] }
    s.members = { 'Bob@acme.test': [ACME] }
    const orgs = (await app.inject({ url: '/api/admin/users/id-bob/access' })).json().orgs
    expect(orgs[1]).toEqual({ orgId: GLOBEX, name: GLOBEX, admin: false, rostered: true, why: 'not_a_member_per_policy', grants: [] })
    // Not rostered at all, but OPA lists the org (a roster OPAL has not yet caught up with): admin.
    s.rosters = {}
    s.manageable = { 'Bob@acme.test': [ACME] }
    const again = (await app.inject({ url: '/api/admin/users/id-bob/access' })).json().orgs
    expect(again[0]).toMatchObject({ orgId: ACME, admin: true, rostered: false })
  })

  it('says why a rostered member is not admin: policy not loaded yet', async () => {
    s.rosters = { [GLOBEX]: ['Bob@acme.test'] }
    s.manageable = { 'Bob@acme.test': [] }
    const orgs = (await app.inject({ url: '/api/admin/users/id-bob/access' })).json().orgs
    expect(orgs[1]).toMatchObject({ admin: false, rostered: true, why: 'policy_not_yet_loaded' })
  })

  it('a roster entry differing only in case counts as rostered', async () => {
    s.rosters = { [GLOBEX]: ['BOB@ACME.TEST'] }
    const orgs = (await app.inject({ url: '/api/admin/users/id-bob/access' })).json().orgs
    expect(orgs[1]).toMatchObject({ admin: true, rostered: true })
    expect(orgs[1].why).toBeUndefined()
  })

  it('503 when OPA cannot be asked — never an admin flag it could not decide', async () => {
    s.opaDown = true
    expect((await app.inject({ url: '/api/admin/users/id-bob/access' })).statusCode).toBe(503)
  })

  it("follows each group's switch: a stored off removes the requirement", async () => {
    s.config = { second_factor_group_flags: JSON.stringify({ 'kuma-admins': false }) }
    const res = await app.inject({ url: '/api/admin/users/id-bob/access' })
    expect(res.json().secondFactor).toMatchObject({ required: false, requiredBecause: [] })
  })

  it('a second-factor part that cannot be read is null, and the access view still answers', async () => {
    s.methods = null
    const res = await app.inject({ url: '/api/admin/users/id-bob/access' })
    expect(res.statusCode).toBe(200)
    expect(res.json().secondFactor).toMatchObject({ required: true, enrolled: null, methods: null })
  })

  it('is gated on access:read in the app layer, not only at the gateway', async () => {
    expect(gate.asked).toContain('access:read')
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
