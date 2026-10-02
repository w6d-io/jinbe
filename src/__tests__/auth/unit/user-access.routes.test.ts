import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance } from 'fastify'

// J-1: GET /api/admin/users/:id/access — site access and org access side by side, for the console.

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'

const s = vi.hoisted(() => ({
  identity: null as null | Record<string, unknown>,
  orgs: [] as string[],
  assignments: {} as Record<string, Record<string, string[]>>,
  assignmentsFail: false,
  methods: ['totp'] as string[] | null,
  config: {} as Record<string, string>,
  // OPA's answers, keyed on the address as the bindings key it.
  inOrg: {} as Record<string, Record<string, string[]>>,
  opaDown: false,
  asked: [] as string[],
  askedRights: [] as string[],
  direct: [] as Array<Record<string, unknown>>,
}))
vi.mock('../../../services/direct-grants.repository.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../services/direct-grants.repository.js')>()),
  directGrantsRepository: { getFor: vi.fn(async () => s.direct) },
}))

vi.mock('../../../authz/opa.js', () => ({
  orgPermissionsByOrg: vi.fn(async (email: string) => {
    s.asked.push(email)
    if (s.opaDown) throw new Error('OPA unreachable')
    return s.inOrg[email] ?? {}
  }),
  rights: vi.fn(async (address: string) => {
    s.askedRights.push(address)
    return { groups: [], roles: [], permissions: ['sites:read', 'groups:write'] }
  }),
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
vi.mock('../../../services/org-roles.repository.js', () => ({
  orgRolesRepository: {
    getAll: vi.fn(async () => {
      if (s.assignmentsFail) throw new Error('ECONNREFUSED')
      return s.assignments
    }),
  },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => ({
      'kuma-admins': { kuma: ['admin'] },
      'fleet-viewers': { fleet: ['viewer'], kuma: ['reader'] },
      super_admins: { jinbe: ['super_admin'] },
    })),
    getConfig: vi.fn(async () => s.config),
    getRoles: vi.fn(async (scope: string) => ({
      jinbe: { super_admin: ['users:read'] }, kuma: { admin: ['kuma:write'], reader: ['kuma:read'] }, fleet: { viewer: ['fleet:read'] },
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
  s.assignments = { [GLOBEX]: { 'id-bob': ['jinbe:owner'] } }
  s.assignmentsFail = false
  s.methods = ['totp']
  s.config = {}
  resetSecondFactorSettingsCache()
  s.inOrg = { 'Bob@acme.test': { [GLOBEX]: ['org.keys:read', 'org.members:read', 'org.members:write'] } }
  s.opaDown = false
  s.asked = []
  s.direct = []
})

describe('GET /api/admin/users/:id/access', () => {
  it('answers site groups + roles per service, and each org with its org roles and permissions', async () => {
    const res = await app.inject({ url: '/api/admin/users/id-bob/access' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({
      site: {
        groups: ['kuma-admins', 'fleet-viewers'],
        byService: { kuma: ['admin', 'reader'], fleet: ['viewer'] },
        direct: [],
      },
      orgs: [
        { orgId: ACME, name: 'Acme', roles: [], permissions: [], direct: [] },
        { orgId: GLOBEX, name: GLOBEX, roles: ['jinbe:owner'], permissions: ['org.keys:read', 'org.members:read', 'org.members:write'], direct: [] },
      ],
      // kuma-admins can write in kuma, so its switch defaults on; fleet-viewers only reads.
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

  it('shows direct grants, platform-wide and per org, marked direct with who, when, why and until when', async () => {
    const at = '2026-10-01T10:00:00.000Z'
    s.direct = [
      { id: 'g1', scope: 'platform', app: 'jinbe', kind: 'role', name: 'viewer', grantedBy: 'root@example.com', grantedAt: at },
      { id: 'g2', scope: 'platform', app: 'jinbe', kind: 'permission', name: 'audit:read', reason: 'incident 42', expiresAt: '2999-01-01T00:00:00.000Z', grantedBy: 'root@example.com', grantedAt: at },
      { id: 'g3', scope: GLOBEX, app: 'jinbe', kind: 'permission', name: 'org.keys:read', expiresAt: '2020-01-01T00:00:00.000Z', grantedBy: 'owner@example.com', grantedAt: at },
    ]
    const body = (await app.inject({ url: '/api/admin/users/id-bob/access' })).json()
    expect(body.site.direct).toEqual([
      { source: 'direct', id: 'g1', app: 'jinbe', kind: 'role', name: 'viewer', grantedBy: 'root@example.com', grantedAt: at, active: true },
      { source: 'direct', id: 'g2', app: 'jinbe', kind: 'permission', name: 'audit:read', grantedBy: 'root@example.com', grantedAt: at, reason: 'incident 42', expiresAt: '2999-01-01T00:00:00.000Z', active: true },
    ])
    expect(body.orgs.find((o: { orgId: string }) => o.orgId === GLOBEX).direct).toEqual([
      { source: 'direct', id: 'g3', app: 'jinbe', kind: 'permission', name: 'org.keys:read', grantedBy: 'owner@example.com', grantedAt: at, expiresAt: '2020-01-01T00:00:00.000Z', active: false },
    ])
    expect(body.orgs.find((o: { orgId: string }) => o.orgId === ACME).direct).toEqual([])
  })

  it('an identity with no groups shows none (no base `users` group)', async () => {
    s.identity = { id: 'id-bob', traits: { email: 'Bob@acme.test' }, metadata_admin: {} }
    expect((await app.inject({ url: '/api/admin/users/id-bob/access' })).json().site.groups).toEqual([])
  })

  it('the second-factor picture asks OPA with the mixed-case address as bound, not a lowercased copy', async () => {
    s.askedRights = []
    const res = await app.inject({ url: '/api/admin/users/id-bob/access' })
    expect(res.json().secondFactor.stepUpPermissions).toEqual(['groups:write'])
    expect(s.askedRights).toEqual(['Bob@acme.test'])
  })

  it('503 when OPA cannot be asked — never an org view it could not decide', async () => {
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

  it('503 when the org roles cannot be read — never an empty org view', async () => {
    s.assignmentsFail = true
    expect((await app.inject({ url: '/api/admin/users/id-bob/access' })).statusCode).toBe(503)
  })
})
