import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// J-1 grant API (contract shared with kuma):
//   GET /grants, PUT /users/:id/grants, GET /assignable-groups — under /api/organizations/:organizationId.
// Each grant is decided by OPA `data.rbac.delegation.can_grant`, asked with the OPA bearer token;
// one refusal refuses the whole write, and nothing is written. OPA unset or unreachable → nothing is
// written either (fail closed).

const ACME = '11111111-1111-1111-1111-111111111111'
const TOKEN = 'o'.repeat(40)
const BOB = '33333333-3333-3333-3333-333333333333'

const s = vi.hoisted(() => ({
  cfg: { OPA_URL: 'http://opal-client:8181' as string | undefined, OPA_TOKEN: 'o'.repeat(40) as string | undefined },
  identity: null as null | Record<string, unknown>,
  member: true,
  grants: {} as Record<string, string[]>,
  setForMember: vi.fn(),
  notify: vi.fn(),
  guard: vi.fn(),
  guardParam: '' as string,
  groups: {
    'fleet-viewers': { fleet: ['viewer'] },
    'kuma-readers': { kuma: ['reader'] },
    'fleet-admins': { fleet: ['admin'] },
    super_admins: { global: ['super_admin'] },
  } as Record<string, Record<string, string[]>>,
  bundle: { '11111111-1111-1111-1111-111111111111': ['fleet', 'kuma'] } as Record<string, string[]>,
}))

vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  return {
    ...real,
    env: new Proxy(real.env, {
      get: (target, key) => (key in s.cfg ? s.cfg[key as keyof typeof s.cfg] : target[key as keyof typeof target]),
    }),
  }
})
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getIdentity: vi.fn(async (id: string) => {
      if (!s.identity || s.identity.id !== id) {
        throw Object.assign(new Error('Identity not found'), { statusCode: 404 })
      }
      return s.identity
    }),
  },
  KratosApiError: class extends Error {},
}))
vi.mock('../../../services/org-membership.service.js', () => ({
  isMemberOf: vi.fn(async () => s.member),
}))
vi.mock('../../../services/org-grants.repository.js', () => ({
  orgGrantsRepository: {
    getForOrg: vi.fn(async () => ({ 'bob@acme.test': s.grants['bob@acme.test'] ?? [] })),
    getForMember: vi.fn(async (_org: string, email: string) => s.grants[email] ?? []),
    setForMember: s.setForMember,
  },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => s.groups),
    getOrgServiceMap: vi.fn(async () => s.bundle),
  },
}))
vi.mock('../../../services/rbac.service.js', () => ({ rbacService: { notifyBindingsChanged: s.notify } }))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))
vi.mock('../../../middleware/require-org-permission.js', () => ({
  requireOrgAdmin: vi.fn((param: string) => async (request: FastifyRequest, reply: FastifyReply) => {
    s.guardParam = param
    s.guard(request)
    if (request.headers['x-test-refuse']) return reply.status(403).send({ error: 'Forbidden', message: 'no' })
  }),
}))

import { orgGrantsRoutes } from '../../../routes/org-grants.routes.js'

let app: FastifyInstance
const opaCalls: Array<{ url: string; input: Record<string, unknown>; auth: string | null }> = []
let canGrant: (input: Record<string, unknown>) => unknown = () => true
let assignable: unknown = []
let opaStatus = 200

beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    request.userContext = { id: 'subject-olivia', email: 'Olivia@acme.test', name: 'Olivia' } as never
  })
  await app.register(orgGrantsRoutes, { prefix: '/api/organizations/:organizationId' })
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  vi.restoreAllMocks()
  s.cfg.OPA_URL = 'http://opal-client:8181'
  s.cfg.OPA_TOKEN = TOKEN
  s.identity = { id: BOB, traits: { email: 'Bob@acme.test' } }
  s.member = true
  s.grants = {}
  s.setForMember.mockReset().mockResolvedValue([])
  s.notify.mockReset().mockResolvedValue(undefined)
  opaCalls.length = 0
  canGrant = () => true
  assignable = []
  opaStatus = 200
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    const input = JSON.parse(String((init as RequestInit).body)).input
    const auth = new Headers((init as RequestInit).headers).get('authorization')
    opaCalls.push({ url: String(url), input, auth })
    const result = String(url).endsWith('/can_grant') ? canGrant(input) : assignable
    return { ok: opaStatus < 300, status: opaStatus, json: async () => ({ result }) } as Response
  })
})

const put = (groups: unknown, headers: Record<string, string> = {}) =>
  app.inject({ method: 'PUT', url: `/api/organizations/${ACME}/users/${BOB}/grants`, payload: { groups }, headers })

describe('grant routes — guard', () => {
  it('every route sits behind the org-admin-or-super_admin guard on :organizationId', async () => {
    for (const [method, url] of [
      ['GET', `/api/organizations/${ACME}/grants`],
      ['PUT', `/api/organizations/${ACME}/users/${BOB}/grants`],
      ['GET', `/api/organizations/${ACME}/assignable-groups`],
    ] as const) {
      const res = await app.inject({ method, url, payload: method === 'PUT' ? { groups: [] } : undefined, headers: { 'x-test-refuse': '1' } })
      expect(res.statusCode).toBe(403)
    }
    expect(s.setForMember).not.toHaveBeenCalled()
    expect(s.guardParam).toBe('organizationId')
  })
})

describe('GET /grants', () => {
  it('answers { grants: { email: groups } }', async () => {
    s.grants = { 'bob@acme.test': ['fleet-viewers'] }
    const res = await app.inject({ url: `/api/organizations/${ACME}/grants` })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ grants: { 'bob@acme.test': ['fleet-viewers'] } })
  })
})

describe('PUT /users/:id/grants', () => {
  it('asks OPA can_grant per new group with the bearer token and the exact input, then writes', async () => {
    const res = await put(['fleet-viewers', 'kuma-readers'])
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ email: 'bob@acme.test', groups: ['fleet-viewers', 'kuma-readers'] })

    expect(opaCalls.map((c) => c.url)).toEqual([
      'http://opal-client:8181/v1/data/rbac/delegation/can_grant',
      'http://opal-client:8181/v1/data/rbac/delegation/can_grant',
    ])
    expect(opaCalls.map((c) => c.input)).toEqual([
      { actor: { email: 'olivia@acme.test' }, target_group: 'fleet-viewers', target_org: ACME, grantee: { email: 'bob@acme.test' } },
      { actor: { email: 'olivia@acme.test' }, target_group: 'kuma-readers', target_org: ACME, grantee: { email: 'bob@acme.test' } },
    ])
    for (const c of opaCalls) expect(c.auth).toBe(`Bearer ${TOKEN}`)
    expect(s.setForMember).toHaveBeenCalledWith(ACME, 'bob@acme.test', ['fleet-viewers', 'kuma-readers'])
    expect(s.notify).toHaveBeenCalled()
  })

  it('refuses with 403 and the refused list when any group is refused — and writes nothing', async () => {
    canGrant = (input) => input.target_group !== 'fleet-admins'
    const res = await put(['fleet-viewers', 'fleet-admins'])
    expect(res.statusCode).toBe(403)
    const body = res.json()
    expect(body.error).toBe('Forbidden')
    expect(body.refused).toEqual([{ group: 'fleet-admins', reason: expect.any(String) }])
    expect(s.setForMember).not.toHaveBeenCalled()
  })

  it('a non-boolean or missing OPA answer is a refusal (only `true` grants)', async () => {
    canGrant = () => undefined
    expect((await put(['fleet-viewers'])).statusCode).toBe(403)
    canGrant = () => 'true'
    expect((await put(['fleet-viewers'])).statusCode).toBe(403)
    expect(s.setForMember).not.toHaveBeenCalled()
  })

  it('removing grants needs no OPA call — only groups being added are asked', async () => {
    s.grants = { 'bob@acme.test': ['fleet-viewers', 'kuma-readers'] }
    const res = await put(['kuma-readers'])
    expect(res.statusCode).toBe(200)
    expect(opaCalls).toEqual([])
    expect(s.setForMember).toHaveBeenCalledWith(ACME, 'bob@acme.test', ['kuma-readers'])
  })

  it('503 and nothing written when OPA_URL / OPA_TOKEN are unset — never an open fallback', async () => {
    s.cfg.OPA_TOKEN = undefined
    const res = await put(['fleet-viewers'])
    expect(res.statusCode).toBe(503)
    expect(globalThis.fetch).not.toHaveBeenCalled()
    expect(s.setForMember).not.toHaveBeenCalled()
  })

  it('fails closed when OPA refuses the query or is unreachable', async () => {
    opaStatus = 401
    expect((await put(['fleet-viewers'])).statusCode).toBe(502)
    vi.mocked(globalThis.fetch).mockRejectedValueOnce(new Error('ECONNREFUSED'))
    opaStatus = 200
    expect((await put(['fleet-viewers'])).statusCode).toBe(502)
    expect(s.setForMember).not.toHaveBeenCalled()
  })

  it('404 for an unknown user or one who is not a member of the org', async () => {
    s.identity = null
    const unknown = await put(['fleet-viewers'])
    expect(unknown.statusCode).toBe(404)
    expect(unknown.json().message).toBe('User not found')
    s.identity = { id: BOB, traits: { email: 'bob@acme.test' } }
    s.member = false
    const outsider = await put(['fleet-viewers'])
    expect(outsider.statusCode).toBe(404)
    // Never Fastify's unmatched-route wording, which kuma reads as "endpoint not deployed".
    expect(outsider.json().message).toBe('User is not a member of this organization')
    expect(outsider.json().message).not.toMatch(/^Route /)
    expect(opaCalls).toEqual([])
    expect(s.setForMember).not.toHaveBeenCalled()
  })

  it('400 on a malformed body', async () => {
    expect((await put([{}])).statusCode).toBe(400)
    expect((await put([''])).statusCode).toBe(400)
    expect(s.setForMember).not.toHaveBeenCalled()
  })
})

describe('GET /assignable-groups', () => {
  it('asks OPA assignable_groups with the bearer token and answers { groups: [{ name, services }] }', async () => {
    assignable = ['fleet-viewers', 'kuma-readers']
    const res = await app.inject({ url: `/api/organizations/${ACME}/assignable-groups` })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({
      groups: [
        { name: 'fleet-viewers', services: { fleet: ['viewer'] } },
        { name: 'kuma-readers', services: { kuma: ['reader'] } },
      ],
    })
    expect(opaCalls).toEqual([{
      url: 'http://opal-client:8181/v1/data/rbac/delegation/assignable_groups',
      input: { actor: { email: 'olivia@acme.test' }, target_org: ACME },
      auth: `Bearer ${TOKEN}`,
    }])
  })

  it('never offers a global group, an unknown group, or one outside the org bundle', async () => {
    s.bundle = { [ACME]: ['kuma'] }
    assignable = ['super_admins', 'ghost', 'fleet-viewers', 'kuma-readers']
    const res = await app.inject({ url: `/api/organizations/${ACME}/assignable-groups` })
    expect(res.json()).toEqual({ groups: [{ name: 'kuma-readers', services: { kuma: ['reader'] } }] })
    s.bundle = { [ACME]: ['fleet', 'kuma'] }
  })

  it('503 when OPA is not configured', async () => {
    s.cfg.OPA_URL = undefined
    const res = await app.inject({ url: `/api/organizations/${ACME}/assignable-groups` })
    expect(res.statusCode).toBe(503)
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })
})
