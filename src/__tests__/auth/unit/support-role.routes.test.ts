import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// The support role, called DIRECTLY at jinbe (no gateway in front — NetworkPolicy is not enforced):
// it edits a user's name and address, lists and revokes sessions, sends recovery and sign-in links —
// and is refused, by jinbe itself, everything else.

const USER = '11111111-1111-1111-1111-111111111111'
const GHOST = '99999999-9999-9999-9999-999999999999'

const SUPPORT = ['sessions:read', 'sessions:revoke', 'users:read', 'users:recovery', 'users:send_login_link', 'users:update', 'users:update_email']

const s = vi.hoisted(() => ({
  rights: {} as Record<string, string[]>,
  identity: null as null | Record<string, unknown>,
  counters: new Map<string, number>(),
  fetches: [] as Array<{ url: string; body?: string }>,
  recoveryGroups: ['default', 'link'] as string[],
  audits: [] as Array<Record<string, unknown>>,
  opaDown: false,
  opaCalls: [] as Array<{ auth: string | null; input: Record<string, unknown> }>,
}))

// OPA is the one engine: jinbe's own guard asks it, over HTTP, with its bearer token.
vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  const over: Record<string, string> = { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret' }
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in over ? over[k as string] : t[k as keyof typeof t]) }) }
})

vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn(async (e: Record<string, unknown>) => { s.audits.push(e); return 'id' }) },
}))
vi.mock('../../../services/kratos.service.js', () => {
  class KratosApiError extends Error {
    constructor(public statusCode: number, message: string) { super(message) }
  }
  const find = async (id: string) => {
    if (!s.identity || s.identity.id !== id) throw new KratosApiError(404, 'Identity not found')
    return s.identity
  }
  return {
    KratosApiError,
    kratosService: {
      getIdentity: vi.fn(find),
      updateIdentity: vi.fn(async (id: string, body: Record<string, unknown>) => {
        const current = await find(id)
        return { ...current, traits: { ...(current.traits as object), ...(body.traits as object) } }
      }),
      deleteIdentity: vi.fn(async () => {}),
      listIdentitySessions: vi.fn(async () => [{ id: 'sess-1', active: true }]),
      revokeSession: vi.fn(async () => {}),
      revokeAllIdentitySessions: vi.fn(async () => {}),
      sendRecoveryEmail: vi.fn(async () => {}),
      invalidateGroupsCache: vi.fn(),
    },
  }
})
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    incr: vi.fn(async (k: string) => { const n = (s.counters.get(k) ?? 0) + 1; s.counters.set(k, n); return n }),
    expire: vi.fn(async () => 1),
    ttl: vi.fn(async () => 600),
  }),
}))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { adminRoutes } from '../../../routes/admin.routes.js'
import { userManagementRoutes } from '../../../routes/user-management.routes.js'
import { meRoutes } from '../../../routes/me.routes.js'
import { rbacRoutes } from '../../../routes/rbac.routes.js'
import { clearAuthzCache } from '../../../authz/opa.js'

let app: FastifyInstance
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.startsWith('http://opal-client:8181/v1/data/rbac/user_info')) {
      const body = JSON.parse(init!.body as string) as { input: Record<string, unknown> }
      s.opaCalls.push({ auth: new Headers(init!.headers).get('authorization'), input: body.input })
      if (s.opaDown) throw new TypeError('fetch failed')
      const who = String(body.input.email).split('@')[0]
      const perms = body.input.app === 'jinbe' ? (s.rights[who] ?? []) : who === 'support' ? [] : ['*']
      return Response.json({ result: { email: body.input.email, groups: [], roles: [], permissions: perms } })
    }
    s.fetches.push({ url, body: init?.body as string | undefined })
    if (url.includes('/self-service/recovery/api')) {
      if (url.includes('return_to=https%3A%2F%2Fevil')) return new Response('{}', { status: 400 })
      return Response.json({
        id: 'flow-1',
        expires_at: '2026-09-26T13:00:00Z',
        ui: { nodes: s.recoveryGroups.map((group) => ({ group })) },
      })
    }
    return Response.json({ state: 'sent_email' })
  }))
  app = Fastify()
  app.addHook('onRequest', async (request) => {
    const who = request.headers['x-test-user'] as string | undefined
    if (who) request.userContext = { id: who, email: `${who}@example.com`, name: who } as never
  })
  await app.register(async (api) => {
    await api.register(userManagementRoutes, { prefix: '/admin' })
    await api.register(adminRoutes, { prefix: '/admin' })
    await api.register(rbacRoutes, { prefix: '/admin/rbac' })
    await api.register(meRoutes, { prefix: '/me' })
  }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => {
  vi.unstubAllGlobals()
  await app.close()
})
beforeEach(() => {
  s.rights = { support: SUPPORT, admin: ['admin:read', 'admin:write'], reader: ['admin:read'], nobody: [], nameonly: ['users:read', 'users:update'] }
  s.identity = { id: USER, schema_id: 'default', state: 'active', traits: { email: 'bob@example.com', name: 'Bob' }, metadata_admin: { groups: ['users'] } }
  s.counters.clear()
  s.fetches = []
  s.recoveryGroups = ['default', 'link']
  s.audits = []
  s.opaDown = false
  s.opaCalls = []
  clearAuthzCache()
})

const as = (who: string) => ({ 'x-test-user': who })

describe('support can do the support desk\'s work', () => {
  it('reads a user', async () => {
    expect((await app.inject({ url: `/api/admin/users/${USER}`, headers: as('support') })).statusCode).toBe(200)
  })

  it('changes a user\'s address', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/admin/users/${USER}`, headers: as('support'), payload: { traits: { email: 'bobby@example.com' } } })
    expect(res.statusCode).toBe(200)
    expect(res.json().traits.email).toBe('bobby@example.com')
  })

  it('lists and revokes sessions', async () => {
    expect((await app.inject({ url: `/api/admin/users/${USER}/sessions`, headers: as('support') })).statusCode).toBe(200)
    expect((await app.inject({ method: 'DELETE', url: `/api/admin/users/${USER}/sessions`, headers: as('support') })).statusCode).toBe(204)
    expect((await app.inject({ method: 'DELETE', url: '/api/admin/sessions/sess-1', headers: as('support') })).statusCode).toBe(204)
  })

  it('sends a recovery email and a sign-in link', async () => {
    expect((await app.inject({ method: 'POST', url: `/api/admin/users/${USER}/recovery-email`, headers: as('support') })).statusCode).toBe(204)
    expect((await app.inject({ method: 'POST', url: `/api/admin/users/${USER}/login-link`, headers: as('support') })).statusCode).toBe(200)
  })
})

describe('support is refused by jinbe itself, not only at the gateway', () => {
  const refused: Array<[string, string, unknown?]> = [
    ['DELETE', `/api/admin/users/${USER}`],
    ['POST', '/api/admin/users', { email: 'new@example.com' }],
    ['PUT', '/api/admin/users/bob@example.com/groups', { groups: ['super_admins'] }],
    ['GET', '/api/admin/users/bob@example.com/groups'],
    ['PATCH', `/api/admin/users/${USER}/state`, { state: 'inactive' }],
    ['PATCH', `/api/admin/users/${USER}/metadata`, { metadata_admin: { x: 1 } }],
    ['GET', '/api/admin/rbac/groups'],
    ['DELETE', '/api/admin/rbac/groups/support'],
    ['GET', '/api/admin/rbac/services'],
    ['GET', '/api/admin/assignable-groups'],
    ['GET', '/api/admin/sites'],
  ]
  for (const [method, url, payload] of refused) {
    it(`${method} ${url} → 403`, async () => {
      const res = await app.inject({ method: method as never, url, headers: as('support'), ...(payload ? { payload: payload as never } : {}) })
      expect(res.statusCode).toBe(403)
    })
  }

  it('an edit reaching outside the traits (state) needs admin:write', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/admin/users/${USER}`, headers: as('support'), payload: { state: 'inactive' } })
    expect(res.statusCode).toBe(403)
  })
})

describe('an edit needs what it changes', () => {
  it('a caller without users:update_email cannot change the address', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/admin/users/${USER}`, headers: as('nameonly'), payload: { traits: { name: 'Robert', email: 'rob@example.com' } } })
    expect(res.statusCode).toBe(403)
    expect(res.json().message).toContain('users:update_email')
  })

  it('but may change the name, and resend the address unchanged (even re-cased)', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/admin/users/${USER}`, headers: as('nameonly'), payload: { traits: { name: 'Robert', email: 'Bob@Example.COM' } } })
    expect(res.statusCode).toBe(200)
  })

  it('somebody holding nothing learns nothing: 403 before the user is looked up', async () => {
    const res = await app.inject({ method: 'PUT', url: `/api/admin/users/${GHOST}`, headers: as('nobody'), payload: { traits: { name: 'x' } } })
    expect(res.statusCode).toBe(403)
  })

  it('anonymous → 401', async () => {
    expect((await app.inject({ method: 'PUT', url: `/api/admin/users/${USER}`, payload: { traits: { name: 'x' } } })).statusCode).toBe(401)
  })
})

describe('administrators keep everything; a reader no longer writes', () => {
  it('admin:write edits, deletes and creates', async () => {
    expect((await app.inject({ method: 'PUT', url: `/api/admin/users/${USER}`, headers: as('admin'), payload: { traits: { email: 'x@example.com' }, state: 'inactive' } })).statusCode).toBe(200)
    expect((await app.inject({ method: 'DELETE', url: `/api/admin/users/${USER}`, headers: as('admin') })).statusCode).toBe(204)
  })

  it('admin:read alone reads but cannot delete', async () => {
    expect((await app.inject({ url: `/api/admin/users/${USER}`, headers: as('reader') })).statusCode).toBe(200)
    expect((await app.inject({ method: 'DELETE', url: `/api/admin/users/${USER}`, headers: as('reader') })).statusCode).toBe(403)
  })
})

describe('POST /users/:id/login-link', () => {
  const send = (payload?: unknown, who = 'support', id = USER) =>
    app.inject({ method: 'POST', url: `/api/admin/users/${id}/login-link`, headers: as(who), ...(payload ? { payload: payload as never } : {}) })

  it('asks Kratos to mail a recovery LINK to the user\'s address and never returns it', async () => {
    const res = await send()
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ sent: true, expiresAt: '2026-09-26T13:00:00Z' })
    expect(res.body).not.toMatch(/token|flow-1|bob@example/)
    const submit = s.fetches.find((f) => f.url.includes('/self-service/recovery?flow=flow-1'))
    expect(JSON.parse(submit!.body!)).toEqual({ email: 'bob@example.com', method: 'link' })
  })

  it('passes return_to to Kratos, which refuses one it does not allow', async () => {
    expect((await send({ return_to: 'https://app.example.com/x' })).statusCode).toBe(200)
    expect(s.fetches[0].url).toContain('return_to=https%3A%2F%2Fapp.example.com%2Fx')
    expect((await send({ return_to: 'https://evil.example/x' })).statusCode).toBe(400)
    expect((await send({ return_to: 'javascript:alert(1)' })).statusCode).toBe(400)
  })

  it('allows 3 per user per 15 minutes', async () => {
    for (let i = 0; i < 3; i++) expect((await send()).statusCode).toBe(200)
    const limited = await send()
    expect(limited.statusCode).toBe(429)
    expect(limited.headers['retry-after']).toBe('600')
  })

  it('404 for an unknown user, without counting or mailing', async () => {
    expect((await send(undefined, 'support', GHOST)).statusCode).toBe(404)
    expect(s.counters.size).toBe(0)
    expect(s.fetches).toHaveLength(0)
  })

  it('refuses rather than mailing a code nobody can use when Kratos recovers by code only', async () => {
    s.recoveryGroups = ['default', 'code']
    const res = await send()
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('login_link_unavailable')
    expect(s.fetches.some((f) => f.url.includes('recovery?flow='))).toBe(false)
  })

  it('audits user.login_link_sent with the actor and target ids and no address', async () => {
    await send()
    const event = s.audits.find((e) => e.v1Event === 'user.login_link_sent')!
    expect(event).toBeDefined()
    expect(event.targetId).toBe(USER)
    expect((event.actor as Record<string, unknown>).id).toBe('support')
    expect(JSON.stringify(event)).not.toContain('@example.com')
  })

  it('needs users:send_login_link', async () => {
    expect((await send(undefined, 'nameonly')).statusCode).toBe(403)
  })
})

describe('the guard asks OPA, and only OPA', () => {
  it('queries rbac/user_info for the caller in app jinbe, with the bearer token', async () => {
    await app.inject({ url: `/api/admin/users/${USER}`, headers: as('support') })
    expect(s.opaCalls[0]).toEqual({ auth: 'Bearer opa-secret', input: { email: 'support@example.com', app: 'jinbe' } })
  })

  it('the admin plugin gate (requireAdmin) asks OPA too — no second source', async () => {
    await app.inject({ url: '/api/admin/sites', headers: as('support') })
    expect(s.opaCalls).toEqual([{ auth: 'Bearer opa-secret', input: { email: 'support@example.com', app: 'jinbe' } }])
  })

  it('caches the answer for a few seconds', async () => {
    for (let i = 0; i < 3; i++) await app.inject({ url: `/api/admin/users/${USER}`, headers: as('support') })
    // The caller's rights once; the user shown is asked about too (what OPA says they hold), also once.
    expect(s.opaCalls.filter((c) => c.input.email === 'support@example.com')).toHaveLength(1)
    expect(s.opaCalls).toHaveLength(2)
  })

  it('fails closed: OPA unreachable → 503, never an allow', async () => {
    s.opaDown = true
    expect((await app.inject({ url: `/api/admin/users/${USER}`, headers: as('admin') })).statusCode).toBe(503)
    expect((await app.inject({ url: '/api/me/permissions', headers: as('admin') })).statusCode).toBe(503)
  })

  it('the Redis-granted support role, as OPA reports it, has users:update_email but not users:assign_group', async () => {
    const { actions } = (await app.inject({ url: '/api/me/permissions', headers: as('support') })).json()
    expect(actions['users:update_email']).toBe(true)
    expect(actions['users:assign_group']).toBe(false)
    // Even a creator is refused a group unless OPA grants users:assign_group.
    s.rights.creator = [...SUPPORT, 'users:create']
    const res = await app.inject({ method: 'POST', url: '/api/admin/users', headers: as('creator'), payload: { email: 'n@example.com', groups: ['admins'] } })
    expect(res.statusCode).toBe(403)
    expect(res.json().message).toContain('users:assign_group')
  })

  it('the per-service `*` (jinbe admin role) passes every action', async () => {
    s.rights.star = ['*']
    expect((await app.inject({ method: 'DELETE', url: `/api/admin/users/${USER}`, headers: as('star') })).statusCode).toBe(204)
  })
})

describe('GET /api/me/permissions', () => {
  it('tells kuma which actions the support role may take', async () => {
    const res = await app.inject({ url: '/api/me/permissions', headers: as('support') })
    expect(res.statusCode).toBe(200)
    const { actions, permissions } = res.json()
    expect(permissions).toEqual(SUPPORT)
    expect(res.json().apps).toEqual({ jinbe: { roles: [], permissions: SUPPORT }, kuma: { roles: [], permissions: [] } })
    expect(actions).toMatchObject({
      'users:read': true, 'users:update_email': true, 'sessions:revoke': true, 'users:send_login_link': true,
      'users:delete': false, 'users:create': false, 'users:assign_group': false, 'admin:read': false, 'admin:write': false,
    })
  })

  it('an administrator is offered every action', async () => {
    const { actions } = (await app.inject({ url: '/api/me/permissions', headers: as('admin') })).json()
    expect(Object.values(actions).every(Boolean)).toBe(true)
  })

  it('anonymous → 401', async () => {
    expect((await app.inject({ url: '/api/me/permissions' })).statusCode).toBe(401)
  })
})
