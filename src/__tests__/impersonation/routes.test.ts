import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { installRouteAccess } from '../../policy/route-access.js'
import { ROLES } from '../../policy/roles.js'

// The console's side of impersonation, called DIRECTLY at jinbe: who may start one (the permission,
// a browser session, a fresh second factor), who can never be impersonated, the cookie it sets, what
// the state route says, and that stopping always works.

const SUPPORT = '10000000-0000-4000-8000-000000000001'
const BOB = '20000000-0000-4000-8000-000000000001'
const ROOT = '20000000-0000-4000-8000-000000000002'
const DIRECT = '20000000-0000-4000-8000-000000000003'
const ROBOT = '20000000-0000-4000-8000-000000000004'
const GONE = '20000000-0000-4000-8000-000000000005'
const NAMELESS = '20000000-0000-4000-8000-000000000006'
const GHOST = '99999999-9999-4999-8999-999999999999'
const KRATOS = 'http://kratos-admin:4434'

const s = vi.hoisted(() => ({
  // Read when the services are constructed, so set before any import.
  env: { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', KRATOS_ADMIN_URL: 'http://kratos-admin:4434' } as Record<string, unknown>,
  rights: {} as Record<string, { groups?: string[]; roles?: string[]; permissions?: string[] }>,
  opaDown: false,
  redis: new Map<string, { v: string; ttl?: number }>(),
  audits: [] as Array<Record<string, unknown>>,
}))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in s.env ? s.env[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn(async (e: Record<string, unknown>) => { s.audits.push(e); return 'id' }) },
}))
vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    get: async (k: string) => s.redis.get(k)?.v ?? null,
    set: async (k: string, v: string, _ex?: string, ttl?: number) => { s.redis.set(k, { v, ttl }); return 'OK' },
    del: async (...keys: string[]) => keys.filter((k) => s.redis.delete(k)).length,
  }),
}))
vi.mock('../../sites/config.js', () => ({ sitesConfig: () => ({ SITES_COOKIE_DOMAIN: '.dev.example.com' }) }))
vi.mock('../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { impersonationRoutes } from '../../impersonation/routes.js'
import { hashToken } from '../../impersonation/store.js'
import { clearAuthzCache } from '../../authz/opa.js'

const identity = (id: string, over: Record<string, unknown> = {}) => ({
  id, schema_id: 'default', state: 'active', traits: { email: 'bob@example.com', name: 'Bob' },
  metadata_public: null, metadata_admin: { groups: ['customers'] }, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', ...over,
})
const IDENTITIES: Record<string, unknown> = {
  [BOB]: identity(BOB),
  [ROOT]: identity(ROOT, { traits: { email: 'root@example.com', name: 'Root' }, metadata_admin: { groups: ['customers', 'super_admins'] } }),
  [DIRECT]: identity(DIRECT, { traits: { email: 'direct@example.com', name: 'Direct' } }),
  [ROBOT]: identity(ROBOT, { traits: { email: 'ci.builds@serviceaccount.cluster.local', name: 'ci' } }),
  [GONE]: identity(GONE, { state: 'inactive', traits: { email: 'gone@example.com', name: 'Gone' } }),
  [NAMELESS]: identity(NAMELESS, { traits: {} }),
}

let app: FastifyInstance
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.startsWith('http://opal-client:8181/v1/data/rbac/user_info')) {
      if (s.opaDown) throw new TypeError('fetch failed')
      const { input: q } = JSON.parse(init!.body as string) as { input: { email: string } }
      const held = s.rights[q.email] ?? {}
      return Response.json({ result: { email: q.email, groups: held.groups ?? [], roles: held.roles ?? [], permissions: held.permissions ?? [] } })
    }
    if (url.startsWith(`${KRATOS}/admin/identities/`)) {
      const found = IDENTITIES[new URL(url).pathname.split('/').pop() as string]
      return found ? Response.json(found) : Response.json({ error: { code: 404 } }, { status: 404 })
    }
    throw new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url}`)
  }))
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    const who = request.headers['x-test-user'] as string | undefined
    if (!who) return
    const proven = request.headers['x-test-proven'] as string | undefined
    const via = (request.headers['x-test-via'] as string | undefined) ?? 'session'
    request.userContext = {
      id: who === 'support' ? SUPPORT : who === 'bob' ? BOB : who,
      email: `${who}@example.com`,
      name: who,
      ...(via === 'session' ? { sessionId: (request.headers['x-test-session'] as string | undefined) ?? `sess-${who}` } : {}),
      aal: proven ? 'aal2' : 'aal1',
      secondFactorAt: proven ? new Date(Date.now() - Number(proven) * 60_000) : null,
      authVia: via,
    } as never
    if (via === 'machine') request.machine = { username: 'system:serviceaccount:ci:builds' } as never
  })
  await app.register(async (api) => {
    await api.register(impersonationRoutes, { prefix: '/admin' })
  }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => {
  vi.unstubAllGlobals()
  await app.close()
})
beforeEach(() => {
  Object.assign(s.env, { IMPERSONATION_ENABLED: true, IMPERSONATION_MAX_MINUTES: 30, IMPERSONATION_COOKIE_NAME: 'platform_impersonation' })
  s.rights = {
    'support@example.com': { groups: ['staff-support'], roles: ['support'], permissions: [...ROLES.support.permissions] },
    'security@example.com': { groups: ['staff-security'], roles: ['security'], permissions: [...ROLES.security.permissions] },
    'direct@example.com': { groups: [], roles: ['super_admin'], permissions: [...ROLES.super_admin.permissions] },
  }
  s.opaDown = false
  s.redis.clear()
  s.audits = []
  clearAuthzCache()
})

const start = (id = BOB, payload: unknown = { reason: 'Ticket 4821: cannot see invoices' }, headers: Record<string, string> = {}) =>
  app.inject({ method: 'POST', url: `/api/admin/users/${id}/impersonate`, headers: { 'x-test-user': 'support', 'x-test-proven': '2', ...headers }, payload: payload as never })
const state = (headers: Record<string, string> = { 'x-test-user': 'support' }) => app.inject({ url: '/api/admin/impersonation', headers })
const stop = (headers: Record<string, string> = { 'x-test-user': 'support' }) => app.inject({ method: 'DELETE', url: '/api/admin/impersonation', headers })
const v1 = () => s.audits.map((a) => a.v1Event)

describe('the catalogue and the roles', () => {
  it('users:impersonate is critical, needs a fresh second factor and is never delegable; support and super_admin hold it', async () => {
    const { CATALOG } = await import('../../policy/catalog.js')
    expect(CATALOG['users:impersonate']).toMatchObject({ scope: 'platform', area: 'users', sensitivity: 'critical', stepUp: true, delegable: 'never' })
    expect(ROLES.support.permissions).toContain('users:impersonate')
    expect(ROLES.super_admin.permissions).toContain('users:impersonate')
    for (const role of ['developer', 'ops', 'security'] as const) expect(ROLES[role].permissions).not.toContain('users:impersonate')
  })
})

describe('POST /api/admin/users/:id/impersonate', () => {
  it('starts a read-only impersonation: 201, the grant, and the cookie scoped like the session cookie', async () => {
    const res = await start(BOB, { reason: '  Ticket 4821: cannot see invoices  ', minutes: 10 })
    expect(res.statusCode).toBe(201)
    const { active } = res.json()
    expect(active).toEqual({
      target: { id: BOB, email: 'bob@example.com', name: 'Bob' },
      reason: 'Ticket 4821: cannot see invoices',
      startedAt: expect.any(String),
      expiresAt: expect.any(String),
      mode: 'read',
    })
    expect(Date.parse(active.expiresAt) - Date.parse(active.startedAt)).toBe(600_000)

    const cookie = res.headers['set-cookie'] as string
    const [pair, ...attrs] = cookie.split('; ')
    const token = pair.slice('platform_impersonation='.length)
    expect(pair.startsWith('platform_impersonation=')).toBe(true)
    expect(Buffer.from(token, 'base64url').length).toBeGreaterThanOrEqual(32)
    expect(attrs).toEqual(['Domain=.dev.example.com', 'Path=/', 'Max-Age=600', 'HttpOnly', 'Secure', 'SameSite=Lax'])
    // Kept under its hash, with the administrator's session and both identities.
    const stored = JSON.parse(s.redis.get(`jinbe:impersonation:grant:${hashToken(token)}`)!.v)
    expect(stored).toMatchObject({ adminId: SUPPORT, adminEmail: 'support@example.com', adminSessionId: 'sess-support', targetId: BOB, targetEmail: 'bob@example.com', targetName: 'Bob' })
    expect(res.body).not.toContain(token)
  })

  it('audits the start: the administrator as actor, the user as target, the reason', async () => {
    await start()
    expect(v1()).toEqual(['impersonation.started'])
    expect(s.audits[0]).toMatchObject({
      verb: 'started', target: `user:${BOB}`, targetType: 'user', targetId: BOB, result: 'applied', severity: 'high',
      reason: 'Ticket 4821: cannot see invoices',
      actor: { id: SUPPORT, email: 'support@example.com', sessionId: 'sess-support' },
      details: { reason: 'Ticket 4821: cannot see invoices', mode: 'read', minutes: 30 },
    })
  })

  it('lasts IMPERSONATION_MAX_MINUTES when the request names no duration, and never longer', async () => {
    const res = await start()
    expect(res.headers['set-cookie']).toContain('Max-Age=1800')
    s.env.IMPERSONATION_MAX_MINUTES = 15
    expect((await start(BOB, { reason: 'Ticket 4821', minutes: 20 })).statusCode).toBe(400)
    expect((await start(BOB, { reason: 'Ticket 4821', minutes: 15 })).statusCode).toBe(201)
  })

  it.each([
    ['no reason', {}],
    ['a reason under 5 characters', { reason: 'abc' }],
    ['a reason of spaces', { reason: '   a    ' }],
    ['a reason over 500 characters', { reason: 'x'.repeat(501) }],
    ['under 5 minutes', { reason: 'Ticket 4821', minutes: 4 }],
    ['over an hour', { reason: 'Ticket 4821', minutes: 61 }],
    ['a fractional duration', { reason: 'Ticket 4821', minutes: 7.5 }],
  ])('refuses %s with 400', async (_label, payload) => {
    expect((await start(BOB, payload)).statusCode).toBe(400)
    expect(s.redis.size).toBe(0)
  })

  it('has no write mode: a request asking for one still gets a read-only grant', async () => {
    const res = await start(BOB, { reason: 'Ticket 4821', mode: 'write' })
    expect(res.statusCode).toBe(201)
    expect(res.json().active.mode).toBe('read')
    expect(JSON.stringify([...s.redis])).not.toContain('write')
  })

  it('replaces the impersonation already running on the session, and says so in the trail', async () => {
    const first = await start()
    const second = await start(BOB, { reason: 'Second look at the same ticket' })
    expect(second.statusCode).toBe(201)
    expect(v1()).toEqual(['impersonation.started', 'impersonation.stopped', 'impersonation.started'])
    expect(s.audits[1]).toMatchObject({ details: { ended: 'replaced' } })
    const token = (first.headers['set-cookie'] as string).split('; ')[0].split('=')[1]
    expect(s.redis.has(`jinbe:impersonation:grant:${hashToken(token)}`)).toBe(false)
    expect([...s.redis.keys()].filter((k) => k.startsWith('jinbe:impersonation:grant:'))).toHaveLength(1)
  })

  describe('refusals', () => {
    const refused = async (res: Awaited<ReturnType<typeof start>>, status: number, code: string) => {
      expect(res.statusCode).toBe(status)
      expect(res.json()).toMatchObject({ error: status === 404 ? 'Not Found' : 'Forbidden', code, message: expect.any(String) })
      expect(res.headers['set-cookie']).toBeUndefined()
      expect(s.redis.size).toBe(0)
      expect(v1()).not.toContain('impersonation.started')
    }

    it('impersonation_disabled (404) when the flag is off — before the permission or the second factor is asked', async () => {
      s.env.IMPERSONATION_ENABLED = false
      await refused(await start(), 404, 'impersonation_disabled')
      await refused(await start(BOB, { reason: 'Ticket 4821' }, { 'x-test-user': 'security', 'x-test-proven': '' }), 404, 'impersonation_disabled')
    })

    it.each(['bearer', 'machine', 'delegated', 'dev'])('impersonation_session_required (403) for a caller proven by %s', async (via) => {
      await refused(await start(BOB, { reason: 'Ticket 4821' }, { 'x-test-via': via }), 403, 'impersonation_session_required')
    })

    it('impersonation_self (403)', async () => {
      await refused(await start(SUPPORT), 403, 'impersonation_self')
    })

    it('impersonation_target_admin (403) for a member of super_admins', async () => {
      await refused(await start(ROOT), 403, 'impersonation_target_admin')
    })

    it('impersonation_target_admin (403) for the super_admin role held without the group', async () => {
      await refused(await start(DIRECT), 403, 'impersonation_target_admin')
    })

    it.each([
      ['a machine identity', ROBOT],
      ['an inactive identity', GONE],
      ['an unknown identity', GHOST],
      ['an identity without an address', NAMELESS],
    ])('impersonation_target_unavailable (403) for %s', async (_label, id) => {
      await refused(await start(id), 403, 'impersonation_target_unavailable')
    })

    it('records a refusal about the target as a denial', async () => {
      await start(ROOT)
      expect(s.audits).toHaveLength(1)
      expect(s.audits[0]).toMatchObject({ v1Event: 'access.denied', reason: 'impersonation_target_admin', actor: { id: SUPPORT } })
    })

    it('403 permission_required without users:impersonate', async () => {
      const res = await start(BOB, { reason: 'Ticket 4821' }, { 'x-test-user': 'security' })
      expect(res.statusCode).toBe(403)
      expect(res.json()).toMatchObject({ code: 'permission_required', permission: 'users:impersonate' })
      expect(s.redis.size).toBe(0)
    })

    it.each([
      ['no second factor on the session', '', 'reauth_required'],
      ['a second factor older than 15 minutes', '20', 'reauth_required'],
    ])('422 with %s', async (_label, proven, error) => {
      const res = await start(BOB, { reason: 'Ticket 4821' }, { 'x-test-proven': proven })
      expect(res.statusCode).toBe(422)
      expect(res.json().error).toBe(error)
      expect(s.redis.size).toBe(0)
    })

    it('503 policy_unavailable when the policy cannot say who the target is', async () => {
      // The caller's own rights are answered (cached by the permission guard); the target's are not.
      await start()
      s.redis.clear()
      s.opaDown = true
      const res = await start(DIRECT)
      expect(res.statusCode).toBe(503)
      expect(res.json().error).toBe('policy_unavailable')
      expect(s.redis.size).toBe(0)
    })
  })
})

describe('GET /api/admin/impersonation', () => {
  it('says it is on, that the caller may, and that nothing runs', async () => {
    expect((await state()).json()).toEqual({ enabled: true, allowed: true, maxMinutes: 30, active: null })
  })

  it('shows what runs on the caller\'s session, and only on that session', async () => {
    await start()
    expect((await state()).json().active).toMatchObject({ target: { id: BOB, email: 'bob@example.com', name: 'Bob' }, reason: 'Ticket 4821: cannot see invoices', mode: 'read' })
    expect((await state({ 'x-test-user': 'support', 'x-test-session': 'sess-another-browser' })).json().active).toBeNull()
    expect((await state({ 'x-test-user': 'security' })).json()).toEqual({ enabled: true, allowed: false, maxMinutes: 30, active: null })
  })

  it('needs no permission and no second factor: it answers about the caller', async () => {
    const res = await state({ 'x-test-user': 'nobody' })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ enabled: true, allowed: false, active: null })
  })

  it('answers enabled false with the flag off, without reading anything', async () => {
    await start()
    s.env.IMPERSONATION_ENABLED = false
    expect((await state()).json()).toEqual({ enabled: false, allowed: false, maxMinutes: 30, active: null })
  })

  it('answers allowed false, not an error, when the policy cannot say', async () => {
    s.opaDown = true
    expect((await state()).json()).toMatchObject({ enabled: true, allowed: false })
  })
})

describe('DELETE /api/admin/impersonation', () => {
  it('ends the grant, clears the cookie and audits the stop', async () => {
    await start()
    const res = await stop()
    expect(res.statusCode).toBe(204)
    expect((res.headers['set-cookie'] as string).split('; ')).toEqual(['platform_impersonation=', 'Domain=.dev.example.com', 'Path=/', 'Max-Age=0', 'HttpOnly', 'Secure', 'SameSite=Lax'])
    expect(s.redis.size).toBe(0)
    expect((await state()).json().active).toBeNull()
    expect(v1()).toEqual(['impersonation.started', 'impersonation.stopped'])
    expect(s.audits[1]).toMatchObject({ target: `user:${BOB}`, actor: { id: SUPPORT }, details: { ended: 'stopped' } })
  })

  it('always succeeds for a signed-in caller: nothing running, no permission, no second factor, flag off', async () => {
    expect((await stop()).statusCode).toBe(204)
    expect((await stop({ 'x-test-user': 'nobody' })).statusCode).toBe(204)
    s.env.IMPERSONATION_ENABLED = false
    const res = await stop()
    expect(res.statusCode).toBe(204)
    expect(res.headers['set-cookie']).toContain('Max-Age=0')
    expect(s.audits).toEqual([])
  })

  it('leaves another session\'s impersonation alone', async () => {
    await start()
    await stop({ 'x-test-user': 'support', 'x-test-session': 'sess-another-browser' })
    expect((await state()).json().active).not.toBeNull()
  })
})
