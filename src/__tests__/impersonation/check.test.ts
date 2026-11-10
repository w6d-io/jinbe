import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { installRouteAccess } from '../../policy/route-access.js'
import { ROLES } from '../../policy/roles.js'

// The gateway's check, asked as Oathkeeper asks it (the site request's method, its Cookie header,
// X-Forwarded-Host): 200 with a session-shaped body for the impersonated user only when every
// condition holds, 401 with the reason otherwise — and the impersonation cookie is a credential
// nowhere else in jinbe.

const SUPPORT = '10000000-0000-4000-8000-000000000001'
const OTHER = '10000000-0000-4000-8000-000000000002'
const BOB = '20000000-0000-4000-8000-000000000001'
const KRATOS_ADMIN = 'http://kratos-admin:4434'
const KRATOS_PUBLIC = 'http://kratos-public:4433'
const URL_ = '/api/oathkeeper/impersonation/session'

type Session = { id: string; identity: string; email: string; aal: string }

const s = vi.hoisted(() => ({
  // Read when the services are constructed, so set before any import.
  env: { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', KRATOS_ADMIN_URL: 'http://kratos-admin:4434', KRATOS_PUBLIC_URL: 'http://kratos-public:4433' } as Record<string, unknown>,
  permissions: {} as Record<string, string[]>,
  groups: {} as Record<string, string[]>,
  opaDown: false,
  sessions: {} as Record<string, Session>,
  target: null as Record<string, unknown> | null,
  redis: new Map<string, { v: string; ttl?: number }>(),
  audits: [] as Array<Record<string, unknown>>,
  whoami: [] as string[],
  identityReads: 0,
}))

vi.mock('../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../config/env.js')>()
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in s.env ? s.env[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../config/index.js', async () => ({ env: (await import('../../config/env.js')).env }))
vi.mock('../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn(async (e: Record<string, unknown>) => { s.audits.push(e); return 'id' }) },
}))
vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    get: async (k: string) => s.redis.get(k)?.v ?? null,
    set: async (k: string, v: string, _ex?: string, ttl?: number, nx?: string) => {
      if (nx === 'NX' && s.redis.has(k)) return null
      s.redis.set(k, { v, ttl })
      return 'OK'
    },
    del: async (...keys: string[]) => keys.filter((k) => s.redis.delete(k)).length,
  }),
}))
vi.mock('../../sites/config.js', () => ({ sitesConfig: () => ({ SITES_COOKIE_DOMAIN: '.dev.example.com' }) }))
vi.mock('../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { impersonationCheckRoutes, impersonationRoutes } from '../../impersonation/routes.js'
import { resetImpersonationCheck } from '../../impersonation/check.js'
import { impersonationStore } from '../../impersonation/store.js'
import { extractIdentity } from '../../middleware/identity-extractor.js'
import { requireAuth } from '../../middleware/require-auth.js'
import { clearSessionCache } from '../../services/kratos-session.service.js'
import { clearAuthzCache } from '../../authz/opa.js'

const METHODS = [
  { method: 'password', aal: 'aal1', completed_at: '2026-11-10T09:00:00Z' },
  { method: 'totp', aal: 'aal2', completed_at: '2026-11-10T09:00:30Z' },
]
const bob = (over: Record<string, unknown> = {}) => ({
  id: BOB, schema_id: 'default', schema_url: 'http://kratos/schemas/default', state: 'active',
  traits: { email: 'bob@example.com', name: 'Bob' },
  verifiable_addresses: [{ id: '30000000-0000-4000-8000-000000000001', value: 'bob@example.com', verified: true, via: 'email', status: 'completed' }],
  metadata_public: { person_uuid: 'p-1' },
  metadata_admin: { groups: ['customers'], internal_note: 'never shown' },
  credentials: { password: { type: 'password' } },
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', ...over,
})

let app: FastifyInstance
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input)
    if (url === `${KRATOS_PUBLIC}/sessions/whoami`) {
      const cookie = String((init?.headers as Record<string, string>).Cookie)
      s.whoami.push(cookie)
      const found = s.sessions[cookie.replace(/^ory_kratos_session=/, '')]
      if (!found) return Response.json({ error: { code: 401 } }, { status: 401 })
      return Response.json({
        id: found.id, active: true, expires_at: new Date(Date.now() + 3_600_000).toISOString(), authenticated_at: '2026-11-10T09:00:00Z',
        authenticator_assurance_level: found.aal, authentication_methods: found.aal === 'aal2' ? METHODS : METHODS.slice(0, 1),
        identity: { id: found.identity, schema_id: 'default', state: 'active', traits: { email: found.email, name: 'Staff' }, created_at: '', updated_at: '' },
      })
    }
    if (url.startsWith('http://opal-client:8181/v1/data/rbac/user_info')) {
      if (s.opaDown) throw new TypeError('fetch failed')
      const { input: q } = JSON.parse(init!.body as string) as { input: { email: string } }
      return Response.json({ result: { email: q.email, groups: s.groups[q.email] ?? [], roles: [], permissions: s.permissions[q.email] ?? [] } })
    }
    if (url === `${KRATOS_ADMIN}/admin/identities/${BOB}`) {
      s.identityReads++
      return s.target ? Response.json(s.target) : Response.json({ error: { code: 404 } }, { status: 404 })
    }
    throw new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url}`)
  }))
  app = Fastify()
  installRouteAccess(app)
  // The real identity extraction and session gate, as the server installs them.
  app.addHook('onRequest', extractIdentity)
  app.addHook('onRequest', requireAuth)
  await app.register(async (api) => {
    await api.register(impersonationRoutes, { prefix: '/admin' })
    await api.register(impersonationCheckRoutes, { prefix: '/oathkeeper' })
  }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => {
  vi.unstubAllGlobals()
  await app.close()
})

/** Forget what the check keeps for a few seconds, as if they had passed. */
const settle = () => {
  clearSessionCache()
  clearAuthzCache()
  resetImpersonationCheck()
}

let token = ''
beforeEach(async () => {
  Object.assign(s.env, { IMPERSONATION_ENABLED: true, IMPERSONATION_COOKIE_NAME: 'platform_impersonation' })
  s.permissions = { 'support@example.com': [...ROLES.support.permissions], 'other@example.com': [...ROLES.support.permissions] }
  s.groups = {}
  s.opaDown = false
  s.sessions = {
    'cookie-support': { id: 'sess-support', identity: SUPPORT, email: 'support@example.com', aal: 'aal2' },
    'cookie-support-2': { id: 'sess-support-2', identity: SUPPORT, email: 'support@example.com', aal: 'aal2' },
    'cookie-other': { id: 'sess-other', identity: OTHER, email: 'other@example.com', aal: 'aal2' },
  }
  s.target = bob()
  s.redis.clear()
  s.audits = []
  s.whoami = []
  s.identityReads = 0
  settle()
  token = (await impersonationStore.start({
    adminId: SUPPORT, adminEmail: 'support@example.com', adminSessionId: 'sess-support',
    targetId: BOB, targetEmail: 'bob@example.com', targetName: 'Bob', reason: 'Ticket 4821: cannot see invoices',
  }, 600)).token
})

const cookies = (over: { imp?: string | null; session?: string | null } = {}) =>
  [
    over.session === null ? null : `ory_kratos_session=${over.session ?? 'cookie-support'}`,
    'theme=dark',
    over.imp === null ? null : `platform_impersonation=${over.imp ?? token}`,
  ].filter(Boolean).join('; ')

const check = (method = 'GET', cookie: string = cookies(), host = 'payroll.dev.example.com') =>
  app.inject({ method: method as 'GET', url: URL_, headers: { cookie, 'x-forwarded-host': host } })

const refused = async (res: Awaited<ReturnType<typeof check>>, reason: string) => {
  expect(res.statusCode).toBe(401)
  expect(res.json()).toEqual({ error: 'Unauthorized', reason })
}
const v1 = () => s.audits.map((a) => a.v1Event)
const grantLive = async () => (await impersonationStore.byToken(token)) !== null

describe('the happy path', () => {
  it('answers 200 with a session whose identity is the impersonated user', async () => {
    const res = await check()
    expect(res.statusCode).toBe(200)
    const body = res.json()
    const grant = (await impersonationStore.byToken(token))!
    expect(body).toEqual({
      id: `impersonation:${grant.id}`,
      active: true,
      expires_at: grant.expiresAt,
      authenticated_at: grant.startedAt,
      authenticator_assurance_level: 'aal2',
      authentication_methods: METHODS,
      identity: {
        id: BOB, schema_id: 'default', schema_url: 'http://kratos/schemas/default', state: 'active',
        traits: { email: 'bob@example.com', name: 'Bob' },
        verifiable_addresses: [{ id: '30000000-0000-4000-8000-000000000001', value: 'bob@example.com', verified: true, via: 'email', status: 'completed' }],
        metadata_public: { person_uuid: 'p-1' },
        created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
      },
      impersonator: { id: SUPPORT, email: 'support@example.com', session_id: 'sess-support' },
    })
    // What the gate templates read: the user as subject and address, the administrator's level.
    expect(body.identity.id).toBe(BOB)
    expect(body.identity.traits.email).toBe('bob@example.com')
    expect(res.body).not.toContain('metadata_admin')
    expect(res.body).not.toContain('credentials')
    expect(res.body).not.toContain('never shown')
    expect(res.headers['cache-control']).toBe('no-store')
  })

  it.each(['GET', 'HEAD', 'OPTIONS'])('lets %s through', async (method) => {
    expect((await check(method)).statusCode).toBe(200)
  })

  it('traces the use once per grant and host, not once per request', async () => {
    await check()
    await check()
    await check('HEAD')
    expect(v1()).toEqual(['impersonation.used'])
    expect(s.audits[0]).toMatchObject({
      target: `user:${BOB}`, targetId: BOB, result: 'applied', reason: 'Ticket 4821: cannot see invoices',
      actor: { id: SUPPORT, email: 'support@example.com', sessionId: 'sess-support' },
      details: { host: 'payroll.dev.example.com', mode: 'read' },
    })
    await check('GET', cookies(), 'invoices.dev.example.com')
    expect(v1()).toEqual(['impersonation.used', 'impersonation.used'])
    // Another replica that never saw the grant finds the Redis marker and stays quiet.
    resetImpersonationCheck()
    await check()
    expect(v1()).toHaveLength(2)
  })

  it('keeps the user for a few seconds instead of asking Kratos on every request', async () => {
    for (let i = 0; i < 5; i++) await check()
    expect(s.identityReads).toBe(1)
    expect(s.whoami).toHaveLength(1)
  })

  it('hands Kratos the session cookie only, never the impersonation cookie', async () => {
    await check()
    expect(s.whoami).toEqual(['ory_kratos_session=cookie-support'])
  })
})

describe('every condition that fails', () => {
  it('impersonation is off', async () => {
    s.env.IMPERSONATION_ENABLED = false
    await refused(await check(), 'impersonation_disabled')
  })

  it('no impersonation cookie', async () => {
    await refused(await check('GET', cookies({ imp: null })), 'impersonation_cookie_missing')
    await refused(await app.inject({ url: URL_ }), 'impersonation_cookie_missing')
  })

  it('a cookie that maps to no grant: unknown, stopped, expired', async () => {
    await refused(await check('GET', cookies({ imp: 'made-up' })), 'impersonation_grant_invalid')
    await impersonationStore.endForSession('sess-support')
    await refused(await check(), 'impersonation_grant_invalid')
    const short = await impersonationStore.start({ adminId: SUPPORT, adminEmail: 'support@example.com', adminSessionId: 'sess-support', targetId: BOB, targetEmail: 'bob@example.com', targetName: 'Bob', reason: 'expired' }, 600, Date.now() - 601_000)
    await refused(await check('GET', cookies({ imp: short.token })), 'impersonation_grant_invalid')
  })

  it('the impersonation cookie alone, without the administrator\'s session cookie', async () => {
    await refused(await check('GET', cookies({ session: null })), 'impersonation_admin_session_missing')
    expect(s.whoami).toEqual([])
  })

  it('a session cookie Kratos no longer accepts (signed out, revoked, expired)', async () => {
    delete s.sessions['cookie-support']
    await refused(await check(), 'impersonation_admin_session_invalid')
    expect(await grantLive()).toBe(true)
  })

  it('refuses as soon as the administrator signs out mid-way', async () => {
    expect((await check()).statusCode).toBe(200)
    delete s.sessions['cookie-support']
    settle()
    await refused(await check(), 'impersonation_admin_session_invalid')
  })

  it('somebody else\'s valid session beside a copied impersonation cookie', async () => {
    await refused(await check('GET', cookies({ session: 'cookie-other' })), 'impersonation_admin_session_mismatch')
  })

  it('the same administrator on another session than the one that started it', async () => {
    await refused(await check('GET', cookies({ session: 'cookie-support-2' })), 'impersonation_admin_session_mismatch')
  })

  it('the administrator\'s session below aal2', async () => {
    s.sessions['cookie-support'].aal = 'aal1'
    await refused(await check(), 'impersonation_admin_aal')
  })

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('a write: %s is impersonation_read_only', async (method) => {
    await refused(await check(method), 'impersonation_read_only')
    expect(await grantLive()).toBe(true)
  })

  it('audits a refused write, once per grant and host per minute', async () => {
    await check('POST')
    await check('DELETE')
    expect(v1()).toEqual(['impersonation.write_refused'])
    expect(s.audits[0]).toMatchObject({
      result: 'denied', target: `user:${BOB}`, actor: { id: SUPPORT },
      details: { host: 'payroll.dev.example.com', method: 'POST' },
    })
    await check('PUT', cookies(), 'invoices.dev.example.com')
    expect(v1()).toEqual(['impersonation.write_refused', 'impersonation.write_refused'])
  })

  it('a write is refused only to a caller who proved the session: no trail for a bare cookie', async () => {
    await refused(await check('POST', cookies({ session: null })), 'impersonation_admin_session_missing')
    expect(s.audits).toEqual([])
  })

  it('the administrator no longer holds users:impersonate: refused, and the grant is ended', async () => {
    expect((await check()).statusCode).toBe(200)
    s.permissions['support@example.com'] = ['users:read']
    settle()
    await refused(await check(), 'impersonation_permission_revoked')
    expect(await grantLive()).toBe(false)
    expect(v1()).toEqual(['impersonation.used', 'impersonation.stopped'])
    expect(s.audits[1]).toMatchObject({ details: { ended: 'impersonation_permission_revoked' } })
    await refused(await check(), 'impersonation_grant_invalid')
  })

  it('the user became a super admin: refused and ended (the group on the identity)', async () => {
    s.target = bob({ metadata_admin: { groups: ['super_admins'] } })
    await refused(await check(), 'impersonation_target_admin')
    expect(await grantLive()).toBe(false)
    expect(s.audits.at(-1)).toMatchObject({ v1Event: 'impersonation.stopped', details: { ended: 'impersonation_target_admin' } })
  })

  it('the user became a super admin: refused and ended (as the policy sees them)', async () => {
    s.groups['bob@example.com'] = ['super_admins']
    await refused(await check(), 'impersonation_target_admin')
    expect(await grantLive()).toBe(false)
  })

  it.each([
    ['deactivated', () => { s.target = bob({ state: 'inactive' }) }],
    ['deleted', () => { s.target = null }],
  ])('the user was %s: refused and ended', async (_label, change) => {
    change()
    await refused(await check(), 'impersonation_target_unavailable')
    expect(await grantLive()).toBe(false)
  })

  it('the policy cannot be asked: refused for now, the grant stays', async () => {
    s.opaDown = true
    await refused(await check(), 'impersonation_unverifiable')
    expect(await grantLive()).toBe(true)
    s.opaDown = false
    settle()
    expect((await check()).statusCode).toBe(200)
  })
})

describe('the impersonation cookie is a credential nowhere else', () => {
  it('alone, it signs nobody in to jinbe: 401, and Kratos is never shown it', async () => {
    const res = await app.inject({ url: '/api/admin/impersonation', headers: { cookie: `platform_impersonation=${token}` } })
    expect(res.statusCode).toBe(401)
    expect(res.json().code).toBe('authentication_required')
    expect(s.whoami).toEqual([])
  })

  it('beside the administrator\'s session, jinbe still sees the administrator', async () => {
    const res = await app.inject({ url: '/api/admin/impersonation', headers: { cookie: cookies() } })
    expect(res.statusCode).toBe(200)
    // Their own permission and their own session's grant: the caller is the administrator, not Bob.
    expect(res.json()).toMatchObject({ enabled: true, allowed: true, active: { target: { id: BOB } } })
    expect(s.whoami).toEqual(['ory_kratos_session=cookie-support'])
  })

  it('the check route is reachable without a session, and says nothing to an empty request', async () => {
    const res = await app.inject({ url: URL_ })
    expect(res.statusCode).toBe(401)
    expect(res.json()).toEqual({ error: 'Unauthorized', reason: 'impersonation_cookie_missing' })
  })
})
