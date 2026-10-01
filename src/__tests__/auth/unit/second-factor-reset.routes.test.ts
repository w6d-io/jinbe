import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { ROLES } from '../../../policy/roles.js'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance } from 'fastify'

// Removing somebody's two-step sign-in, called DIRECTLY at jinbe: the permission, the caller's own
// recent second factor, never oneself, never a stronger account — and the Kratos admin calls it
// makes, against a stand-in for Kratos' admin API.

const USER = '11111111-1111-1111-1111-111111111111'
const GHOST = '99999999-9999-9999-9999-999999999999'
const KRATOS = 'http://kratos-admin:4434'

const s = vi.hoisted(() => ({
  rights: {} as Record<string, string[]>,
  credentials: {} as Record<string, unknown>,
  required: true as boolean | 'down',
  deleteFails: null as string | null,
  kratos: [] as Array<{ method: string; url: string }>,
  audits: [] as Array<Record<string, unknown>>,
}))

vi.mock('../../../config/env.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../config/env.js')>()
  const over: Record<string, string> = { OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', KRATOS_ADMIN_URL: 'http://kratos-admin:4434' }
  return { ...real, env: new Proxy(real.env, { get: (t, k) => (k in over ? over[k as string] : t[k as keyof typeof t]) }) }
})
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn(async (e: Record<string, unknown>) => { s.audits.push(e); return 'id' }) },
}))
vi.mock('../../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { userManagementRoutes } from '../../../routes/user-management.routes.js'
import { clearAuthzCache } from '../../../authz/opa.js'

const TOTP = { type: 'totp', config: { totp_url: 'otpauth://totp/x' } }
const CODES = { type: 'lookup_secret', config: { recovery_codes: [{ code: 'a' }] } }
const KEYS = { type: 'webauthn', config: { user_handle: 'h', credentials: [{ id: 'k1', is_passwordless: false }, { id: 'pk', is_passwordless: true }] } }
const PASSKEY_ONLY = { type: 'webauthn', config: { user_handle: 'h', credentials: [{ id: 'pk', is_passwordless: true }] } }

let app: FastifyInstance
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.startsWith('http://opal-client:8181/v1/data/rbac/user_info')) {
      const { input: q } = JSON.parse(init!.body as string) as { input: { email: string } }
      return Response.json({ result: { email: q.email, groups: [], roles: [], permissions: s.rights[q.email.split('@')[0]] ?? [] } })
    }
    if (url.startsWith('http://opal-client:8181/v1/data/rbac/second_factor_required')) {
      if (s.required === 'down') throw new TypeError('fetch failed')
      return Response.json({ result: s.required })
    }
    if (url.startsWith(KRATOS)) {
      s.kratos.push({ method, url: url.slice(KRATOS.length) })
      const path = new URL(url).pathname
      if (!path.startsWith(`/admin/identities/${USER}`)) return Response.json({ error: { code: 404 } }, { status: 404 })
      const cred = path.match(/\/credentials\/(\w+)$/)?.[1]
      if (method === 'DELETE' && cred) {
        if (cred === s.deleteFails) return Response.json({ error: { code: 500 } }, { status: 500 })
        if (!(cred in s.credentials)) return Response.json({ error: { code: 404 } }, { status: 404 })
        delete s.credentials[cred]
        return new Response(null, { status: 204 })
      }
      if (method === 'DELETE' && path.endsWith('/sessions')) return new Response(null, { status: 204 })
      return Response.json({ id: USER, schema_id: 'default', state: 'active', traits: { email: 'bob@example.com', name: 'Bob' }, credentials: s.credentials })
    }
    throw new Error(`unexpected fetch ${method} ${url}`)
  }))
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    const who = request.headers['x-test-user'] as string | undefined
    const proven = request.headers['x-test-proven'] as string | undefined
    if (who) {
      request.userContext = {
        id: who === 'bob' ? USER : who,
        email: `${who}@example.com`,
        name: who,
        sessionId: `sess-${who}`,
        aal: proven ? 'aal2' : 'aal1',
        secondFactorAt: proven ? new Date(Date.now() - Number(proven) * 60_000) : null,
        authVia: 'session',
      } as never
    }
  })
  await app.register(async (api) => {
    await api.register(userManagementRoutes, { prefix: '/admin' })
  }, { prefix: '/api' })
  await app.ready()
})
afterAll(async () => {
  vi.unstubAllGlobals()
  await app.close()
})
beforeEach(() => {
  s.rights = {
    admin: [...ROLES.security.permissions],
    support: ['sessions:read', 'sessions:revoke', 'users:read', 'users:recovery', 'users:send_login_link'],
    star: [...ROLES.super_admin.permissions],
    bob: ['clusters:list', 'databases:read'],
  }
  s.credentials = { totp: TOTP, lookup_secret: CODES, webauthn: KEYS }
  s.required = true
  s.deleteFails = null
  s.kratos = []
  s.audits = []
  clearAuthzCache()
})

const reset = (payload: unknown = { reason: 'Lost their phone' }, who = 'admin', proven: string | null = '2', id = USER) =>
  app.inject({
    method: 'POST',
    url: `/api/admin/users/${id}/second-factors/reset`,
    headers: { 'x-test-user': who, ...(proven ? { 'x-test-proven': proven } : {}) },
    payload: payload as never,
  })

describe('GET /users/:id/second-factors', () => {
  const get = (who = 'support', id = USER) =>
    app.inject({ url: `/api/admin/users/${id}/second-factors`, headers: { 'x-test-user': who } })

  it('lists the enrolled second factors and whether the role requires one', async () => {
    const res = await get()
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ methods: ['totp', 'webauthn', 'lookup_secret'], required: true })
    // Kratos hides credential configs unless asked for each type.
    expect(s.kratos[0].url).toBe(`/admin/identities/${USER}?include_credential=totp&include_credential=webauthn&include_credential=lookup_secret`)
  })

  it('a passkey is a first factor: not listed', async () => {
    s.credentials = { webauthn: PASSKEY_ONLY }
    expect((await get()).json().methods).toEqual([])
  })

  it('required is null when the policy cannot say', async () => {
    s.required = 'down'
    expect((await get()).json().required).toBeNull()
  })

  it('404 for an unknown user; 403 without users:read', async () => {
    expect((await get('support', GHOST)).statusCode).toBe(404)
    expect((await get('nobody')).statusCode).toBe(403)
  })
})

describe('POST /users/:id/second-factors/reset', () => {
  it('removes each enrolled factor through the Kratos admin API, then ends the sessions', async () => {
    const res = await reset()
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ removed: ['totp', 'webauthn', 'lookup_secret'], sessionsRevoked: true })
    expect(s.kratos.filter((c) => c.method === 'DELETE').map((c) => c.url)).toEqual([
      `/admin/identities/${USER}/credentials/totp`,
      `/admin/identities/${USER}/credentials/webauthn`,
      `/admin/identities/${USER}/credentials/lookup_secret`,
      `/admin/identities/${USER}/sessions`,
    ])
  })

  it('removes only what is enrolled, and leaves sessions alone when asked', async () => {
    s.credentials = { totp: TOTP, webauthn: PASSKEY_ONLY }
    const res = await reset({ reason: 'Lost phone', revokeSessions: false })
    expect(res.json()).toEqual({ removed: ['totp'], sessionsRevoked: false })
    expect(s.kratos.filter((c) => c.method === 'DELETE').map((c) => c.url)).toEqual([`/admin/identities/${USER}/credentials/totp`])
  })

  it('records a high-severity audit event: actor, target, reason, factors — and no address of the target', async () => {
    await reset()
    expect(s.audits).toHaveLength(1)
    const e = s.audits[0]
    expect(e).toMatchObject({
      v1Event: 'user.second_factor_reset', severity: 'high', result: 'applied', targetId: USER, reason: 'Lost their phone',
      details: { reason: 'Lost their phone', factors: ['totp', 'webauthn', 'lookup_secret'], sessionsRevoked: true },
    })
    expect((e.actor as Record<string, unknown>).id).toBe('admin')
    expect(JSON.stringify(e)).not.toContain('bob@example.com')
  })

  it('a Kratos failure part-way answers 502 and audits what was removed before it', async () => {
    s.deleteFails = 'webauthn'
    const res = await reset()
    expect(res.statusCode).toBe(502)
    expect(res.json()).toMatchObject({ error: 'reset_incomplete', removed: ['totp'] })
    expect(s.audits[0]).toMatchObject({ result: 'failed', details: { factors: ['totp'], sessionsRevoked: false } })
  })

  it('409 when there is nothing to remove, without touching Kratos', async () => {
    s.credentials = {}
    const res = await reset()
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toBe('no_second_factor')
    expect(s.kratos.some((c) => c.method === 'DELETE')).toBe(false)
    expect(s.audits).toHaveLength(0)
  })

  it('404 for an unknown user', async () => {
    expect((await reset(undefined, 'admin', '2', GHOST)).statusCode).toBe(404)
  })
})

describe('who may', () => {
  it('needs users:reset_second_factor — the support role is refused', async () => {
    const res = await reset(undefined, 'support')
    expect(res.statusCode).toBe(403)
    expect(res.json().message).toContain('users:reset_second_factor')
    expect(s.kratos).toHaveLength(0)
  })

  it('anonymous → 401', async () => {
    expect((await app.inject({ method: 'POST', url: `/api/admin/users/${USER}/second-factors/reset`, payload: { reason: 'x' } })).statusCode).toBe(401)
  })

  it('needs the caller\'s own second factor proven within 15 minutes', async () => {
    const none = await reset(undefined, 'admin', null)
    expect(none.statusCode).toBe(422)
    expect(none.json().error).toBe('reauth_required')
    expect((await reset(undefined, 'admin', '20')).statusCode).toBe(422)
    expect(s.kratos).toHaveLength(0)
  })

  it('refuses removing your own factors through this path', async () => {
    s.rights.bob = [...ROLES.security.permissions]
    const res = await reset(undefined, 'bob')
    expect(res.statusCode).toBe(403)
    expect(res.json().error).toBe('own_second_factor')
    expect(s.kratos).toHaveLength(0)
  })

  it('refuses an account holding administrative rights the caller does not', async () => {
    s.rights.bob = [...ROLES.super_admin.permissions]
    const res = await reset()
    expect(res.statusCode).toBe(403)
    expect(res.json().error).toBe('outranked')
    expect(s.kratos.some((c) => c.method === 'DELETE')).toBe(false)
    // A super admin may.
    expect((await reset(undefined, 'star')).statusCode).toBe(200)
  })

  it('an administrator may reset another administrator', async () => {
    s.rights.bob = [...ROLES.security.permissions]
    expect((await reset()).statusCode).toBe(200)
  })

  it('a reason is mandatory', async () => {
    expect((await reset({})).statusCode).toBe(400)
    expect((await reset({ reason: '' })).statusCode).toBe(400)
    expect((await reset({ reason: '   ' })).statusCode).toBe(400)
    expect(s.kratos).toHaveLength(0)
  })
})
