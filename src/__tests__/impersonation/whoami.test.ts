import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import { installRouteAccess, open } from '../../policy/route-access.js'
import { ROLES } from '../../policy/roles.js'

// The auth host's /sessions/whoami while the browser carries the impersonation cookie: a site's
// page is told the impersonated user; everybody else — the console, the login UI, a request without
// an Origin, anything the check refuses — gets Kratos' own answer, relayed unchanged.

const SUPPORT = '10000000-0000-4000-8000-000000000001'
const OTHER = '10000000-0000-4000-8000-000000000002'
const BOB = '20000000-0000-4000-8000-000000000001'
const KRATOS_PUBLIC = 'http://kratos-public:4433'
const URL_ = '/api/public/impersonation/whoami'
const SITE = 'https://payroll.dev.example.com'

type Session = { id: string; identity: string; email: string }

const s = vi.hoisted(() => ({
  // Read when the services are constructed, so set before any import.
  env: {
    OPA_URL: 'http://opal-client:8181', OPA_TOKEN: 'opa-secret', KRATOS_ADMIN_URL: 'http://kratos-admin:4434', KRATOS_PUBLIC_URL: 'http://kratos-public:4433',
    AUTH_DOMAIN: 'auth.dev.example.com', APP_DOMAIN: 'kuma.dev.example.com', API_DOMAIN: 'api.dev.example.com', LOGIN_UI_URL: 'https://login.dev.example.com/login',
  } as Record<string, unknown>,
  sessions: {} as Record<string, Session>,
  kratosDown: false,
  sitesDown: false,
  records: [] as Array<Record<string, unknown>>,
  versions: {} as Record<string, unknown>,
  redis: new Map<string, { v: string; ttl?: number }>(),
  audits: [] as Array<Record<string, unknown>>,
  whoami: [] as Array<{ url: string; headers: Record<string, string> }>,
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
vi.mock('../../sites/config.js', () => ({ sitesConfig: () => ({ SITES_COOKIE_DOMAIN: '.dev.example.com', SITES_RESERVED_HOSTS: ['grafana.dev.example.com'] }) }))
vi.mock('../../sites/repository.js', () => ({
  sitesRepository: {
    list: async () => { if (s.sitesDown) throw new Error('redis down'); return s.records },
    version: async (name: string, v: number) => s.versions[`${name}@${v}`] ?? null,
  },
}))
vi.mock('../../server.js', () => ({ notificationService: { emit: vi.fn() } }))

import { impersonationWhoamiRoutes } from '../../impersonation/whoami.js'
import { resetImpersonationCheck } from '../../impersonation/check.js'
import { resetSiteOrigins } from '../../impersonation/site-origins.js'
import { impersonationStore } from '../../impersonation/store.js'
import { extractIdentity } from '../../middleware/identity-extractor.js'
import { requireAuth } from '../../middleware/require-auth.js'
import { clearSessionCache } from '../../services/kratos-session.service.js'
import { clearAuthzCache } from '../../authz/opa.js'
import corsPlugin from '../../plugins/cors.js'

const METHODS = [
  { method: 'password', aal: 'aal1', completed_at: '2026-11-10T09:00:00Z' },
  { method: 'totp', aal: 'aal2', completed_at: '2026-11-10T09:00:30Z' },
]
const kratosSession = (found: Session) => ({
  id: found.id, active: true, expires_at: '2099-01-01T00:00:00Z', authenticated_at: '2026-11-10T09:00:00Z',
  authenticator_assurance_level: 'aal2', authentication_methods: METHODS,
  identity: { id: found.identity, schema_id: 'default', state: 'active', traits: { email: found.email, name: 'Staff' }, created_at: '', updated_at: '' },
})
const UNAUTHORIZED = { error: { code: 401, status: 'Unauthorized', reason: 'No valid session credentials found in the request.', message: 'The request could not be authorized' } }
const record = (name: string, host: string, over: Record<string, unknown> = {}) => ({ site: { name, address: { host }, state: 'active' }, version: 1, applied: { version: 1 }, ...over })

async function build(cors = false): Promise<FastifyInstance> {
  const app = Fastify()
  if (cors) await app.register(corsPlugin)
  installRouteAccess(app)
  app.addHook('onRequest', extractIdentity)
  app.addHook('onRequest', requireAuth)
  await app.register(async (api) => {
    await api.register(impersonationWhoamiRoutes, { prefix: '/public/impersonation' })
    api.get('/health', open('public'), async () => ({ ok: true }))
  }, { prefix: '/api' })
  await app.ready()
  return app
}

let app: FastifyInstance
beforeAll(async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.startsWith(`${KRATOS_PUBLIC}/sessions/whoami`)) {
      if (s.kratosDown) throw new TypeError('fetch failed')
      const headers = (init?.headers ?? {}) as Record<string, string>
      s.whoami.push({ url, headers })
      const found = s.sessions[String(headers.Cookie ?? '').replace(/^ory_kratos_session=/, '')] ?? s.sessions[`token:${headers['X-Session-Token'] ?? ''}`]
      if (!found) return new Response(JSON.stringify(UNAUTHORIZED), { status: 401, headers: { 'content-type': 'application/json' } })
      return new Response(JSON.stringify(kratosSession(found)), { status: 200, headers: { 'content-type': 'application/json; charset=utf-8', 'x-kratos-authenticated-identity-id': found.identity, 'set-cookie': 'csrf=never-relayed' } })
    }
    if (url.startsWith('http://opal-client:8181/v1/data/rbac/user_info')) {
      const { input: q } = JSON.parse(init!.body as string) as { input: { email: string } }
      return Response.json({ result: { email: q.email, groups: [], roles: [], permissions: q.email === 'support@example.com' ? [...ROLES.support.permissions] : [] } })
    }
    if (url === `http://kratos-admin:4434/admin/identities/${BOB}`) {
      return Response.json({ id: BOB, schema_id: 'default', state: 'active', traits: { email: 'bob@example.com', name: 'Bob' }, metadata_public: null, metadata_admin: { groups: ['customers'] }, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' })
    }
    throw new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url}`)
  }))
  app = await build()
})
afterAll(async () => {
  vi.unstubAllGlobals()
  await app.close()
})

let token = ''
beforeEach(async () => {
  Object.assign(s.env, { IMPERSONATION_ENABLED: true, IMPERSONATION_COOKIE_NAME: 'platform_impersonation', NODE_ENV: 'test', DISABLE_CORS: 'true' })
  s.sessions = {
    'cookie-support': { id: 'sess-support', identity: SUPPORT, email: 'support@example.com' },
    'cookie-other': { id: 'sess-other', identity: OTHER, email: 'other@example.com' },
  }
  s.kratosDown = false
  s.sitesDown = false
  s.records = [
    record('payroll', 'payroll.dev.example.com'),
    record('unpublished', 'draft.dev.example.com', { applied: undefined }),
    record('paused', 'paused.dev.example.com', { site: { name: 'paused', address: { host: 'paused.dev.example.com' }, state: 'paused' } }),
    // Saved on a new host, still applied on the old one.
    record('moving', 'new.dev.example.com', { version: 2 }),
    // Records that would claim platform hosts.
    record('rogue', 'kuma.dev.example.com'),
    record('kuma', 'console.dev.example.com'),
  ]
  s.versions = { 'moving@1': { site: { address: { host: 'old.dev.example.com' } } } }
  s.redis.clear()
  s.audits = []
  s.whoami = []
  clearSessionCache()
  clearAuthzCache()
  resetImpersonationCheck()
  resetSiteOrigins()
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

const whoami = (origin: string | null = SITE, cookie: string = cookies(), on: FastifyInstance = app, extra: Record<string, string> = {}) =>
  on.inject({ url: URL_, headers: { cookie, ...(origin ? { origin } : {}), ...extra } })

/** Kratos' own answer for the administrator, relayed as it is. */
const isAdmin = (res: Awaited<ReturnType<typeof whoami>>) => {
  expect(res.statusCode).toBe(200)
  expect(res.json()).toEqual(kratosSession(s.sessions['cookie-support']))
  expect(res.body).not.toContain('bob@example.com')
}

describe('a site origin, while the impersonation is valid', () => {
  it('is told the impersonated user: the body the gateway check produces', async () => {
    const res = await whoami()
    expect(res.statusCode).toBe(200)
    const grant = (await impersonationStore.byToken(token))!
    expect(res.json()).toEqual({
      id: `impersonation:${grant.id}`,
      active: true,
      expires_at: grant.expiresAt,
      authenticated_at: grant.startedAt,
      authenticator_assurance_level: 'aal2',
      authentication_methods: METHODS,
      identity: { id: BOB, schema_id: 'default', state: 'active', traits: { email: 'bob@example.com', name: 'Bob' }, metadata_public: null, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' },
      impersonator: { id: SUPPORT, email: 'support@example.com', session_id: 'sess-support' },
    })
    expect(res.headers['x-kratos-authenticated-identity-id']).toBe(BOB)
  })

  it('names the site in the sampled trail, once', async () => {
    await whoami()
    await whoami()
    expect(s.audits.map((a) => a.v1Event)).toEqual(['impersonation.used'])
    expect(s.audits[0]).toMatchObject({ targetId: BOB, actor: { id: SUPPORT }, details: { host: 'payroll.dev.example.com' } })
  })

  it('goes by the host a site is APPLIED on, not the one it was saved on', async () => {
    expect((await whoami('https://old.dev.example.com')).json().identity.id).toBe(BOB)
    isAdmin(await whoami('https://new.dev.example.com'))
  })

  it('reads the published sites once for a burst of calls', async () => {
    const list = vi.fn(async () => s.records)
    const { sitesRepository } = await import('../../sites/repository.js')
    const real = sitesRepository.list
    sitesRepository.list = list as never
    for (let i = 0; i < 5; i++) await whoami()
    sitesRepository.list = real
    expect(list).toHaveBeenCalledTimes(1)
  })
})

describe('everybody else gets Kratos\' own answer', () => {
  it.each([
    ['no Origin (a navigation, a server-side caller)', null],
    ['the console', 'https://kuma.dev.example.com'],
    ['the auth host', 'https://auth.dev.example.com'],
    ['the API host', 'https://api.dev.example.com'],
    ['the login UI', 'https://login.dev.example.com'],
    ['a reserved platform host', 'https://grafana.dev.example.com'],
    ['a system site\'s host', 'https://console.dev.example.com'],
    ['an unknown origin', 'https://evil.example.net'],
    ['a site that was never published', 'https://draft.dev.example.com'],
    ['a paused site', 'https://paused.dev.example.com'],
    ['a site host over plain http', 'http://payroll.dev.example.com'],
    ['a lookalike of a site host', 'https://payroll.dev.example.com.evil.example.net'],
    ['the opaque origin', 'null'],
    ['something that is not an origin', 'payroll.dev.example.com'],
  ])('%s: the administrator, 200 relayed', async (_label, origin) => {
    isAdmin(await whoami(origin))
    expect(s.audits).toEqual([])
  })

  it('relays Kratos\' 401 unchanged when the session is not valid', async () => {
    for (const origin of [null, 'https://kuma.dev.example.com', SITE]) {
      const res = await whoami(origin, cookies({ session: 'signed-out' }))
      expect(res.statusCode).toBe(401)
      expect(res.json()).toEqual(UNAUTHORIZED)
    }
    const none = await app.inject({ url: URL_ })
    expect(none.statusCode).toBe(401)
    expect(none.json()).toEqual(UNAUTHORIZED)
  })

  it.each([
    ['a cookie that maps to no grant', () => cookies({ imp: 'made-up' }), 'cookie-support'],
    ['somebody else\'s session beside the impersonation cookie', () => cookies({ session: 'cookie-other' }), 'cookie-other'],
  ])('the check refused (%s): Kratos\' answer for the session presented', async (_label, cookie, session) => {
    const res = await whoami(SITE, cookie())
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual(kratosSession(s.sessions[session]))
  })

  it('a stopped grant: back to the administrator at once', async () => {
    expect((await whoami()).json().identity.id).toBe(BOB)
    await impersonationStore.endForSession('sess-support')
    isAdmin(await whoami())
  })

  it('the feature off: Kratos, without looking at sites or grants', async () => {
    s.env.IMPERSONATION_ENABLED = false
    s.sitesDown = true
    isAdmin(await whoami())
  })

  it('the published sites cannot be read: Kratos, never a guess', async () => {
    s.sitesDown = true
    isAdmin(await whoami())
  })

  it('hands Kratos its own cookies and tokens only, fresh every time, with the query as asked', async () => {
    await whoami(null)
    await whoami(null, 'theme=dark', app, { 'x-session-token': 'tok', authorization: 'Bearer abc' })
    await app.inject({ url: `${URL_}?tokenize_as=jwt`, headers: { cookie: cookies() } })
    expect(s.whoami).toEqual([
      // The server's own identity extraction (kept a few seconds for reads), then the relay — which
      // asks again on every request.
      { url: `${KRATOS_PUBLIC}/sessions/whoami`, headers: { Cookie: 'ory_kratos_session=cookie-support' } },
      { url: `${KRATOS_PUBLIC}/sessions/whoami`, headers: { Cookie: 'ory_kratos_session=cookie-support' } },
      { url: `${KRATOS_PUBLIC}/sessions/whoami`, headers: { 'X-Session-Token': 'tok', Authorization: 'Bearer abc' } },
      { url: `${KRATOS_PUBLIC}/sessions/whoami?tokenize_as=jwt`, headers: { Cookie: 'ory_kratos_session=cookie-support' } },
    ])
  })

  it('answers a session token as Kratos does', async () => {
    s.sessions['token:tok'] = s.sessions['cookie-support']
    const res = await whoami(null, 'theme=dark', app, { 'x-session-token': 'tok' })
    expect(res.statusCode).toBe(200)
    expect(res.headers['x-kratos-authenticated-identity-id']).toBe(SUPPORT)
  })
})

describe('Kratos down', () => {
  it('503 with a small error, for a caller Kratos would have answered', async () => {
    s.kratosDown = true
    const res = await whoami(null)
    expect(res.statusCode).toBe(503)
    expect(res.json()).toEqual({ error: 'identity_service_unavailable', message: expect.any(String) })
    expect(res.headers['cache-control']).toBe('no-store')
  })

  it('never falls back to the impersonated answer for a non-site origin', async () => {
    s.kratosDown = true
    const res = await whoami('https://kuma.dev.example.com')
    expect(res.statusCode).toBe(503)
    expect(res.body).not.toContain('bob@example.com')
  })
})

describe('the response', () => {
  it.each([
    ['impersonated', SITE],
    ['relayed', 'https://kuma.dev.example.com'],
    ['relayed, no Origin', null],
  ])('%s: never cacheable, varies by Origin and Cookie, sets no cookie', async (_label, origin) => {
    const res = await whoami(origin)
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.headers.vary).toBe('Origin, Cookie')
    expect(res.headers['set-cookie']).toBeUndefined()
    expect(res.headers['content-type']).toContain('application/json')
  })

  it('a relayed 401 carries the same headers', async () => {
    const res = await app.inject({ url: URL_ })
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.headers.vary).toBe('Origin, Cookie')
  })

  it('writes nothing: no grant is created, changed or ended by asking', async () => {
    const before = JSON.stringify([...s.redis].filter(([k]) => !k.startsWith('jinbe:impersonation:seen:')))
    await whoami()
    await whoami('https://kuma.dev.example.com')
    await whoami(SITE, cookies({ session: 'cookie-other' }))
    expect(JSON.stringify([...s.redis].filter(([k]) => !k.startsWith('jinbe:impersonation:seen:')))).toBe(before)
  })
})

describe('CORS is the edge\'s: this route never adds its own', () => {
  const cors = (res: Awaited<ReturnType<typeof whoami>>) => Object.keys(res.headers).filter((h) => h.startsWith('access-control-'))

  it('as deployed (DISABLE_CORS=true): no Access-Control header at all', async () => {
    const deployed = await build(true)
    expect(cors(await whoami(SITE, cookies(), deployed))).toEqual([])
    await deployed.close()
  })

  it('with the CORS plugin on (production allowlist): the plugin\'s headers are removed here, kept elsewhere', async () => {
    Object.assign(s.env, { DISABLE_CORS: 'false', NODE_ENV: 'production', CORS_ORIGIN: `${SITE},https://kuma.dev.example.com` })
    const withCors = await build(true)
    for (const origin of [SITE, 'https://kuma.dev.example.com']) {
      const res = await whoami(origin, cookies(), withCors)
      expect(res.statusCode).toBe(200)
      expect(cors(res)).toEqual([])
      expect(res.headers.vary).toBe('Origin, Cookie')
    }
    const other = await withCors.inject({ url: '/api/health', headers: { origin: SITE } })
    expect(other.headers['access-control-allow-origin']).toBe(SITE)
    await withCors.close()
  })

  it('with the development CORS hooks: removed here too', async () => {
    Object.assign(s.env, { DISABLE_CORS: 'false', NODE_ENV: 'development' })
    const dev = await build(true)
    expect(cors(await whoami('https://kuma.dev.example.com', cookies(), dev))).toEqual([])
    expect((await dev.inject({ url: '/api/health', headers: { origin: SITE } })).headers['access-control-allow-origin']).toBe(SITE)
    await dev.close()
  })
})
