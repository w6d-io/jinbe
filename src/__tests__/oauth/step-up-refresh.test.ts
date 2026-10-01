import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// "The assistant asks to refresh the second factor": a key or a signed-in assistant asks a link for
// ITSELF; its holder opens it, proves a second factor (< 2 min) and the credential's protected-actions
// proof is renewed — a Redis proof per (person, client) for a sign-in, step_up_at for a key. Only for
// a credential given protected actions, never with the administrator's switch off; single use.

const NOW = Date.now()
const ago = (ms: number) => new Date(NOW - ms)
const iso = (ms: number) => new Date(ms).toISOString()

const h = vi.hoisted(() => ({
  env: { DELEGATED_TOKENS_ENABLED: true, AUTH_DOMAIN: 'auth.example.com' } as Record<string, unknown>,
  config: {} as Record<string, string>,
  redis: new Map<string, { v: string; ttl?: number }>(),
  session: null as null | Record<string, unknown>,
  clients: new Map<string, Record<string, unknown>>(),
  sessions: [] as unknown[],
  patchClient: vi.fn(async () => ({})),
  forgetClient: vi.fn(),
  emit: vi.fn(async () => 'id'),
}))

vi.mock('../../config/index.js', async (orig) => {
  const real = (await orig()) as { env: object }
  Object.setPrototypeOf(h.env, real.env)
  return { ...real, env: h.env }
})
vi.mock('../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => h.config, setConfig: vi.fn() } }))
vi.mock('../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    get: async (k: string) => h.redis.get(k)?.v ?? null,
    set: async (k: string, v: string, _ex?: string, ttl?: number) => { h.redis.set(k, { v, ttl }); return 'OK' },
    del: async (k: string) => (h.redis.delete(k) ? 1 : 0),
    incr: async (k: string) => { const n = Number(h.redis.get(k)?.v ?? 0) + 1; h.redis.set(k, { v: String(n) }); return n },
    expire: async () => 1,
    ttl: async () => 321,
  }),
}))
vi.mock('../../services/hydra.service.js', async (orig) => {
  const real = (await orig()) as { HydraApiError: new (s: number, m: string) => Error }
  return {
    ...real,
    hydraService: {
      getClient: vi.fn(async (id: string) => {
        const c = h.clients.get(id)
        if (!c) throw new real.HydraApiError(404, 'Not Found')
        return c
      }),
    },
  }
})
vi.mock('../../services/hydra-flows.service.js', () => ({ hydraFlows: { listConsentSessions: vi.fn(async () => h.sessions), patchClient: h.patchClient } }))
vi.mock('../../services/kratos-session.service.js', async (orig) => ({
  ...((await orig()) as object),
  kratosSessionService: { validateSession: vi.fn(async () => ({ session: h.session })) },
}))
vi.mock('../../services/delegated-token.service.js', () => ({ delegatedTokenService: { forgetClient: h.forgetClient } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))

import { installRouteAccess } from '../../policy/route-access.js'
import { oauthProviderRoutes, stepUpRequestRoutes } from '../../oauth/routes.js'
import { resetMcpSettingsCache } from '../../mcp/settings.js'
import { laterProof, oauthProofKey } from '../../oauth/step-up-proof.js'

type Who = { kind?: 'oauth' | 'personal'; client?: string; actions?: boolean; session?: boolean }

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const raw = request.headers['x-who'] as string | undefined
    if (!raw) return
    const who = JSON.parse(raw) as Who
    request.userContext = (who.session
      ? { id: 'user-1', email: 'ann@acme.io', name: 'Ann', authVia: 'session' }
      : {
          id: 'user-1', email: 'ann@acme.io', name: 'Ann', authVia: 'delegated',
          delegation: who.kind === 'personal'
            ? { clientId: who.client ?? 'pk-1', scopes: [], kind: 'personal', via: 'auth-mcp', keyStepUpActions: who.actions ?? true }
            : { clientId: who.client ?? 'c-1', scopes: [], kind: 'oauth', via: 'auth-mcp', stepUpActions: who.actions ?? true },
        }) as never
  })
  await app.register(stepUpRequestRoutes, { prefix: '/api/me/mcp/step-up-requests' })
  await app.register(oauthProviderRoutes, { prefix: '/api/public/oauth2' })
  await app.ready()
})
afterAll(() => app.close())

const GRANT_END = NOW + 20 * 86_400_000
const grant = (ext: Record<string, unknown> = {}) => ({
  consent_request: { client: h.clients.get('c-1') },
  grant_scope: ['mcp', 'sites:apply'],
  session: { access_token: { kind: 'oauth', scope_mode: 'all', step_up_actions: true, second_factor_at: iso(NOW - 3 * 86_400_000), grant_expires_at: iso(GRANT_END), ...ext } },
})

beforeEach(() => {
  h.config = { mcp: JSON.stringify({ enabled: true }) }
  h.redis.clear()
  h.session = { sessionId: 's-1', identityId: 'user-1', email: 'ann@acme.io', aal: 'aal2', secondFactorAt: ago(30_000) }
  h.clients = new Map<string, Record<string, unknown>>([
    ['c-1', { client_id: 'c-1', client_name: 'Claude Code', metadata: { kind: 'mcp_oauth', bound_subject: 'user-1' } }],
    ['pk-1', { client_id: 'pk-1', client_name: 'laptop key', metadata: { kind: 'personal', subject: 'user-1', expires_at: iso(NOW + 10 * 86_400_000), step_up_at: iso(NOW - 40 * 86_400_000), step_up_actions: true } }],
  ])
  h.sessions = [grant()]
  h.patchClient.mockClear()
  h.forgetClient.mockClear()
  h.emit.mockClear()
  resetMcpSettingsCache()
})

const ask = (who: Who) => app.inject({ method: 'POST', url: '/api/me/mcp/step-up-requests', headers: { 'x-who': JSON.stringify(who) } })
const reqIdOf = (url: string) => new URL(url).searchParams.get('req')!
const cookie = 'ory_kratos_session=abc'
const show = (req: string) => app.inject({ method: 'GET', url: `/api/public/oauth2/step-up?req=${req}`, headers: { cookie } })
const complete = (req: string, headers: Record<string, string> = {}) =>
  app.inject({ method: 'POST', url: '/api/public/oauth2/step-up', headers: { cookie, origin: 'https://auth.example.com', 'content-type': 'application/json', ...headers }, payload: JSON.stringify({ req }) })

describe('POST /api/me/mcp/step-up-requests (the credential asks for itself)', () => {
  it('answers a single-use 10-minute link to login-ui, bound to the holder and the calling client', async () => {
    const res = await ask({ kind: 'oauth' })
    expect(res.statusCode).toBe(201)
    const { url, expiresAt } = res.json()
    expect(url).toMatch(/^https:\/\/auth\.example\.com\/oauth2\/step-up\?req=[A-Za-z0-9_-]{32}$/)
    expect(Date.parse(expiresAt) - Date.now()).toBeGreaterThan(9.9 * 60_000)
    const stored = h.redis.get(`jinbe:stepup-req:${reqIdOf(url)}`)!
    expect(JSON.parse(stored.v)).toMatchObject({ subject: 'user-1', clientId: 'c-1', kind: 'oauth' })
    expect(stored.ttl).toBe(600)
  })

  it('refuses a browser session (nothing to refresh), a credential given no protected actions, and the admin switch off', async () => {
    expect((await ask({ session: true })).json()).toMatchObject({ error: 'not_delegated' })
    const oauthOff = await ask({ kind: 'oauth', actions: false })
    expect(oauthOff.statusCode).toBe(409)
    expect(oauthOff.json()).toMatchObject({ error: 'protected_actions_not_allowed', message: expect.stringContaining('Reconnect') })
    expect((await ask({ kind: 'personal', actions: false })).json()).toMatchObject({ error: 'protected_actions_not_allowed' })
    h.config = { mcp: JSON.stringify({ enabled: true, oauth: { protectedActions: 'off' } }) }
    resetMcpSettingsCache()
    const off = await ask({ kind: 'oauth' })
    expect(off.statusCode).toBe(403)
    expect(off.json().error).toBe('protected_actions_off')
    expect([...h.redis.keys()].some((k) => k.startsWith('jinbe:stepup-req:'))).toBe(false)
  })

  it('brakes a looping assistant: 5 links per 10 minutes per credential, then 429 with Retry-After', async () => {
    for (let i = 0; i < 5; i++) expect((await ask({ kind: 'oauth' })).statusCode).toBe(201)
    const res = await ask({ kind: 'oauth' })
    expect(res.statusCode).toBe(429)
    expect(res.headers['retry-after']).toBe('321')
    expect((await ask({ kind: 'personal' })).statusCode).toBe(201)
  })
})

describe('the holder completes the link (login-ui)', () => {
  it('shows what it refreshes without consuming it', async () => {
    const req = reqIdOf((await ask({ kind: 'oauth' })).json().url)
    expect((await show(req)).json()).toMatchObject({ action: 'show', kind: 'oauth', client_id: 'c-1', client_name: 'Claude Code', hours: 12 })
    const key = reqIdOf((await ask({ kind: 'personal' })).json().url)
    expect((await show(key)).json()).toMatchObject({ kind: 'personal', hours: 720 })
    expect(h.redis.has(`jinbe:stepup-req:${req}`)).toBe(true)
  })

  it('a sign-in: records the proof per (person, client) until the grant ends, drops caches, audits; single use', async () => {
    const req = reqIdOf((await ask({ kind: 'oauth' })).json().url)
    const res = await complete(req)
    expect(res.statusCode).toBe(200)
    const at = ago(30_000).toISOString()
    expect(res.json()).toEqual({ action: 'done', kind: 'oauth', client_id: 'c-1', client_name: 'Claude Code', step_up_at: at, step_up_until: iso(NOW - 30_000 + 12 * 3600_000) })
    const proof = h.redis.get(oauthProofKey('user-1', 'c-1'))!
    expect(proof.v).toBe(at)
    expect(proof.ttl).toBeGreaterThan(19 * 86_400)
    expect(proof.ttl).toBeLessThanOrEqual(20 * 86_400 + 1)
    expect(h.forgetClient).toHaveBeenCalledWith('c-1')
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'mcp.step_up.refreshed', targetId: 'c-1', actor: expect.objectContaining({ id: 'user-1' }) }))
    expect((await complete(req)).json()).toMatchObject({ error: 'request_unknown' })
  })

  it('a personal key: rewrites its step_up_at (30 days from the new proof, never past the key)', async () => {
    const req = reqIdOf((await ask({ kind: 'personal' })).json().url)
    const res = await complete(req)
    expect(res.json()).toMatchObject({ action: 'done', kind: 'personal', client_id: 'pk-1', step_up_until: iso(NOW + 10 * 86_400_000) })
    expect(h.patchClient).toHaveBeenCalledWith('pk-1', [{ op: 'replace', path: '/metadata/step_up_at', value: ago(30_000).toISOString() }])
    expect(h.forgetClient).toHaveBeenCalledWith('pk-1')
  })

  it('a second factor older than 2 minutes: off to Kratos aal2 refresh, back to the link — nothing consumed', async () => {
    const req = reqIdOf((await ask({ kind: 'oauth' })).json().url)
    h.session = { ...h.session, secondFactorAt: ago(3 * 60_000) }
    const back = encodeURIComponent(`https://auth.example.com/oauth2/step-up?req=${req}`)
    expect((await complete(req)).json()).toEqual({ action: 'redirect', to: `https://auth.example.com/self-service/login/browser?aal=aal2&refresh=true&return_to=${back}` })
    expect(h.redis.has(`jinbe:stepup-req:${req}`)).toBe(true)
    expect(h.redis.has(oauthProofKey('user-1', 'c-1'))).toBe(false)
  })

  it('never for another account, without a session, from another origin, or for an unknown link', async () => {
    const req = reqIdOf((await ask({ kind: 'oauth' })).json().url)
    h.session = { ...h.session, identityId: 'user-2' }
    expect((await complete(req)).json()).toMatchObject({ error: 'wrong_account' })
    h.session = null
    expect((await complete(req)).statusCode).toBe(401)
    expect((await complete(req, { origin: 'https://evil.example' })).json()).toMatchObject({ error: 'bad_origin' })
    expect((await complete('A'.repeat(32))).json()).toMatchObject({ error: 'request_unknown' })
    expect(h.redis.has(oauthProofKey('user-1', 'c-1'))).toBe(false)
  })

  it('re-checks the credential at completion: consent without protected actions, grant gone, admin switch off', async () => {
    let req = reqIdOf((await ask({ kind: 'oauth' })).json().url)
    h.sessions = [grant({ step_up_actions: false })]
    expect((await complete(req)).json()).toMatchObject({ error: 'protected_actions_not_allowed' })
    h.sessions = []
    expect((await complete(req)).json()).toMatchObject({ error: 'credential_gone' })
    h.sessions = [grant()]
    req = reqIdOf((await ask({ kind: 'oauth' })).json().url)
    h.config = { mcp: JSON.stringify({ enabled: true, oauth: { protectedActions: 'off' } }) }
    resetMcpSettingsCache()
    expect((await complete(req)).json()).toMatchObject({ error: 'protected_actions_off' })
    expect(h.redis.has(oauthProofKey('user-1', 'c-1'))).toBe(false)
  })
})

describe('laterProof', () => {
  it('takes the newer proof, ignoring an absent or garbled one', () => {
    expect(laterProof('2026-10-01T00:00:00Z', '2026-10-01T01:00:00Z')).toBe('2026-10-01T01:00:00Z')
    expect(laterProof('2026-10-01T02:00:00Z', '2026-10-01T01:00:00Z')).toBe('2026-10-01T02:00:00Z')
    expect(laterProof(undefined, '2026-10-01T01:00:00Z')).toBe('2026-10-01T01:00:00Z')
    expect(laterProof('2026-10-01T02:00:00Z', 'nope')).toBe('2026-10-01T02:00:00Z')
    expect(laterProof(null, null)).toBeUndefined()
  })
})
