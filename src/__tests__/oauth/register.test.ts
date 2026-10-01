import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// MCP browser sign-in, the authorization-server side jinbe serves on the Hydra host: RFC 8414 metadata
// and the locked-down client registration (owner decisions 2026-09-30: loopback callbacks only, DCR
// through jinbe, no Hydra native DCR, no pre-registered clients).

const h = vi.hoisted(() => ({
  env: {
    MCP_OAUTH_ISSUER: 'https://hydra.example.com/',
    DELEGATED_TOKENS_ENABLED: true,
    DELEGATED_TOKEN_AUDIENCE: 'https://mcp.example.com/mcp',
    HYDRA_PUBLIC_URL: 'http://hydra-public:4444',
    MCP_OAUTH_DCR_RATE: '10/h/ip,200/d',
    TRUST_ENVOY_EXTERNAL_ADDRESS: false,
  } as Record<string, unknown>,
  config: {} as Record<string, string>,
  counters: new Map<string, number>(),
  redisDown: false,
  createClient: vi.fn(),
  listAllClients: vi.fn(),
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
    incr: async (k: string) => {
      if (h.redisDown) throw new Error('ECONNREFUSED')
      const n = (h.counters.get(k) ?? 0) + 1
      h.counters.set(k, n)
      return n
    },
    expire: async () => 1,
    ttl: async () => 1234,
  }),
}))
vi.mock('../../services/hydra-flows.service.js', () => ({ hydraFlows: { createClient: h.createClient } }))
vi.mock('../../services/hydra.service.js', async (orig) => ({ ...((await orig()) as object), hydraService: { listAllClients: h.listAllClients } }))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))
vi.mock('../../services/platform-scopes.js', () => ({ delegableJinbePermissions: () => new Map([['users:read', {}], ['sites:apply', {}]]) }))

import { installRouteAccess } from '../../policy/route-access.js'
import { oauthAuthorizationServerRoutes } from '../../oauth/routes.js'
import { resetMcpSettingsCache } from '../../mcp/settings.js'
import { resetOAuthMetadataCache } from '../../oauth/metadata.js'
import { dcrRate, ipNet, loopbackRedirect, validateRegistration } from '../../oauth/register.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  await app.register(oauthAuthorizationServerRoutes)
  await app.ready()
})
afterAll(() => app.close())

beforeEach(() => {
  h.config = { mcp: JSON.stringify({ enabled: true }) }
  h.counters.clear()
  h.redisDown = false
  h.env.MCP_OAUTH_ISSUER = 'https://hydra.example.com/'
  h.env.DELEGATED_TOKENS_ENABLED = true
  h.createClient.mockReset().mockImplementation(async (body: Record<string, unknown>) => ({ ...body, client_id: 'c-1', created_at: '2026-09-30T12:00:00Z' }))
  h.listAllClients.mockReset().mockResolvedValue([])
  h.emit.mockClear()
  resetMcpSettingsCache()
  resetOAuthMetadataCache()
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('ECONNREFUSED') }))
})

const CC = { client_name: 'Claude Code (example)', redirect_uris: ['http://localhost:53682/callback'], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none', scope: 'mcp offline_access users:read sites:apply' }
const register = (body: unknown, headers: Record<string, string> = {}) =>
  app.inject({ method: 'POST', url: '/oauth2/register', headers: { host: 'hydra.example.com', 'content-type': 'application/json', ...headers }, payload: JSON.stringify(body) })

describe('RFC 8414 metadata', () => {
  const meta = (host = 'hydra.example.com') => app.inject({ method: 'GET', url: '/.well-known/oauth-authorization-server', headers: { host } })

  it('names the issuer verbatim, S256 only, public clients, and the registration endpoint', async () => {
    const res = await meta()
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({
      issuer: 'https://hydra.example.com/',
      authorization_endpoint: 'https://hydra.example.com/oauth2/auth',
      token_endpoint: 'https://hydra.example.com/oauth2/token',
      revocation_endpoint: 'https://hydra.example.com/oauth2/revoke',
      jwks_uri: 'https://hydra.example.com/.well-known/jwks.json',
      registration_endpoint: 'https://hydra.example.com/oauth2/register',
      scopes_supported: ['mcp', 'offline_access', 'sites:apply', 'users:read'],
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      revocation_endpoint_auth_methods_supported: ['none'],
    })
  })

  it("takes Hydra's own endpoints when its discovery answers, but only on the issuer's origin", async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      issuer: 'https://hydra.example.com/', authorization_endpoint: 'https://hydra.example.com/oauth2/auth?x=1',
      token_endpoint: 'https://evil.example.org/token', code_challenge_methods_supported: ['plain', 'S256'],
    }), { status: 200 })))
    const body = (await meta()).json()
    expect(body.authorization_endpoint).toBe('https://hydra.example.com/oauth2/auth?x=1')
    expect(body.token_endpoint).toBe('https://hydra.example.com/oauth2/token')
    expect(body.code_challenge_methods_supported).toEqual(['S256'])
  })

  it('answers only on the Hydra host, and only with an issuer configured', async () => {
    expect((await meta('api.example.com')).statusCode).toBe(404)
    h.env.MCP_OAUTH_ISSUER = ''
    expect((await meta()).statusCode).toBe(404)
  })

  it('joins paths without doubling a slash when the issuer has none', async () => {
    h.env.MCP_OAUTH_ISSUER = 'https://hydra.example.com'
    const body = (await meta()).json()
    expect(body.issuer).toBe('https://hydra.example.com')
    expect(body.registration_endpoint).toBe('https://hydra.example.com/oauth2/register')
  })
})

describe('redirect URIs (loopback only)', () => {
  it.each([
    'http://localhost:53682/callback',
    'http://127.0.0.1:1024/cb',
    'http://[::1]:65535/',
  ])('accepts %s', (u) => expect(loopbackRedirect(u)).toBe(u))

  it.each([
    'https://localhost:53682/callback', // https is not loopback-only (D2: hosted callbacks later)
    'https://claude.ai/api/mcp/auth_callback',
    'http://localhost/callback', // no port
    'http://localhost:80/callback', // default port vanishes
    'http://localhost:1023/cb', // privileged
    'http://localhost:53682/cb?x=1',
    'http://localhost:53682/cb?',
    'http://localhost:53682/cb#frag',
    'http://user:pw@localhost:53682/cb',
    'http://localhost.evil.com:53682/cb',
    'http://127.0.0.2:53682/cb',
    'custom-scheme://callback',
    'http://localhost:53682/c b',
  ])('refuses %s', (u) => expect(loopbackRedirect(u)).toBeNull())
})

describe('validateRegistration', () => {
  it('keeps mcp, offline_access and resource:verb scopes, adds the two baseline ones, drops the rest', () => {
    const v = validateRegistration({ ...CC, scope: 'openid users:read * sites:* Users:Read profile' })
    expect(v).toEqual({ client_name: 'Claude Code (example)', redirect_uris: CC.redirect_uris, scopes: ['users:read', 'mcp', 'offline_access'] })
  })

  it('cleans and truncates the name, defaulting it', () => {
    expect(validateRegistration({ ...CC, client_name: '  Claude‮ Code\u0007  ' })).toMatchObject({ client_name: 'Claude Code' })
    expect(validateRegistration({ ...CC, client_name: 'x'.repeat(100) })).toMatchObject({ client_name: 'x'.repeat(64) })
    expect(validateRegistration({ redirect_uris: CC.redirect_uris })).toMatchObject({ client_name: 'MCP client', scopes: ['mcp', 'offline_access'] })
  })

  it.each([
    [{ ...CC, redirect_uris: [] }, 'invalid_redirect_uri'],
    [{ ...CC, redirect_uris: Array.from({ length: 6 }, (_, i) => `http://localhost:${5000 + i}/cb`) }, 'invalid_redirect_uri'],
    [{ ...CC, redirect_uris: ['http://localhost:5000/cb', 'https://evil.example/cb'] }, 'invalid_redirect_uri'],
    [{ ...CC, token_endpoint_auth_method: 'client_secret_basic' }, 'invalid_client_metadata'],
    [{ ...CC, grant_types: ['client_credentials'] }, 'invalid_client_metadata'],
    [{ ...CC, grant_types: ['implicit'] }, 'invalid_client_metadata'],
    [{ ...CC, response_types: ['token'] }, 'invalid_client_metadata'],
    [{ ...CC, scope: Array.from({ length: 301 }, (_, i) => `r${i}:read`).join(' ') }, 'invalid_client_metadata'],
    [{ ...CC, client_name: 42 }, 'invalid_client_metadata'],
    ['nope', 'invalid_client_metadata'],
  ])('refuses %#', (body, error) => {
    expect(validateRegistration(body)).toMatchObject({ status: 400, error })
  })
})

describe('POST /oauth2/register', () => {
  it('creates a public client with every field forced, and answers no secret', async () => {
    const res = await register(CC, { 'user-agent': 'claude-code/2.1' })
    expect(res.statusCode).toBe(201)
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.json()).toEqual({
      client_id: 'c-1', client_id_issued_at: Date.parse('2026-09-30T12:00:00Z') / 1000, client_name: 'Claude Code (example)',
      redirect_uris: CC.redirect_uris, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
      token_endpoint_auth_method: 'none', scope: 'mcp offline_access users:read sites:apply',
    })
    expect(res.json()).not.toHaveProperty('client_secret')
    expect(res.json()).not.toHaveProperty('registration_access_token')
    const body = h.createClient.mock.calls[0][0]
    expect(body).toMatchObject({
      token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
      audience: ['https://mcp.example.com/mcp'], owner: 'mcp-dcr', skip_consent: false, access_token_strategy: 'opaque',
      authorization_code_grant_access_token_lifespan: '15m', refresh_token_grant_access_token_lifespan: '15m',
      authorization_code_grant_refresh_token_lifespan: '168h', refresh_token_grant_refresh_token_lifespan: '168h',
      metadata: { kind: 'mcp_oauth', bound_subject: null, user_agent: 'claude-code/2.1' },
    })
    expect(body.metadata.registered_ip_net).toMatch(/\/24$|\/48$|^unknown$/)
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'mcp.oauth.client_registered', targetId: 'c-1' }))
  })

  it('never passes a client-supplied audience, secret method or extra field through', async () => {
    await register({ ...CC, audience: ['https://api.example.com'], owner: 'x', metadata: { kind: 'personal' }, skip_consent: true, client_secret: 's' })
    const body = h.createClient.mock.calls[0][0]
    expect(body.audience).toEqual(['https://mcp.example.com/mcp'])
    expect(body.owner).toBe('mcp-dcr')
    expect(body.skip_consent).toBe(false)
    expect(body.metadata.kind).toBe('mcp_oauth')
    expect(body).not.toHaveProperty('client_secret')
  })

  it('refuses a bad body with RFC 7591 errors', async () => {
    const res = await register({ ...CC, redirect_uris: ['https://evil.example/cb'] })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toMatchObject({ error: 'invalid_redirect_uri' })
    expect(h.createClient).not.toHaveBeenCalled()
  })

  it('is closed while MCP or browser sign-in is off (403 access_denied)', async () => {
    h.config = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    expect((await register(CC)).json()).toMatchObject({ error: 'access_denied' })
    h.config = { mcp: JSON.stringify({ enabled: true, oauth: { enabled: false } }) }
    resetMcpSettingsCache()
    const res = await register(CC)
    expect(res.statusCode).toBe(403)
    h.env.DELEGATED_TOKENS_ENABLED = false
    expect((await register(CC)).statusCode).toBe(403)
    expect(h.createClient).not.toHaveBeenCalled()
  })

  it('answers only on the Hydra host', async () => {
    expect((await register(CC, { host: 'api.example.com' })).statusCode).toBe(404)
  })

  it('brakes per network (10/h) with Retry-After, and fails closed without its counters', async () => {
    for (let i = 0; i < 10; i++) expect((await register(CC)).statusCode).toBe(201)
    const res = await register(CC)
    expect(res.statusCode).toBe(429)
    expect(res.headers['retry-after']).toBe('1234')
    h.counters.clear()
    h.redisDown = true
    expect((await register(CC)).statusCode).toBe(503)
  })

  it('brakes for everyone once the daily budget is spent', async () => {
    h.env.MCP_OAUTH_DCR_RATE = '100/h/ip,3/d'
    for (let i = 0; i < 3; i++) expect((await register(CC)).statusCode).toBe(201)
    expect((await register(CC)).statusCode).toBe(429)
    h.env.MCP_OAUTH_DCR_RATE = '10/h/ip,200/d'
  })

  it('pauses (503) when 500 registrations await consent', async () => {
    h.listAllClients.mockResolvedValue(Array.from({ length: 500 }, (_, i) => ({ client_id: `u${i}`, metadata: { kind: 'mcp_oauth', bound_subject: null } })))
    expect((await register(CC)).statusCode).toBe(503)
    expect(h.createClient).not.toHaveBeenCalled()
    expect(h.listAllClients).toHaveBeenCalledWith(500, 2, 'mcp-dcr')
  })
})

describe('helpers', () => {
  it('ipNet groups callers by /24 and /48', () => {
    expect(ipNet('203.0.113.77')).toBe('203.0.113.0/24')
    expect(ipNet('::ffff:203.0.113.77')).toBe('203.0.113.0/24')
    expect(ipNet('2001:db8:abcd:12::1')).toBe('2001:db8:abcd::/48')
    expect(ipNet('2001:db8::1')).toBe('2001:db8:0::/48')
    expect(ipNet('garbage')).toBe('unknown')
  })

  it('dcrRate reads MCP_OAUTH_DCR_RATE and keeps the defaults on nonsense', () => {
    expect(dcrRate('5/h/ip,50/d')).toEqual({ perIpHour: 5, perDay: 50 })
    expect(dcrRate('lots')).toEqual({ perIpHour: 10, perDay: 200 })
    expect(dcrRate('0/h/ip,0/d')).toEqual({ perIpHour: 10, perDay: 200 })
  })
})
