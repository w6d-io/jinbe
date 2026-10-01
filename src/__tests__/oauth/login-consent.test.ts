import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// The Hydra login and consent providers for MCP clients, as login-ui asks them (the visitor's Kratos
// cookies): aal2 with a factor under 15 minutes old at every sign-in, the MCP switch + browser sign-in
// switch + group gate, PKCE S256 and no foreign resource, the consent picker (all my permissions or a
// subset of what is held), protected actions for 12 h after the consent-time factor (D1), and the
// registration bound to its first consenting person.

const NOW = Date.now()
const minutesAgo = (m: number) => new Date(NOW - m * 60_000)

const h = vi.hoisted(() => ({
  env: {
    MCP_OAUTH_ISSUER: 'https://hydra.example.com/',
    DELEGATED_TOKENS_ENABLED: true,
    DELEGATED_TOKEN_AUDIENCE: 'https://mcp.example.com/mcp',
    AUTH_DOMAIN: 'auth.example.com',
  } as Record<string, unknown>,
  config: {} as Record<string, string>,
  session: null as null | Record<string, unknown>,
  mfa: ['totp'] as string[],
  groups: ['staff'] as string[],
  held: ['sites:read', 'sites:apply', 'users:read'] as string[],
  flows: {
    getLoginRequest: vi.fn(),
    acceptLogin: vi.fn(async () => ({ redirect_to: 'https://hydra.example.com/oauth2/auth?login_verifier=v' })),
    rejectLogin: vi.fn(async () => ({ redirect_to: 'http://localhost:53682/callback?error=access_denied' })),
    getConsentRequest: vi.fn(),
    acceptConsent: vi.fn(async () => ({ redirect_to: 'https://hydra.example.com/oauth2/auth?consent_verifier=v' })),
    rejectConsent: vi.fn(async () => ({ redirect_to: 'http://localhost:53682/callback?error=access_denied' })),
    patchClient: vi.fn(async () => ({})),
  },
  getClient: vi.fn(),
  emit: vi.fn(async () => 'id'),
}))

vi.mock('../../config/index.js', async (orig) => {
  const real = (await orig()) as { env: object }
  Object.setPrototypeOf(h.env, real.env)
  return { ...real, env: h.env }
})
vi.mock('../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => h.config, setConfig: vi.fn() } }))
vi.mock('../../services/hydra-flows.service.js', () => ({ hydraFlows: h.flows }))
vi.mock('../../services/hydra.service.js', async (orig) => ({ ...((await orig()) as object), hydraService: { getClient: h.getClient } }))
vi.mock('../../services/kratos-session.service.js', async (orig) => ({
  ...((await orig()) as object),
  kratosSessionService: { validateSession: vi.fn(async () => ({ session: h.session })) },
}))
vi.mock('../../services/kratos.service.js', () => ({ kratosService: { mfaMethodsOf: vi.fn(async () => h.mfa) } }))
vi.mock('../../authz/opa.js', async (orig) => ({ ...((await orig()) as object), rights: vi.fn(async () => ({ groups: h.groups, roles: [], permissions: [] })) }))
vi.mock('../../services/platform-scopes.js', () => ({
  platformScopes: vi.fn(async () => h.held),
  scopeGroup: (s: string) => s.split(/[.:]/)[0],
  delegableJinbePermissions: () => new Map(),
}))
vi.mock('../../services/audit-event.service.js', () => ({ auditEventService: { emit: h.emit } }))

import { installRouteAccess } from '../../policy/route-access.js'
import { oauthProviderRoutes } from '../../oauth/routes.js'
import { resetMcpSettingsCache } from '../../mcp/settings.js'
import { HydraApiError } from '../../services/hydra.service.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  await app.register(oauthProviderRoutes, { prefix: '/api/public/oauth2' })
  await app.ready()
})
afterAll(() => app.close())

const CLIENT = { client_id: 'c-1', client_name: 'Claude Code', redirect_uris: ['http://localhost:53682/callback'], metadata: { kind: 'mcp_oauth', bound_subject: null, registered_at: '2026-09-30T10:00:00Z' } }
const AUTH_URL = 'https://hydra.example.com/oauth2/auth?client_id=c-1&response_type=code&code_challenge=abc&code_challenge_method=S256&resource=https%3A%2F%2Fmcp.example.com%2Fmcp&scope=mcp'
const loginReq = (over: Record<string, unknown> = {}) => ({ challenge: 'L', client: CLIENT, request_url: AUTH_URL, skip: false, ...over })
const consentReq = (over: Record<string, unknown> = {}) => ({
  challenge: 'C', client: CLIENT, subject: 'user-1', request_url: AUTH_URL,
  requested_scope: ['mcp', 'offline_access', 'sites:read', 'sites:apply', 'payroll:read', 'users:read', 'settings:read'], ...over,
})
const session = (over: Record<string, unknown> = {}) => ({
  sessionId: 's-1', identityId: 'user-1', email: 'ann@acme.io', aal: 'aal2', secondFactorAt: minutesAgo(2), methods: ['password', 'totp'],
  expiresAt: new Date(NOW + 3600_000), active: true, authenticatedAt: minutesAgo(3), ...over,
})

beforeEach(() => {
  h.config = { mcp: JSON.stringify({ enabled: true }) }
  h.session = session()
  h.mfa = ['totp']
  h.groups = ['staff']
  h.held = ['sites:read', 'sites:apply', 'users:read']
  for (const f of Object.values(h.flows)) f.mockClear()
  h.flows.getLoginRequest.mockReset().mockResolvedValue(loginReq())
  h.flows.getConsentRequest.mockReset().mockResolvedValue(consentReq())
  // Hydra's client store, as getClient reads it and patchClient writes it (no JSON Patch `test` in Hydra).
  let stored: Record<string, unknown> = { ...CLIENT.metadata }
  h.flows.patchClient.mockReset().mockImplementation(async (_id: string, ops: { path: string; value: unknown }[]) => {
    for (const o of ops) stored = { ...stored, [o.path.replace('/metadata/', '')]: o.value }
    return {}
  })
  h.getClient.mockReset().mockImplementation(async () => ({ ...CLIENT, metadata: { ...stored } }))
  h.emit.mockClear()
  resetMcpSettingsCache()
})

const cookie = 'ory_kratos_session=abc; other=1'
const login = (headers: Record<string, string> = { cookie }) => app.inject({ method: 'GET', url: '/api/public/oauth2/login?login_challenge=L', headers })
const screen = (headers: Record<string, string> = { cookie }) => app.inject({ method: 'GET', url: '/api/public/oauth2/consent?consent_challenge=C', headers })
const decide = (body: Record<string, unknown>, headers: Record<string, string> = {}) =>
  app.inject({ method: 'POST', url: '/api/public/oauth2/consent', headers: { cookie, origin: 'https://auth.example.com', 'content-type': 'application/json', ...headers }, payload: JSON.stringify({ consent_challenge: 'C', ...body }) })

const back = encodeURIComponent('https://auth.example.com/oauth2/login?login_challenge=L')

describe('login provider', () => {
  it('accepts an aal2 session with a fresh factor: subject, no remember, acr/amr, the proof time in the context', async () => {
    const res = await login()
    expect(res.statusCode).toBe(200)
    expect(res.headers['cache-control']).toBe('private, no-store')
    expect(res.json()).toEqual({ action: 'redirect', to: 'https://hydra.example.com/oauth2/auth?login_verifier=v' })
    expect(h.flows.acceptLogin).toHaveBeenCalledWith('L', {
      subject: 'user-1', remember: false, acr: 'aal2', amr: ['password', 'totp'],
      context: { second_factor_at: minutesAgo(2).toISOString(), kratos_session_id: 's-1', aal: 'aal2' },
    })
  })

  it('without a session: Kratos login, coming back here', async () => {
    h.session = null
    expect((await login({})).json()).toEqual({ action: 'redirect', to: `https://auth.example.com/self-service/login/browser?return_to=${back}` })
    expect(h.flows.acceptLogin).not.toHaveBeenCalled()
  })

  it('aal1 with a factor enrolled: the Kratos aal2 flow', async () => {
    h.session = session({ aal: 'aal1', secondFactorAt: null })
    expect((await login()).json()).toEqual({ action: 'redirect', to: `https://auth.example.com/self-service/login/browser?aal=aal2&return_to=${back}` })
  })

  it('no factor at all: enrolment first, no bypass', async () => {
    h.session = session({ aal: 'aal1', secondFactorAt: null })
    h.mfa = []
    expect((await login()).json()).toEqual({ action: 'redirect', to: `https://auth.example.com/two-step?return_to=${back}&must_enrol=1` })
  })

  it('a factor older than 15 minutes: aal2 refresh', async () => {
    h.session = session({ secondFactorAt: minutesAgo(16) })
    expect((await login()).json()).toEqual({ action: 'redirect', to: `https://auth.example.com/self-service/login/browser?aal=aal2&refresh=true&return_to=${back}` })
  })

  it.each([
    ['MCP off', () => { h.config = { mcp: JSON.stringify({ enabled: false }) } }, 'mcp_disabled'],
    ['browser sign-in off', () => { h.config = { mcp: JSON.stringify({ enabled: true, oauth: { enabled: false } }) } }, 'oauth_disabled'],
    ['no issuer configured', () => { h.env.MCP_OAUTH_ISSUER = '' }, 'oauth_disabled'],
    ['groups not allowed', () => { h.config = { mcp: JSON.stringify({ enabled: true, allowedGroups: ['support'] }) } }, 'group_not_allowed'],
    ['not an MCP client', () => { h.flows.getLoginRequest.mockResolvedValue(loginReq({ client: { client_id: 'org-key', metadata: { organization_id: 'x' } } })) }, 'not_mcp_client'],
    ['PKCE plain', () => { h.flows.getLoginRequest.mockResolvedValue(loginReq({ request_url: AUTH_URL.replace('S256', 'plain') })) }, 'pkce_required'],
    ['no PKCE', () => { h.flows.getLoginRequest.mockResolvedValue(loginReq({ request_url: 'https://hydra.example.com/oauth2/auth?client_id=c-1' })) }, 'pkce_required'],
    ['a foreign resource', () => { h.flows.getLoginRequest.mockResolvedValue(loginReq({ request_url: `${AUTH_URL}&resource=https%3A%2F%2Fevil.example%2F` })) }, 'invalid_target'],
  ])('refuses (%s): Hydra reject, audited', async (_label, arrange, reason) => {
    arrange()
    resetMcpSettingsCache()
    const res = await login()
    h.env.MCP_OAUTH_ISSUER = 'https://hydra.example.com/'
    expect(res.json()).toEqual({ action: 'refused', reason, to: 'http://localhost:53682/callback?error=access_denied' })
    expect(h.flows.rejectLogin).toHaveBeenCalledWith('L', expect.objectContaining({ error: expect.any(String), error_description: expect.any(String) }))
    expect(h.flows.acceptLogin).not.toHaveBeenCalled()
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'mcp.oauth.login_refused', reason, result: 'denied' }))
  })

  it('an expired or used challenge is 404 challenge_unknown; Hydra down is 503', async () => {
    h.flows.getLoginRequest.mockRejectedValue(new HydraApiError(410, 'Gone'))
    expect((await login()).json()).toMatchObject({ error: 'challenge_unknown' })
    h.flows.getLoginRequest.mockRejectedValue(new HydraApiError(500, 'boom'))
    expect((await login()).statusCode).toBe(503)
  })

  it('refuses a bearer: the provider takes the visitor, not a token', async () => {
    expect((await login({ cookie, authorization: 'Bearer ory_at_x' })).statusCode).toBe(403)
  })

  it('refuses a remembered subject that is not the signed-in visitor', async () => {
    h.flows.getLoginRequest.mockResolvedValue(loginReq({ skip: true, subject: 'user-2' }))
    expect((await login()).json()).toMatchObject({ action: 'refused', reason: 'wrong_account' })
  })
})

describe('consent screen', () => {
  it('shows the unverified client, the account, what is asked AND held, and offers protected actions for 12 h', async () => {
    const res = await screen()
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body).toMatchObject({
      action: 'show',
      client: { client_id: 'c-1', name: 'Claude Code', name_verified: false, redirect_host: 'localhost:53682', registered_at: '2026-09-30T10:00:00Z' },
      account: { email: 'ann@acme.io', subject: 'user-1' },
      offline_access: true,
      protectedActions: { offered: true, until: new Date(minutesAgo(2).getTime() + 12 * 3600_000).toISOString(), hours: 12, permissions: ['sites:apply'] },
    })
    expect(body.requested).toEqual(['payroll:read', 'settings:read', 'sites:apply', 'sites:read', 'users:read'])
    // payroll:read and settings:read are asked but not held: never offered.
    expect(body.catalog.map((c: { scope: string }) => c.scope)).toEqual(['sites:apply', 'sites:read', 'users:read'])
    expect(body.catalog[0]).toEqual({ scope: 'sites:apply', group: 'sites', label: expect.any(String), sensitivity: expect.any(String), protected: true })
    expect(Date.parse(body.grantExpiresAt) - Date.now()).toBeGreaterThan(29.9 * 24 * 3600_000)
  })

  it('offers no protected actions without a held protected permission, with the window off, or a stale factor', async () => {
    h.held = ['sites:read']
    expect((await screen()).json().protectedActions).toEqual({ offered: false, until: null, hours: 12, permissions: [] })
    h.held = ['sites:apply']
    h.config = { mcp: JSON.stringify({ enabled: true, oauth: { protectedActions: 'off' } }) }
    resetMcpSettingsCache()
    expect((await screen()).json().protectedActions.offered).toBe(false)
    h.config = { mcp: JSON.stringify({ enabled: true }) }
    resetMcpSettingsCache()
    h.session = session({ secondFactorAt: minutesAgo(20) })
    expect((await screen()).json().protectedActions.offered).toBe(false)
  })

  it('never shows a challenge that belongs to someone else (403), and needs a session (401)', async () => {
    h.flows.getConsentRequest.mockResolvedValue(consentReq({ subject: 'user-2' }))
    expect((await screen()).statusCode).toBe(403)
    h.session = null
    expect((await screen({})).statusCode).toBe(401)
  })

  it.each([
    ['a foreign resource', () => h.flows.getConsentRequest.mockResolvedValue(consentReq({ request_url: `${AUTH_URL}&resource=https%3A%2F%2Fevil.example%2F` })), 'invalid_target'],
    ['a registration bound to someone else', () => h.flows.getConsentRequest.mockResolvedValue(consentReq({ client: { ...CLIENT, metadata: { ...CLIENT.metadata, bound_subject: 'user-2' } } })), 'client_bound_elsewhere'],
    ['groups not allowed', () => { h.groups = ['guests']; h.config = { mcp: JSON.stringify({ enabled: true, allowedGroups: ['staff'] }) } }, 'group_not_allowed'],
  ])('refuses (%s) with a Hydra reject', async (_l, arrange, reason) => {
    arrange()
    resetMcpSettingsCache()
    expect((await screen()).json()).toEqual({ action: 'refused', reason, to: 'http://localhost:53682/callback?error=access_denied' })
    expect(h.flows.rejectConsent).toHaveBeenCalled()
  })
})

describe('consent decision', () => {
  const ext = () => h.flows.acceptConsent.mock.calls[0][1] as { grant_scope: string[]; grant_access_token_audience: string[]; remember: boolean; session: { access_token: Record<string, unknown> } }

  it("'all my permissions': asked ∩ held + mcp + offline_access, the MCP audience, the stamp jinbe reads", async () => {
    const res = await decide({ decision: 'allow', mode: 'all' })
    expect(res.json()).toEqual({ action: 'redirect', to: 'https://hydra.example.com/oauth2/auth?consent_verifier=v' })
    const body = ext()
    expect(body.grant_scope).toEqual(['mcp', 'offline_access', 'sites:apply', 'sites:read', 'users:read'])
    expect(body.grant_access_token_audience).toEqual(['https://mcp.example.com/mcp'])
    expect(body.remember).toBe(false)
    expect(body.session.access_token).toMatchObject({ kind: 'oauth', scope_mode: 'all', second_factor_at: minutesAgo(2).toISOString(), step_up_actions: false })
    expect(Date.parse(body.session.access_token.grant_expires_at as string) - Date.parse(body.session.access_token.granted_at as string)).toBe(30 * 24 * 3600_000)
    // First consent binds the registration (no JSON Patch `test`: Hydra answers 500 on it), then re-reads it.
    expect(h.flows.patchClient).toHaveBeenCalledWith('c-1', [{ op: 'replace', path: '/metadata/bound_subject', value: 'user-1' }])
    expect(h.flows.patchClient.mock.calls[0][1].some((o: { op: string }) => o.op === 'test')).toBe(false)
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'mcp.oauth.consent_granted', targetId: 'c-1' }))
  })

  it("'chosen': only the ticked scopes that are asked and held — a forged or unheld one is dropped", async () => {
    await decide({ decision: 'allow', mode: 'chosen', scopes: ['sites:read', 'payroll:read', 'admin:write'] })
    expect(ext().grant_scope).toEqual(['mcp', 'offline_access', 'sites:read'])
    expect(ext().session.access_token.scope_mode).toBe('chosen')
  })

  it("'chosen' with nothing usable is refused (400 no_scopes)", async () => {
    const res = await decide({ decision: 'allow', mode: 'chosen', scopes: ['payroll:read'] })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toBe('no_scopes')
    expect(h.flows.acceptConsent).not.toHaveBeenCalled()
  })

  it('protected actions: stamped when offered and ticked; refused when not offered', async () => {
    await decide({ decision: 'allow', mode: 'all', protected_actions: true })
    expect(ext().session.access_token.step_up_actions).toBe(true)
    h.flows.acceptConsent.mockClear()
    h.session = session({ secondFactorAt: minutesAgo(30) })
    const res = await decide({ decision: 'allow', mode: 'all', protected_actions: true })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toBe('protected_actions_unavailable')
    expect(h.flows.acceptConsent).not.toHaveBeenCalled()
  })

  it('deny: Hydra reject, audited', async () => {
    const res = await decide({ decision: 'deny' })
    expect(res.json()).toEqual({ action: 'redirect', to: 'http://localhost:53682/callback?error=access_denied' })
    expect(h.flows.rejectConsent).toHaveBeenCalledWith('C', expect.objectContaining({ error: 'access_denied' }))
    expect(h.emit).toHaveBeenCalledWith(expect.objectContaining({ v1Event: 'mcp.oauth.consent_denied' }))
  })

  it('a registration someone else already bound is refused without writing, never granted', async () => {
    h.getClient.mockResolvedValue({ ...CLIENT, metadata: { ...CLIENT.metadata, bound_subject: 'user-2' } })
    expect((await decide({ decision: 'allow', mode: 'all' })).json()).toMatchObject({ action: 'refused', reason: 'client_bound_elsewhere' })
    expect(h.flows.patchClient).not.toHaveBeenCalled()
    expect(h.flows.acceptConsent).not.toHaveBeenCalled()
  })

  it('a lost race (the other write landed after ours) is refused on the re-read', async () => {
    h.getClient
      .mockResolvedValueOnce({ ...CLIENT })
      .mockResolvedValueOnce({ ...CLIENT, metadata: { ...CLIENT.metadata, bound_subject: 'user-2' } })
    expect((await decide({ decision: 'allow', mode: 'all' })).json()).toMatchObject({ action: 'refused', reason: 'client_bound_elsewhere' })
    expect(h.flows.acceptConsent).not.toHaveBeenCalled()
  })

  it('an already-bound (own) registration is not patched again', async () => {
    h.flows.getConsentRequest.mockResolvedValue(consentReq({ client: { ...CLIENT, metadata: { ...CLIENT.metadata, bound_subject: 'user-1' } } }))
    await decide({ decision: 'allow', mode: 'all' })
    expect(h.flows.patchClient).not.toHaveBeenCalled()
    expect(h.flows.acceptConsent).toHaveBeenCalled()
  })

  it('CSRF: Origin must be the auth host; a bearer is refused; the challenge must be the visitor\'s', async () => {
    expect((await decide({ decision: 'allow' }, { origin: 'https://evil.example' })).json()).toMatchObject({ error: 'bad_origin' })
    expect((await decide({ decision: 'allow' }, { origin: '' })).statusCode).toBe(403)
    expect((await decide({ decision: 'allow' }, { authorization: 'Bearer ory_at_x' })).statusCode).toBe(403)
    h.flows.getConsentRequest.mockResolvedValue(consentReq({ subject: 'user-2' }))
    expect((await decide({ decision: 'allow' })).json()).toMatchObject({ error: 'wrong_account' })
    expect(h.flows.acceptConsent).not.toHaveBeenCalled()
  })

  it('re-checks the gate at decision time (MCP turned off since the screen)', async () => {
    h.config = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    expect((await decide({ decision: 'allow', mode: 'all' })).json()).toMatchObject({ action: 'refused', reason: 'mcp_disabled' })
    expect(h.flows.acceptConsent).not.toHaveBeenCalled()
  })

  it('ignores a smuggled field: the grant is computed here, never taken from the body', async () => {
    await decide({ decision: 'allow', mode: 'all', grant_scope: ['*'], session: { access_token: { scope_mode: 'all', step_up_actions: true } } })
    expect(ext().grant_scope).not.toContain('*')
    expect(ext().session.access_token.step_up_actions).toBe(false)
  })
})
