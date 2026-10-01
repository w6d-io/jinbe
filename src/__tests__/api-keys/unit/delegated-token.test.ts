import { describe, it, expect, beforeEach, vi } from 'vitest'

// Delegated user tokens: an opaque Hydra token → the user and their scopes, bound to no org. Refused
// when inactive, expired, for another audience, an org MACHINE key, a personal key past its expiry, or
// a holder whose groups may not use MCP. A personal key's scopes are what its holder holds NOW.

const s = vi.hoisted(() => ({
  mcpConfig: {} as Record<string, string>,
  env: { DELEGATED_TOKENS_ENABLED: true, DELEGATED_TOKEN_AUDIENCE: 'https://mcp.test', DELEGATED_TOKEN_CACHE_MS: 30_000 },
  introspect: vi.fn(),
  getClient: vi.fn(),
  getIdentity: vi.fn(),
  touch: vi.fn(),
  groups: ['staff'] as string[],
  held: ['admin:read', 'users:read'] as string[],
  heldFails: false,
  revokeConsent: vi.fn(async () => undefined),
  refreshed: null as string | null,
  audit: vi.fn(),
}))

vi.mock('../../../config/index.js', () => ({ env: s.env }))
// The MCP setting (mcp/settings.ts) read from rbac:config — unset is OFF, so each test saves it on (every org).
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => s.mcpConfig, setConfig: vi.fn() } }))
vi.mock('../../../services/hydra.service.js', () => ({ hydraService: { introspect: s.introspect, getClient: s.getClient } }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: { getIdentity: s.getIdentity } }))
vi.mock('../../../authz/opa.js', () => ({ rights: vi.fn(async () => ({ groups: s.groups, roles: [], permissions: [] })) }))
vi.mock('../../../services/platform-scopes.js', () => ({
  platformScopes: vi.fn(async () => {
    if (s.heldFails) throw new Error('opa down')
    return s.held
  }),
}))
vi.mock('../../../services/api-key-last-used.js', () => ({ touchApiKeyUse: s.touch }))
vi.mock('../../../services/hydra-flows.service.js', () => ({ hydraFlows: { revokeConsentSessions: s.revokeConsent } }))
vi.mock('../../../oauth/audit.js', () => ({ oauthAudit: s.audit }))
vi.mock('../../../oauth/step-up-proof.js', async (orig) => ({ ...((await orig()) as object), refreshedOAuthProof: vi.fn(async () => s.refreshed) }))

import { DelegatedTokenService } from '../../../services/delegated-token.service.js'
import { resetMcpSettingsCache } from '../../../mcp/settings.js'

const NOW = Date.parse('2026-09-28T12:00:00Z')
const exp = NOW / 1000 + 600

const GRANT_END = '2026-10-28T12:00:00.000Z'
const oauthExt = (over: Record<string, unknown> = {}) => ({ org: 'acme', kind: 'oauth', scope_mode: 'chosen', step_up_actions: false, grant_expires_at: GRANT_END, ...over })
const oauth = (over: Record<string, unknown> = {}) => ({
  active: true, sub: 'user-1', client_id: 'claude-code', scope: 'mcp offline_access users:read payroll:read * sites:*',
  aud: ['https://mcp.test'], exp, token_use: 'access_token', ext: oauthExt(), ...over,
})
const mcpClient = (meta: Record<string, unknown> = {}) => ({ client_id: 'claude-code', client_name: 'Claude Code', metadata: { kind: 'mcp_oauth', bound_subject: 'user-1', ...meta } })

let svc: DelegatedTokenService
beforeEach(() => {
  s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
  resetMcpSettingsCache()
  s.env.DELEGATED_TOKENS_ENABLED = true
  s.env.DELEGATED_TOKEN_AUDIENCE = 'https://mcp.test'
  s.introspect.mockReset()
  s.getClient.mockReset().mockResolvedValue(mcpClient())
  s.revokeConsent.mockReset().mockResolvedValue(undefined)
  s.audit.mockReset()
  s.refreshed = null
  s.getIdentity.mockReset().mockResolvedValue({ id: 'user-1', state: 'active', traits: { email: 'ann@acme.io', name: { first: 'Ann', last: 'Lee' } } })
  s.groups = ['staff']
  s.held = ['admin:read', 'users:read']
  s.heldFails = false
  s.touch.mockReset()
  svc = new DelegatedTokenService()
})

describe('DelegatedTokenService.resolve', () => {
  it('maps an OAuth token to its user, the granted scopes still held, and its consent org for information', async () => {
    s.introspect.mockResolvedValue(oauth())
    const r = await svc.resolve('ory_at_abc', NOW)
    expect(r).toEqual({
      principal: {
        subject: 'user-1', email: 'ann@acme.io', name: 'Ann Lee', clientId: 'claude-code',
        scopes: ['users:read'], org: 'acme', kind: 'oauth', expiresAt: exp * 1000,
        tokenScope: 'users:read mcp offline_access * sites:*', aud: ['https://mcp.test'],
        scopeMode: 'chosen', stepUpActions: false, grantExpiresAt: Date.parse(GRANT_END), clientName: 'Claude Code',
      },
    })
  })

  describe('OAuth sign-ins (authorization code, src/oauth/)', () => {
    it("'all' follows what the holder holds now; 'chosen' is the grant still held", async () => {
      s.introspect.mockResolvedValue(oauth({ scope: 'mcp offline_access', ext: oauthExt({ scope_mode: 'all' }) }))
      expect(await svc.resolve('a', NOW)).toMatchObject({ principal: { scopes: ['admin:read', 'users:read'], tokenScope: 'admin:read users:read mcp offline_access', scopeMode: 'all' } })
      s.held = ['users:read']
      expect(await svc.resolve('a', NOW + 1000)).toMatchObject({ principal: { scopes: ['users:read'] } })
      s.introspect.mockResolvedValue(oauth({ scope: 'mcp users:read admin:read' }))
      s.held = ['admin:read']
      expect(await svc.resolve('c', NOW)).toMatchObject({ principal: { scopes: ['admin:read'], scopeMode: 'chosen' } })
    })

    it('refuses a token of a client that is not an MCP registration, or bound to someone else', async () => {
      s.introspect.mockResolvedValue(oauth())
      s.getClient.mockResolvedValue({ client_id: 'claude-code', metadata: { organization_id: 'acme' } })
      expect(await svc.resolve('x1', NOW)).toEqual({ error: 'not_an_mcp_client' })
      s.getClient.mockResolvedValue(mcpClient({ bound_subject: 'user-2' }))
      expect(await svc.resolve('x2', NOW)).toEqual({ error: 'client_bound_elsewhere' })
      s.getClient.mockRejectedValue(new Error('404'))
      expect(await svc.resolve('x3', NOW)).toEqual({ error: 'client_unknown' })
    })

    it('refuses a sign-in past its absolute end (or without one) and revokes it at Hydra, once', async () => {
      s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ grant_expires_at: '2026-09-28T11:00:00Z' }) }))
      expect(await svc.resolve('e1', NOW)).toEqual({ error: 'grant_expired' })
      expect(await svc.resolve('e2', NOW)).toEqual({ error: 'grant_expired' })
      await new Promise((r) => setTimeout(r, 0))
      expect(s.revokeConsent).toHaveBeenCalledTimes(1)
      expect(s.revokeConsent).toHaveBeenCalledWith('user-1', 'claude-code')
      expect(s.audit).toHaveBeenCalledWith('mcp.oauth.grant_expired', expect.objectContaining({ targetId: 'claude-code' }))
      s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ grant_expires_at: undefined }) }))
      expect(await svc.resolve('e3', NOW)).toEqual({ error: 'grant_expired' })
    })

    it('never outlives the sign-in: expiresAt is the earlier of the token and the grant', async () => {
      const soon = new Date(NOW + 60_000).toISOString()
      s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ grant_expires_at: soon }) }))
      expect(await svc.resolve('s', NOW)).toMatchObject({ principal: { expiresAt: NOW + 60_000 } })
    })

    it('protected actions: allowed at consent, for the settings window after the consent-time factor, never past the grant', async () => {
      const at = new Date(NOW - 3600_000).toISOString()
      s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ step_up_actions: true, second_factor_at: at }) }))
      expect(await svc.resolve('p1', NOW)).toMatchObject({ principal: { stepUpActions: true, stepUpAt: at, stepUpUntil: new Date(NOW + 11 * 3600_000).toISOString() } })
      s.mcpConfig = { mcp: JSON.stringify({ enabled: true, oauth: { protectedActions: 'off' } }) }
      resetMcpSettingsCache()
      expect((await svc.resolve('p1', NOW + 1000) as { principal: Record<string, unknown> }).principal.stepUpUntil).toBeUndefined()
      s.mcpConfig = { mcp: JSON.stringify({ enabled: true, oauth: { protectedActionsHours: 720 } }) }
      resetMcpSettingsCache()
      const end = new Date(NOW + 2 * 3600_000).toISOString()
      s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ step_up_actions: true, second_factor_at: at, grant_expires_at: end }) }))
      expect(await svc.resolve('p3', NOW)).toMatchObject({ principal: { stepUpUntil: end } })
      s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ step_up_actions: false, second_factor_at: at }) }))
      expect((await svc.resolve('p2', NOW) as { principal: Record<string, unknown> }).principal.stepUpUntil).toBeUndefined()
    })

    it('a proof refreshed through a step-up link wins when newer than the consent stamp (only with protected actions)', async () => {
      const consented = new Date(NOW - 20 * 3600_000).toISOString()
      const refreshed = new Date(NOW - 60_000).toISOString()
      s.refreshed = refreshed
      s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ step_up_actions: true, second_factor_at: consented }) }))
      expect(await svc.resolve('r1', NOW)).toMatchObject({ principal: { stepUpAt: refreshed, stepUpUntil: new Date(NOW - 60_000 + 12 * 3600_000).toISOString() } })
      s.refreshed = new Date(NOW - 30 * 3600_000).toISOString()
      expect(await svc.resolve('r2', NOW)).toMatchObject({ principal: { stepUpAt: consented } })
      s.refreshed = refreshed
      s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ step_up_actions: false, second_factor_at: consented }) }))
      const r = (await svc.resolve('r3', NOW)) as { principal: Record<string, unknown> }
      expect(r.principal.stepUpAt).toBe(consented)
      expect(r.principal.stepUpUntil).toBeUndefined()
    })

    it('an administrator turning browser sign-in off refuses OAuth tokens at once (keys keep working)', async () => {
      s.introspect.mockResolvedValue(oauth())
      expect(await svc.resolve('o', NOW)).toHaveProperty('principal')
      s.mcpConfig = { mcp: JSON.stringify({ enabled: true, oauth: { enabled: false } }) }
      resetMcpSettingsCache()
      expect(await svc.resolve('o', NOW + 1000)).toEqual({ error: 'oauth_disabled' })
    })
  })

  it.each([
    ['inactive', { active: false }, 'token_inactive'],
    ['expired', { exp: NOW / 1000 - 1 }, 'token_expired'],
    ['another audience', { aud: ['https://jinbe'] }, 'audience_mismatch'],
    ['a refresh token', { token_use: 'refresh_token' }, 'not_an_access_token'],
  ])('refuses a token that is %s', async (_label, over, error) => {
    s.introspect.mockResolvedValue(oauth(over))
    expect(await svc.resolve('t', NOW)).toEqual({ error })
  })

  it('refuses everything while disabled or without an audience, without asking Hydra', async () => {
    s.env.DELEGATED_TOKENS_ENABLED = false
    expect(await svc.resolve('t', NOW)).toEqual({ error: 'delegated_tokens_disabled' })
    s.env.DELEGATED_TOKENS_ENABLED = true
    s.env.DELEGATED_TOKEN_AUDIENCE = ''
    expect(await svc.resolve('t', NOW)).toEqual({ error: 'delegated_audience_unset' })
    expect(s.introspect).not.toHaveBeenCalled()
  })

  it('an unreachable Hydra is a refusal, never an allow', async () => {
    s.introspect.mockRejectedValue(new Error('ECONNREFUSED'))
    expect(await svc.resolve('t', NOW)).toEqual({ error: 'introspection_unavailable' })
  })

  it('a disabled user is refused even with a live token', async () => {
    s.introspect.mockResolvedValue(oauth())
    s.getIdentity.mockResolvedValue({ id: 'user-1', state: 'inactive', traits: { email: 'ann@acme.io' } })
    expect(await svc.resolve('t', NOW)).toEqual({ error: 'subject_inactive' })
  })

  it('never introspects a personal key (stk_mcp_…): it is a secret, not a token', () => {
    expect(svc.looksOpaque('stk_mcp_pk.secret')).toBe(false)
    expect(svc.looksOpaque('ory_at_abc')).toBe(true)
  })

  it('caches an answer briefly (one introspection) and keys it on the token', async () => {
    s.introspect.mockResolvedValue(oauth())
    await svc.resolve('same', NOW)
    await svc.resolve('same', NOW + 1000)
    expect(s.introspect).toHaveBeenCalledTimes(1)
    await svc.resolve('same', NOW + 31_000)
    expect(s.introspect).toHaveBeenCalledTimes(2)
  })

  it('a revoked key is asked again at once, not after the cache window', async () => {
    s.introspect.mockResolvedValue(oauth())
    await svc.resolve('tok', NOW)
    svc.forgetClient('another-client')
    await svc.resolve('tok', NOW + 1000)
    expect(s.introspect).toHaveBeenCalledTimes(1)
    s.introspect.mockResolvedValue(oauth({ active: false }))
    svc.forgetClient('claude-code')
    expect(await svc.resolve('tok', NOW + 2000)).toEqual({ error: 'token_inactive' })
  })

  it('a revocation announced elsewhere reaches this replica through the invalidation channel', async () => {
    s.introspect.mockResolvedValue(oauth())
    await svc.resolve('tok2', NOW)
    // Another instance stands in for the replica that revoked: only the channel links the two.
    new DelegatedTokenService().forgetClient('claude-code')
    await svc.resolve('tok2', NOW + 1000)
    expect(s.introspect).toHaveBeenCalledTimes(2)
  })

  it('an administrator switching MCP off refuses tokens already cached; switching it back on restores them', async () => {
    s.introspect.mockResolvedValue(oauth())
    expect(await svc.resolve('same', NOW)).toHaveProperty('principal')
    s.mcpConfig = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    expect(await svc.resolve('same', NOW + 1000)).toEqual({ error: 'mcp_disabled' })
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
    resetMcpSettingsCache()
    expect(await svc.resolve('same', NOW + 2000)).toHaveProperty('principal')
    expect(s.introspect).toHaveBeenCalledTimes(1)
  })

  it('accepts a token that names no org', async () => {
    s.introspect.mockResolvedValue(oauth({ ext: oauthExt({ org: undefined }) }))
    const r = await svc.resolve('t', NOW)
    expect(r).toHaveProperty('principal')
    expect((r as { principal: Record<string, unknown> }).principal).not.toHaveProperty('org')
  })

  it("refuses a holder whose groups the administrator has not allowed, cached or not — at once", async () => {
    s.introspect.mockResolvedValue(oauth())
    expect(await svc.resolve('same', NOW)).toHaveProperty('principal')
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, allowedGroups: ['support'] }) }
    resetMcpSettingsCache()
    expect(await svc.resolve('same', NOW + 1000)).toEqual({ error: 'mcp_group_not_allowed' })
    s.groups = ['staff', 'support']
    expect(await svc.resolve('same', NOW + 2000)).toHaveProperty('principal')
    expect(s.introspect).toHaveBeenCalledTimes(1)
  })

  describe('personal keys (client_credentials, sub = client)', () => {
    const cc = oauth({ sub: 'pk-1', client_id: 'pk-1', ext: undefined, scope: 'users:read sessions:read mcp' })
    const meta = { kind: 'personal', subject: 'user-1', scope_mode: 'selected', expires_at: '2026-10-10T00:00:00Z' }

    it('acts as the subject in its metadata, bound to no org, with the stored scopes it STILL holds', async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: meta })
      const r = await svc.resolve('k', NOW)
      expect(r).toMatchObject({ principal: { subject: 'user-1', kind: 'personal', clientId: 'pk-1', scopes: ['users:read'], tokenScope: 'users:read mcp', allPermissions: false, keyExpiresAt: Date.parse('2026-10-10T00:00:00Z') } })
      expect((r as { principal: Record<string, unknown> }).principal).not.toHaveProperty('org')
    })

    it('an all-permissions key carries everything its holder holds now, recomputed on every call', async () => {
      s.introspect.mockResolvedValue({ ...cc, scope: 'mcp' })
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: { ...meta, scope_mode: 'all' } })
      expect(await svc.resolve('k', NOW)).toMatchObject({ principal: { scopes: ['admin:read', 'users:read'], tokenScope: 'admin:read users:read mcp', allPermissions: true } })
      // A group removed: the next call, cached token or not, carries less.
      s.held = ['users:read']
      expect(await svc.resolve('k', NOW + 1000)).toMatchObject({ principal: { scopes: ['users:read'] } })
      expect(s.introspect).toHaveBeenCalledTimes(1)
    })

    it('refuses when what the holder holds cannot be told, never guesses', async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: meta })
      s.heldFails = true
      expect(await svc.resolve('k', NOW)).toEqual({ error: 'authz_unavailable' })
    })

    it('marks the key used on every accepted token, cached or not — an OAuth sign-in too', async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: meta })
      await svc.resolve('k', NOW)
      await svc.resolve('k', NOW + 1000)
      expect(s.introspect).toHaveBeenCalledTimes(1)
      expect(s.touch.mock.calls).toEqual([['pk-1', NOW], ['pk-1', NOW + 1000]])
      s.touch.mockReset()
      s.getClient.mockResolvedValue(mcpClient())
      s.introspect.mockResolvedValue(oauth())
      await svc.resolve('o', NOW)
      expect(s.touch.mock.calls).toEqual([['claude-code', NOW]])
    })

    it('refuses an org MACHINE key: it is not a person', async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: { organization_id: 'acme' } })
      expect(await svc.resolve('k', NOW)).toEqual({ error: 'not_a_user_token' })
    })

    it('refuses an expired key, and one without an expiry', async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: { ...meta, expires_at: '2026-09-01T00:00:00Z' } })
      expect(await svc.resolve('k1', NOW)).toEqual({ error: 'key_expired' })
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: { ...meta, expires_at: undefined } })
      expect(await svc.resolve('k2', NOW)).toEqual({ error: 'key_expired' })
    })

    it('an older key still naming an org works as any other: the org means nothing now', async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: { ...meta, organization_id: 'acme' } })
      expect(await svc.resolve('k', NOW)).toHaveProperty('principal')
    })
  })
})
