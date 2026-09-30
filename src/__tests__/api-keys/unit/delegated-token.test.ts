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

import { DelegatedTokenService } from '../../../services/delegated-token.service.js'
import { resetMcpSettingsCache } from '../../../mcp/settings.js'

const NOW = Date.parse('2026-09-28T12:00:00Z')
const exp = NOW / 1000 + 600

const oauth = (over: Record<string, unknown> = {}) => ({
  active: true, sub: 'user-1', client_id: 'claude-code', scope: 'mcp offline_access payroll:read * sites:*',
  aud: ['https://mcp.test'], exp, token_use: 'access_token', ext: { org: 'acme' }, ...over,
})

let svc: DelegatedTokenService
beforeEach(() => {
  s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
  resetMcpSettingsCache()
  s.env.DELEGATED_TOKENS_ENABLED = true
  s.env.DELEGATED_TOKEN_AUDIENCE = 'https://mcp.test'
  s.introspect.mockReset()
  s.getClient.mockReset()
  s.getIdentity.mockReset().mockResolvedValue({ id: 'user-1', state: 'active', traits: { email: 'ann@acme.io', name: { first: 'Ann', last: 'Lee' } } })
  s.groups = ['staff']
  s.held = ['admin:read', 'users:read']
  s.heldFails = false
  s.touch.mockReset()
  svc = new DelegatedTokenService()
})

describe('DelegatedTokenService.resolve', () => {
  it('maps an OAuth token to its user, grantable scopes only, and its consent org for information', async () => {
    s.introspect.mockResolvedValue(oauth())
    const r = await svc.resolve('ory_at_abc', NOW)
    expect(r).toEqual({
      principal: {
        subject: 'user-1', email: 'ann@acme.io', name: 'Ann Lee', clientId: 'claude-code',
        scopes: ['payroll:read'], org: 'acme', kind: 'oauth', expiresAt: exp * 1000,
        tokenScope: 'mcp offline_access payroll:read * sites:*', aud: ['https://mcp.test'],
      },
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
    s.introspect.mockResolvedValue(oauth({ ext: {} }))
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

    it("marks the key used on every accepted token, cached or not, and never an OAuth client's", async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: meta })
      await svc.resolve('k', NOW)
      await svc.resolve('k', NOW + 1000)
      expect(s.introspect).toHaveBeenCalledTimes(1)
      expect(s.touch.mock.calls).toEqual([['pk-1', NOW], ['pk-1', NOW + 1000]])
      s.touch.mockReset()
      s.introspect.mockResolvedValue(oauth())
      await svc.resolve('o', NOW)
      expect(s.touch).not.toHaveBeenCalled()
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
