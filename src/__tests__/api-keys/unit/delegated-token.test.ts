import { describe, it, expect, beforeEach, vi } from 'vitest'

// Delegated user tokens: an opaque Hydra token → the user, their one org, their scopes. Refused when
// inactive, expired, for another audience, not org-bound, an org MACHINE key, or a personal key past
// its expiry or in an org that forbids them.

const s = vi.hoisted(() => ({
  mcpConfig: {} as Record<string, string>,
  env: { DELEGATED_TOKENS_ENABLED: true, DELEGATED_TOKEN_AUDIENCE: 'https://mcp.test', DELEGATED_TOKEN_CACHE_MS: 30_000 },
  introspect: vi.fn(),
  getClient: vi.fn(),
  getIdentity: vi.fn(),
  policy: vi.fn(async () => ({ personal_keys: 'allowed' })),
  touch: vi.fn(),
}))

vi.mock('../../../config/index.js', () => ({ env: s.env }))
// The MCP setting (mcp/settings.ts) read from rbac:config — unset is on, every org.
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => s.mcpConfig, setConfig: vi.fn() } }))
vi.mock('../../../services/hydra.service.js', () => ({ hydraService: { introspect: s.introspect, getClient: s.getClient } }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: { getIdentity: s.getIdentity } }))
vi.mock('../../../services/api-key-policy.js', () => ({ getApiKeyPolicy: s.policy }))
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
  s.mcpConfig = {}
  resetMcpSettingsCache()
  s.env.DELEGATED_TOKENS_ENABLED = true
  s.env.DELEGATED_TOKEN_AUDIENCE = 'https://mcp.test'
  s.introspect.mockReset()
  s.getClient.mockReset()
  s.getIdentity.mockReset().mockResolvedValue({ id: 'user-1', state: 'active', traits: { email: 'ann@acme.io', name: { first: 'Ann', last: 'Lee' } } })
  s.policy.mockReset().mockResolvedValue({ personal_keys: 'allowed' })
  s.touch.mockReset()
  svc = new DelegatedTokenService()
})

describe('DelegatedTokenService.resolve', () => {
  it('maps an OAuth token to its user, org and grantable scopes only', async () => {
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
    ['not bound to an org', { ext: {} }, 'token_not_org_bound'],
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

  it("refuses a token whose org is outside the administrator's scope, cached or not", async () => {
    s.introspect.mockResolvedValue(oauth({ ext: { org: '11111111-1111-1111-1111-111111111111' } }))
    expect(await svc.resolve('same', NOW)).toHaveProperty('principal')
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, allowedOrgs: ['22222222-2222-2222-2222-222222222222'] }) }
    resetMcpSettingsCache()
    expect(await svc.resolve('same', NOW + 1000)).toEqual({ error: 'mcp_org_not_allowed' })
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, allowedOrgs: ['11111111-1111-1111-1111-111111111111'] }) }
    resetMcpSettingsCache()
    expect(await svc.resolve('same', NOW + 2000)).toHaveProperty('principal')
  })

  describe('personal keys (client_credentials, sub = client)', () => {
    const cc = oauth({ sub: 'pk-1', client_id: 'pk-1', ext: undefined, scope: 'payroll:read' })
    const meta = { kind: 'personal', subject: 'user-1', organization_id: 'acme', expires_at: '2026-10-10T00:00:00Z' }

    it('acts as the subject in its metadata, until the earlier of token exp and key expiry', async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: meta })
      const r = await svc.resolve('k', NOW)
      expect(r).toMatchObject({ principal: { subject: 'user-1', org: 'acme', kind: 'personal', clientId: 'pk-1', scopes: ['payroll:read'], keyExpiresAt: Date.parse('2026-10-10T00:00:00Z') } })
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

    it('refuses once the org forbids personal keys', async () => {
      s.introspect.mockResolvedValue(cc)
      s.getClient.mockResolvedValue({ client_id: 'pk-1', metadata: meta })
      s.policy.mockResolvedValue({ personal_keys: 'forbidden' })
      expect(await svc.resolve('k', NOW)).toEqual({ error: 'personal_keys_forbidden' })
    })
  })
})
