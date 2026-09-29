import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// auth-mcp's jinbe endpoints: actor-only, 404 while the flag is off, and the shapes
// auth-mcp's JinbeTokenInfoVerifier / JinbeKeyExchanger read.

const s = vi.hoisted(() => ({
  mcpConfig: {} as Record<string, string>,
  env: { DELEGATED_TOKENS_ENABLED: true },
  actor: 'auth-mcp' as string | null,
  resolve: vi.fn(),
  exchange: vi.fn(),
}))
vi.mock('../../../config/index.js', () => ({ env: s.env }))
// The MCP setting (mcp/settings.ts) read from rbac:config — unset is OFF, so each test saves it on (every org).
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => s.mcpConfig, setConfig: vi.fn() } }))
vi.mock('../../../middleware/identity-extractor.js', () => ({ verifiedActor: vi.fn(async () => s.actor) }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))
vi.mock('../../../services/delegated-token.service.js', () => ({
  PERSONAL_KEY_PREFIX: 'stk_mcp_',
  delegatedTokenService: { looksOpaque: (t: string) => t.split('.').length !== 3 && !t.startsWith('stk_mcp_'), resolve: s.resolve },
}))
vi.mock('../../../services/personal-key.service.js', () => {
  class PersonalKeyRefused extends Error { constructor(public reason: string) { super(reason) } }
  return { personalKeyService: { exchange: s.exchange }, PersonalKeyRefused }
})

import { mcpRoutes } from '../../../routes/mcp.routes.js'
import { PersonalKeyRefused } from '../../../services/personal-key.service.js'
import { resetMcpSettingsCache } from '../../../mcp/settings.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  await app.register(mcpRoutes, { prefix: '/api/mcp' })
  await app.ready()
})
afterAll(() => app.close())
beforeEach(() => {
  s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
  resetMcpSettingsCache()
  s.env.DELEGATED_TOKENS_ENABLED = true
  s.actor = 'auth-mcp'
  s.resolve.mockReset()
  s.exchange.mockReset()
})

const tokenInfo = (token = 'ory_at_abcdefghijklmnop') =>
  app.inject({ method: 'POST', url: '/api/mcp/token-info', headers: { authorization: `Bearer ${token}`, 'x-actor-token': 'h.p.s' } })
const exchange = (key: string) =>
  app.inject({ method: 'POST', url: '/api/mcp/personal-keys/exchange', headers: { authorization: `Bearer ${key}`, 'x-actor-token': 'h.p.s' } })

describe('/api/mcp', () => {
  it('is 404 while DELEGATED_TOKENS_ENABLED is off, and 403 without an allowed actor', async () => {
    s.env.DELEGATED_TOKENS_ENABLED = false
    expect((await tokenInfo()).statusCode).toBe(404)
    s.env.DELEGATED_TOKENS_ENABLED = true
    s.actor = null
    expect((await tokenInfo()).statusCode).toBe(403)
    expect((await exchange('stk_mcp_pk.secret')).statusCode).toBe(403)
    expect(s.resolve).not.toHaveBeenCalled()
  })

  it('is 403 mcp_disabled (after the actor check) while an administrator turned MCP off', async () => {
    s.mcpConfig = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    const res = await tokenInfo()
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ error: 'mcp_disabled', message: 'MCP access is turned off by an administrator.' })
    expect((await exchange('stk_mcp_pk.secret')).json()).toMatchObject({ error: 'mcp_disabled' })
    expect(s.resolve).not.toHaveBeenCalled()
    expect(s.exchange).not.toHaveBeenCalled()
    s.actor = null
    expect((await tokenInfo()).json()).toMatchObject({ error: 'Forbidden' })
  })

  it("maps groups outside the administrator's scope to 403 mcp_disabled, for tokens and keys; 'cannot tell' to 503", async () => {
    s.resolve.mockResolvedValue({ error: 'mcp_group_not_allowed' })
    const res = await tokenInfo()
    expect(res.statusCode).toBe(403)
    expect(res.json()).toMatchObject({ error: 'mcp_disabled', reason: 'group_not_allowed' })
    s.resolve.mockResolvedValue({ error: 'authz_unavailable' })
    expect((await tokenInfo()).statusCode).toBe(503)
    s.exchange.mockRejectedValueOnce(new PersonalKeyRefused('mcp_group_not_allowed'))
    expect((await exchange('stk_mcp_pk.secret')).json()).toMatchObject({ error: 'mcp_disabled', reason: 'group_not_allowed' })
    s.exchange.mockRejectedValue(new PersonalKeyRefused('mcp_disabled'))
    const ex = await exchange('stk_mcp_pk.secret')
    expect(ex.statusCode).toBe(403)
    expect(ex.json()).toMatchObject({ error: 'mcp_disabled', reason: 'disabled' })
  })

  it('token-info answers the claims auth-mcp reads (OAuth token)', async () => {
    s.resolve.mockResolvedValue({ principal: {
      subject: 'user-1', email: 'ann@acme.io', name: 'Ann', clientId: 'claude', scopes: ['sites:read'], org: 'acme', kind: 'oauth',
      expiresAt: 1_900_000_000_000, tokenScope: 'mcp sites:read offline_access', aud: ['https://mcp.test'],
    } })
    const res = await tokenInfo()
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({
      active: true, token_use: 'access_token', scope: 'mcp sites:read offline_access', client_id: 'claude', sub: 'user-1',
      exp: 1_900_000_000, aud: ['https://mcp.test'], ext: { org: 'acme', email: 'ann@acme.io', kind: 'oauth' },
    })
  })

  it('token-info names the key and its holder for a personal-key token', async () => {
    s.resolve.mockResolvedValue({ principal: {
      subject: 'user-1', email: 'ann@acme.io', name: 'Ann', clientId: 'pk', scopes: ['users:read'], kind: 'personal', allPermissions: true,
      expiresAt: 1_900_000_000_000, keyExpiresAt: 1_900_500_000_000, tokenScope: 'users:read mcp', aud: ['https://mcp.test'],
    } })
    const body = (await tokenInfo()).json()
    // Bound to no org; the scope is the effective one (what the holder holds now).
    expect(body).toMatchObject({ sub: 'pk', client_id: 'pk', scope: 'users:read mcp', ext: { kind: 'personal', subject: 'user-1', key_id: 'pk', key_expires_at: 1_900_500_000, all_permissions: true } })
    expect(body.ext).not.toHaveProperty('org')
  })

  it('token-info is 401 for a refused token, a key, or no token', async () => {
    s.resolve.mockResolvedValue({ error: 'token_inactive' })
    expect((await tokenInfo()).json()).toMatchObject({ error: 'invalid_token', reason: 'token_inactive' })
    expect((await tokenInfo('stk_mcp_pk.secret')).statusCode).toBe(401)
  })

  it('exchange splits stk_mcp_<id>.<secret> on the first dot and answers the token', async () => {
    s.exchange.mockResolvedValue({ access_token: 'ory_at_x', expires_in: 600 })
    const res = await exchange('stk_mcp_pk-123.sec.ret')
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ access_token: 'ory_at_x', expires_in: 600 })
    expect(s.exchange).toHaveBeenCalledWith('pk-123', 'sec.ret')
  })

  it('exchange is 401 for a malformed or refused key', async () => {
    expect((await exchange('ory_at_notakey')).statusCode).toBe(401)
    expect((await exchange('stk_mcp_nodot')).statusCode).toBe(401)
    s.exchange.mockRejectedValue(new PersonalKeyRefused('key_expired'))
    expect((await exchange('stk_mcp_pk.secret')).json()).toMatchObject({ error: 'invalid_key', reason: 'key_expired' })
  })
})
