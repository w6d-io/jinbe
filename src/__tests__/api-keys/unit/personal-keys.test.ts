import { describe, it, expect, beforeEach, vi } from 'vitest'

// Personal keys: owned by the user, bound to no org, inheriting the holder — all their permissions by
// default, or a subset of what they hold — 30 days at most, only for groups allowed MCP. And the
// policy's client dataset leaves them out.

const s = vi.hoisted(() => ({
  mcpConfig: {} as Record<string, string>,
  env: { DELEGATED_TOKENS_ENABLED: true, DELEGATED_TOKEN_AUDIENCE: 'https://mcp.test' },
  hydra: { createClient: vi.fn(), getClient: vi.fn(), deleteClient: vi.fn(), listClientsByOwner: vi.fn(), listAllClients: vi.fn(), clientCredentialsToken: vi.fn() },
  identity: vi.fn(),
  catalog: vi.fn(async () => [] as { scope: string; group: string }[]),
  held: vi.fn(async () => ['admin:read', 'users:read'] as string[]),
  groups: ['staff'] as string[],
  used: vi.fn(),
  schedule: vi.fn(),
  touch: vi.fn(),
  forget: vi.fn(),
}))

vi.mock('../../../config/index.js', () => ({ env: s.env }))
// The MCP setting (mcp/settings.ts) read from rbac:config — unset is OFF, so each test saves it on (every group).
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => s.mcpConfig, setConfig: vi.fn() } }))
vi.mock('../../../services/hydra.service.js', () => {
  class HydraApiError extends Error { constructor(public statusCode: number, m: string) { super(m) } }
  return { hydraService: s.hydra, HydraApiError }
})
vi.mock('../../../authz/opa.js', () => ({ rights: vi.fn(async () => ({ groups: s.groups, roles: [], permissions: [] })) }))
vi.mock('../../../services/opal-publisher.js', () => ({ opalPublisher: { schedule: s.schedule } }))
vi.mock('../../../services/api-key-scopes.js', () => ({
  scopeCatalog: vi.fn(async () => []),
  // The expansion itself is api-key-scopes.test.ts's: here, a key's scopes as they stand.
  loadKeyModel: vi.fn(async () => ({})),
  expandScopes: vi.fn((_m: unknown, _org: string, scopes: string[]) => [...scopes].sort()),
  expandScope: vi.fn((_m: unknown, _org: string, scope: string) => [scope]),
}))
// What the holder holds (services/platform-scopes.ts, tested on its own).
vi.mock('../../../services/platform-scopes.js', () => ({ personalScopeCatalog: s.catalog, platformScopes: s.held }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: { getIdentity: s.identity } }))
vi.mock('../../../audit/record.js', () => ({ recordApiKeyUse: s.used }))
vi.mock('../../../services/api-key-last-used.js', () => ({ touchApiKeyUse: s.touch, forgetApiKeyUse: s.forget }))

import { personalKeyService, PersonalKeyRefused } from '../../../services/personal-key.service.js'
import { apiClientsDataset, apiClientsChanged, resetApiClients } from '../../../services/api-clients.js'
import { personalKeyCreateBodySchema } from '../../../schemas/api-key.schema.js'
import { resetMcpSettingsCache } from '../../../mcp/settings.js'

const ME = { id: 'user-1', email: 'ann@acme.io' }

beforeEach(() => {
  s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
  resetMcpSettingsCache()
  Object.values(s.hydra).forEach((f) => f.mockReset())
  s.groups = ['staff']
  s.held.mockReset().mockResolvedValue(['admin:read', 'users:read'])
  resetApiClients()
})

describe('personal key body', () => {
  it('scopes are optional (all my permissions), never empty when given; the expiry at most 30 days', () => {
    expect(personalKeyCreateBodySchema.parse({ label: 'x' })).toEqual({ label: 'x' })
    expect(() => personalKeyCreateBodySchema.parse({ label: 'x', scopes: [] })).toThrow()
    expect(personalKeyCreateBodySchema.parse({ label: 'x', scopes: ['a:read'] }).expires_in_days).toBeUndefined()
    expect(() => personalKeyCreateBodySchema.parse({ label: 'x', scopes: ['a:read'], expires_in_days: 31 })).toThrow()
  })
})

const created = (meta: Record<string, unknown> = {}, scope = 'mcp') =>
  ({ client_id: 'pk', client_secret: 'once', scope, metadata: { kind: 'personal', subject: 'user-1', scope_mode: 'all', expires_at: '2026-10-05T00:00:00Z', ...meta } })

describe('PersonalKeyService', () => {
  it('by default creates an "all my permissions" key: user-owned, no org, audience-bound, with an expiry', async () => {
    s.hydra.createClient.mockResolvedValue(created())
    const out = await personalKeyService.create(ME, { label: 'laptop', expires_in_days: 7 })
    const arg = s.hydra.createClient.mock.calls[0][0]
    // No permission is registered: jinbe computes them at each call. `mcp` rides along for auth-mcp.
    expect(arg).toMatchObject({ personal: { subject: 'user-1', allPermissions: true }, audience: ['https://mcp.test'], scopes: ['mcp'] })
    expect(arg.organizationId).toBeUndefined()
    expect(Date.parse(arg.expiresAt) - Date.now()).toBeLessThanOrEqual(7 * 86_400_000)
    expect(out).toMatchObject({ client_secret: 'once', kind: 'personal', organization_id: null, all_permissions: true, scopes: [], created_by_email: 'ann@acme.io', key: 'stk_mcp_pk.once' })
  })

  it('narrows to a subset of what the holder holds, and refuses anything else', async () => {
    s.hydra.createClient.mockResolvedValue(created({ scope_mode: 'selected' }, 'users:read mcp'))
    const out = await personalKeyService.create(ME, { label: 'x', scopes: ['users:read'] })
    expect(s.hydra.createClient.mock.calls[0][0]).toMatchObject({ scopes: ['users:read', 'mcp'], personal: { allPermissions: false } })
    expect(out).toMatchObject({ all_permissions: false, scopes: ['users:read'] })

    s.hydra.createClient.mockClear()
    await expect(personalKeyService.create(ME, { label: 'x', scopes: ['users:read', 'audit:read', '*'] }))
      .rejects.toMatchObject({ statusCode: 400, details: { invalid_scopes: ['audit:read', '*'] } })
    expect(s.hydra.createClient).not.toHaveBeenCalled()
  })

  it("defaults to the administrator's maximum and refuses longer (mcp settings)", async () => {
    s.hydra.createClient.mockResolvedValue(created())
    await personalKeyService.create(ME, { label: 'x' })
    const days = (Date.parse(s.hydra.createClient.mock.calls[0][0].expiresAt) - Date.now()) / 86_400_000
    expect(Math.round(days)).toBe(30)

    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, personalKeys: { maxDays: 5 } }) }
    resetMcpSettingsCache()
    s.hydra.createClient.mockClear()
    await expect(personalKeyService.create(ME, { label: 'x', expires_in_days: 7 })).rejects.toMatchObject({ statusCode: 400, details: { reason: 'expiry_too_long', max_days: 5 } })
    expect(s.hydra.createClient).not.toHaveBeenCalled()
    await personalKeyService.create(ME, { label: 'x' })
    expect(Math.round((Date.parse(s.hydra.createClient.mock.calls[0][0].expiresAt) - Date.now()) / 86_400_000)).toBe(5)
  })

  it('refuses while an administrator turned MCP off (404), or for groups outside its scope (403)', async () => {
    s.mcpConfig = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.create(ME, { label: 'x' })).rejects.toMatchObject({ statusCode: 404, details: { reason: 'mcp_disabled' } })
    await expect(personalKeyService.scopes(ME)).rejects.toMatchObject({ statusCode: 404 })
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, allowedGroups: ['support'] }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.create(ME, { label: 'x' })).rejects.toMatchObject({ statusCode: 403, details: { reason: 'mcp_group_not_allowed' } })
    await expect(personalKeyService.scopes(ME)).rejects.toMatchObject({ statusCode: 403 })
    expect(s.hydra.createClient).not.toHaveBeenCalled()
    s.groups = ['staff', 'support']
    s.hydra.createClient.mockResolvedValue(created())
    await expect(personalKeyService.create(ME, { label: 'x' })).resolves.toMatchObject({ kind: 'personal' })
  })

  it('lists and revokes only the caller\'s own personal keys; an older org-bound key shows its org as data only', async () => {
    const mine = { client_id: 'pk', scope: 'payroll:read mcp', metadata: { kind: 'personal', subject: 'user-1', organization_id: 'acme' } }
    const orgKey = { client_id: 'ok', metadata: { organization_id: 'acme' } }
    s.hydra.listClientsByOwner.mockResolvedValue([mine, orgKey])
    expect(await personalKeyService.list('user-1')).toMatchObject([{ client_id: 'pk', organization_id: 'acme', all_permissions: false, scopes: ['payroll:read'] }])
    expect(s.hydra.listClientsByOwner).toHaveBeenCalledWith('user:user-1')

    s.hydra.getClient.mockResolvedValue(mine)
    await expect(personalKeyService.revoke('user-2', 'pk')).rejects.toMatchObject({ statusCode: 404 })
    s.hydra.getClient.mockResolvedValue(orgKey)
    await expect(personalKeyService.revoke('user-1', 'ok')).rejects.toMatchObject({ statusCode: 404 })
    expect(s.hydra.deleteClient).not.toHaveBeenCalled()
    s.hydra.getClient.mockResolvedValue(mine)
    await personalKeyService.revoke('user-1', 'pk')
    expect(s.hydra.deleteClient).toHaveBeenCalledWith('pk')
    expect(s.forget).toHaveBeenCalledWith('pk')
  })

  it('offers the catalog of what the caller holds, no org asked', async () => {
    s.catalog.mockReset().mockResolvedValue([{ scope: 'users:read', group: 'users' }])
    expect(await personalKeyService.scopes(ME)).toEqual([{ scope: 'users:read', group: 'users' }])
    expect(s.catalog).toHaveBeenCalledWith('ann@acme.io')
  })
})

describe('PersonalKeyService.exchange', () => {
  const NOW = Date.parse('2026-09-28T12:00:00Z')
  const key = (over: Record<string, unknown> = {}, scope = 'admin:read audit:read mcp') => ({
    client_id: 'pk', scope,
    metadata: { kind: 'personal', subject: 'user-1', scope_mode: 'selected', expires_at: '2026-09-28T12:05:00Z', ...over },
  })
  beforeEach(() => {
    s.identity.mockReset().mockResolvedValue({ id: 'user-1', state: 'active', traits: { email: 'ann@acme.io' } })
    s.hydra.clientCredentialsToken.mockResolvedValue({ access_token: 'ory_at_x', expires_in: 600 })
  })

  it("a narrowed key: the stored scopes the holder STILL holds, plus mcp, for the delegated audience, capped at the key's expiry", async () => {
    s.hydra.getClient.mockResolvedValue(key())
    const out = await personalKeyService.exchange('pk', 'secret', NOW)
    expect(s.hydra.clientCredentialsToken).toHaveBeenCalledWith('pk', 'secret', ['admin:read', 'mcp'], 'https://mcp.test')
    expect(out).toEqual({ access_token: 'ory_at_x', expires_in: 300 })
    expect(s.held).toHaveBeenCalledWith('ann@acme.io')
    expect(s.used).toHaveBeenCalledWith('pk', null)
    expect(s.touch).toHaveBeenCalledWith('pk')
  })

  it('an all-permissions key: mcp alone — its permissions are computed at each call', async () => {
    s.hydra.getClient.mockResolvedValue(key({ scope_mode: 'all' }, 'mcp'))
    await personalKeyService.exchange('pk', 'secret', NOW)
    expect(s.hydra.clientCredentialsToken).toHaveBeenCalledWith('pk', 'secret', ['mcp'], 'https://mcp.test')
  })

  it.each([
    ['an org machine key', { kind: undefined }, 'not_a_personal_key'],
    ['an expired key', { expires_at: '2026-09-28T11:00:00Z' }, 'key_expired'],
  ])('refuses %s', async (_l, over, reason) => {
    s.hydra.getClient.mockResolvedValue(key(over))
    await expect(personalKeyService.exchange('pk', 'secret', NOW)).rejects.toEqual(new PersonalKeyRefused(reason))
    expect(s.hydra.clientCredentialsToken).not.toHaveBeenCalled()
  })

  it('refuses while MCP is switched off or the holder\'s groups are out of scope, and works again once back — the key is kept', async () => {
    s.hydra.getClient.mockResolvedValue(key())
    s.mcpConfig = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toEqual(new PersonalKeyRefused('mcp_disabled'))
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, allowedGroups: ['support'] }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toEqual(new PersonalKeyRefused('mcp_group_not_allowed'))
    expect(s.hydra.clientCredentialsToken).not.toHaveBeenCalled()
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.exchange('pk', 's', NOW)).resolves.toMatchObject({ access_token: 'ory_at_x' })
    expect(s.hydra.deleteClient).not.toHaveBeenCalled()
  })

  it('refuses an unknown key, a disabled holder, and a wrong secret', async () => {
    const { HydraApiError } = await import('../../../services/hydra.service.js')
    s.hydra.getClient.mockRejectedValue(new HydraApiError(404, 'gone'))
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toMatchObject({ reason: 'unknown_key' })
    s.hydra.getClient.mockResolvedValue(key())
    s.identity.mockResolvedValueOnce({ id: 'user-1', state: 'inactive', traits: { email: 'ann@acme.io' } })
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toMatchObject({ reason: 'subject_inactive' })
    s.hydra.clientCredentialsToken.mockRejectedValueOnce(new HydraApiError(401, 'bad secret'))
    await expect(personalKeyService.exchange('pk', 'wrong', NOW)).rejects.toMatchObject({ reason: 'key_refused' })
  })
})

describe('data.api_clients', () => {
  it('lists org keys by client_id with org, expanded scopes and expiry — never personal or org-less clients', async () => {
    s.hydra.listAllClients.mockResolvedValue([
      { client_id: 'ci', scope: 'payroll:write payroll:read', metadata: { organization_id: 'acme', expires_at: '2027-01-01T00:00:00Z' } },
      { client_id: 'pk', scope: 'payroll:read', metadata: { organization_id: 'acme', kind: 'personal', subject: 'u' } },
      { client_id: 'kuma-login', scope: 'openid', metadata: {} },
    ])
    expect(await apiClientsDataset()).toEqual({ ci: {
      org: 'acme',
      scopes: ['payroll:read', 'payroll:write'],
      by_scope: { 'payroll:write': ['payroll:write'], 'payroll:read': ['payroll:read'] },
      expires_at: '2027-01-01T00:00:00Z',
    } })
  })

  it('is cached briefly, dropped and pushed on a change', async () => {
    s.hydra.listAllClients.mockResolvedValue([])
    await apiClientsDataset()
    await apiClientsDataset()
    expect(s.hydra.listAllClients).toHaveBeenCalledTimes(1)
    apiClientsChanged('api_key.created')
    expect(s.schedule).toHaveBeenCalledWith('api_key.created')
    await apiClientsDataset()
    expect(s.hydra.listAllClients).toHaveBeenCalledTimes(2)
  })
})

describe('nextPageToken', () => {
  it('reads rel="next" and stops on the last page', async () => {
    const { nextPageToken } = await vi.importActual<typeof import('../../../services/hydra.service.js')>('../../../services/hydra.service.js')
    expect(nextPageToken('</admin/clients?page_size=500&page_token=abc>; rel="next", </admin/clients?page_token=zzz>; rel="first"')).toBe('abc')
    expect(nextPageToken('</admin/clients?page_token=zzz>; rel="first"')).toBeNull()
    expect(nextPageToken(null)).toBeNull()
  })
})
