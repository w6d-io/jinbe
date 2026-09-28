import { describe, it, expect, beforeEach, vi } from 'vitest'

// Personal keys: owned by the user, scoped to one org they belong to, scopes ⊆ what they hold there,
// 30 days at most, refused when the org forbids them. And the policy's client dataset leaves them out.

const s = vi.hoisted(() => ({
  mcpConfig: {} as Record<string, string>,
  env: { DELEGATED_TOKENS_ENABLED: true, DELEGATED_TOKEN_AUDIENCE: 'https://mcp.test' },
  hydra: { createClient: vi.fn(), getClient: vi.fn(), deleteClient: vi.fn(), listClientsByOwner: vi.fn(), listAllClients: vi.fn(), clientCredentialsToken: vi.fn() },
  identity: vi.fn(),
  catalog: vi.fn(async () => [] as { scope: string; sites: string[]; kind?: string }[]),
  used: vi.fn(),
  validate: vi.fn(async () => {}),
  policy: vi.fn(async () => ({ personal_keys: 'allowed' })),
  superAdmin: vi.fn(async () => false),
  memberOrgs: vi.fn(async () => ['acme']),
  schedule: vi.fn(),
  touch: vi.fn(),
  forget: vi.fn(),
}))

vi.mock('../../../config/index.js', () => ({ env: s.env }))
// The MCP setting (mcp/settings.ts) read from rbac:config — unset is OFF, so each test saves it on (every org).
vi.mock('../../../services/redis-rbac.repository.js', () => ({ redisRbacRepository: { getConfig: async () => s.mcpConfig, setConfig: vi.fn() } }))
vi.mock('../../../services/hydra.service.js', () => {
  class HydraApiError extends Error { constructor(public statusCode: number, m: string) { super(m) } }
  return { hydraService: s.hydra, HydraApiError }
})
vi.mock('../../../services/api-key-policy.js', () => ({ getApiKeyPolicy: s.policy }))
vi.mock('../../../authz/opa.js', () => ({ isSuperAdmin: s.superAdmin, memberOrgs: s.memberOrgs }))
vi.mock('../../../services/opal-publisher.js', () => ({ opalPublisher: { schedule: s.schedule } }))
vi.mock('../../../services/api-key-scopes.js', () => ({ scopeCatalog: vi.fn(async () => []) }))
// Site ∪ jinbe permissions (services/platform-scopes.ts, tested on its own).
vi.mock('../../../services/platform-scopes.js', () => ({ personalScopeCatalog: s.catalog }))
vi.mock('../../../services/kratos.service.js', () => ({ kratosService: { getIdentity: s.identity } }))
vi.mock('../../../audit/record.js', () => ({ recordApiKeyUse: s.used }))
vi.mock('../../../services/api-key-last-used.js', () => ({ touchApiKeyUse: s.touch, forgetApiKeyUse: s.forget }))

import { personalKeyService, PersonalKeyRefused } from '../../../services/personal-key.service.js'
import { apiKeyService } from '../../../services/api-key.service.js'
import { apiClientsDataset, apiClientsChanged, resetApiClients } from '../../../services/api-clients.js'
import { personalKeyCreateBodySchema } from '../../../schemas/api-key.schema.js'
import { resetMcpSettingsCache } from '../../../mcp/settings.js'

const ME = { id: 'user-1', email: 'ann@acme.io' }
const ORG = '11111111-1111-1111-1111-111111111111'

beforeEach(() => {
  s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
  resetMcpSettingsCache()
  Object.values(s.hydra).forEach((f) => f.mockReset())
  s.policy.mockReset().mockResolvedValue({ personal_keys: 'allowed' })
  s.memberOrgs.mockReset().mockResolvedValue([ORG])
  s.superAdmin.mockReset().mockResolvedValue(false)
  vi.spyOn(apiKeyService, 'validateScopes').mockImplementation(s.validate)
  s.validate.mockReset().mockResolvedValue(undefined)
  resetApiClients()
})

describe('personal key body', () => {
  it('leaves the expiry to the service when absent, and refuses more than 30 days', () => {
    expect(personalKeyCreateBodySchema.parse({ label: 'x', organization_id: ORG, scopes: ['a:read'] }).expires_in_days).toBeUndefined()
    expect(() => personalKeyCreateBodySchema.parse({ label: 'x', organization_id: ORG, scopes: ['a:read'], expires_in_days: 31 })).toThrow()
  })
})

describe('PersonalKeyService', () => {
  const body = { label: 'laptop', organization_id: ORG, scopes: ['payroll:read'], expires_in_days: 7 }

  it('creates a user-owned client bound to the org, audience-bound, with an expiry', async () => {
    s.hydra.createClient.mockResolvedValue({ client_id: 'pk', client_secret: 'once', scope: 'payroll:read', metadata: { organization_id: ORG, kind: 'personal', subject: 'user-1', expires_at: '2026-10-05T00:00:00Z' } })
    const out = await personalKeyService.create(ME, body)
    expect(s.validate).toHaveBeenCalledWith(ORG, 'ann@acme.io', ['payroll:read'], s.catalog)
    const arg = s.hydra.createClient.mock.calls[0][0]
    // `mcp` rides along so auth-mcp accepts the key's tokens.
    expect(arg).toMatchObject({ organizationId: ORG, personal: { subject: 'user-1' }, audience: ['https://mcp.test'], scopes: ['payroll:read', 'mcp'] })
    expect(Date.parse(arg.expiresAt) - Date.now()).toBeLessThanOrEqual(7 * 86_400_000)
    expect(out).toMatchObject({ client_secret: 'once', kind: 'personal', created_by_email: 'ann@acme.io', last_used_at: null, expires_at: '2026-10-05T00:00:00Z', key: 'stk_mcp_pk.once' })
  })

  it('refuses a non-member, and an org that forbids personal keys, before touching Hydra', async () => {
    s.memberOrgs.mockResolvedValue(['other'])
    await expect(personalKeyService.create(ME, body)).rejects.toMatchObject({ statusCode: 403 })
    s.memberOrgs.mockResolvedValue([ORG])
    s.policy.mockResolvedValue({ personal_keys: 'forbidden' })
    await expect(personalKeyService.create(ME, body)).rejects.toMatchObject({ statusCode: 403, details: { reason: 'personal_keys_forbidden' } })
    expect(s.hydra.createClient).not.toHaveBeenCalled()
  })

  it("defaults to the administrator's maximum and refuses longer (mcp settings)", async () => {
    s.hydra.createClient.mockResolvedValue({ client_id: 'pk', client_secret: 'once', scope: 'payroll:read', metadata: { organization_id: ORG, kind: 'personal', subject: 'user-1' } })
    await personalKeyService.create(ME, { ...body, expires_in_days: undefined })
    const days = (Date.parse(s.hydra.createClient.mock.calls[0][0].expiresAt) - Date.now()) / 86_400_000
    expect(Math.round(days)).toBe(30)

    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, personalKeys: { maxDays: 5 } }) }
    resetMcpSettingsCache()
    s.hydra.createClient.mockClear()
    await expect(personalKeyService.create(ME, body)).rejects.toMatchObject({ statusCode: 400, details: { reason: 'expiry_too_long', max_days: 5 } })
    expect(s.hydra.createClient).not.toHaveBeenCalled()
    await personalKeyService.create(ME, { ...body, expires_in_days: undefined })
    expect(Math.round((Date.parse(s.hydra.createClient.mock.calls[0][0].expiresAt) - Date.now()) / 86_400_000)).toBe(5)
  })

  it('refuses while an administrator turned MCP off (404), or for an org outside its scope (403)', async () => {
    s.mcpConfig = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.create(ME, body)).rejects.toMatchObject({ statusCode: 404, details: { reason: 'mcp_disabled' } })
    await expect(personalKeyService.scopes(ME, ORG)).rejects.toMatchObject({ statusCode: 404 })
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, allowedOrgs: ['22222222-2222-2222-2222-222222222222'] }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.create(ME, body)).rejects.toMatchObject({ statusCode: 403, details: { reason: 'mcp_org_not_allowed' } })
    expect(s.hydra.createClient).not.toHaveBeenCalled()
  })

  it('lists and revokes only the caller\'s own personal keys', async () => {
    const mine = { client_id: 'pk', metadata: { kind: 'personal', subject: 'user-1', organization_id: ORG } }
    const orgKey = { client_id: 'ok', metadata: { organization_id: ORG } }
    s.hydra.listClientsByOwner.mockResolvedValue([mine, orgKey])
    expect((await personalKeyService.list('user-1')).map((k) => k.client_id)).toEqual(['pk'])
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

  it('offers the catalog of what the caller holds in the org, to a member or super_admin only', async () => {
    s.catalog.mockReset().mockResolvedValue([{ scope: 'payroll:read', sites: ['payroll'] }])
    expect(await personalKeyService.scopes(ME, ORG)).toEqual([{ scope: 'payroll:read', sites: ['payroll'] }])
    expect(s.catalog).toHaveBeenCalledWith(ORG, 'ann@acme.io')

    s.catalog.mockClear()
    s.memberOrgs.mockResolvedValue(['other'])
    await expect(personalKeyService.scopes(ME, ORG)).rejects.toMatchObject({ statusCode: 403 })
    expect(s.catalog).not.toHaveBeenCalled()
    s.superAdmin.mockResolvedValue(true)
    await expect(personalKeyService.scopes(ME, ORG)).resolves.toHaveLength(1)
  })
})

describe('PersonalKeyService.exchange', () => {
  const NOW = Date.parse('2026-09-28T12:00:00Z')
  const key = (over: Record<string, unknown> = {}) => ({
    client_id: 'pk', scope: 'payroll:read payroll:write mcp',
    metadata: { kind: 'personal', subject: 'user-1', organization_id: ORG, expires_at: '2026-09-28T12:05:00Z', ...over },
  })
  beforeEach(() => {
    s.identity.mockReset().mockResolvedValue({ id: 'user-1', state: 'active', traits: { email: 'ann@acme.io' } })
    s.catalog.mockReset().mockResolvedValue([{ scope: 'payroll:read', sites: ['payroll'] }])
    s.hydra.clientCredentialsToken.mockResolvedValue({ access_token: 'ory_at_x', expires_in: 600 })
  })

  it("asks Hydra for the stored scopes the holder STILL holds, plus mcp, for the delegated audience, capped at the key's expiry", async () => {
    s.hydra.getClient.mockResolvedValue(key())
    const out = await personalKeyService.exchange('pk', 'secret', NOW)
    expect(s.hydra.clientCredentialsToken).toHaveBeenCalledWith('pk', 'secret', ['payroll:read', 'mcp'], 'https://mcp.test')
    expect(out).toEqual({ access_token: 'ory_at_x', expires_in: 300 })
    expect(s.catalog).toHaveBeenCalledWith(ORG, 'ann@acme.io')
    expect(s.used).toHaveBeenCalledWith('pk', ORG)
    expect(s.touch).toHaveBeenCalledWith('pk')
  })

  it('re-checks jinbe permissions the same way: a platform scope the holder lost is dropped', async () => {
    s.hydra.getClient.mockResolvedValue({ ...key(), scope: 'admin:read users:read org:manage_users mcp' })
    s.catalog.mockResolvedValue([{ scope: 'admin:read', sites: ['platform'], kind: 'platform' }, { scope: 'org:manage_users', sites: ['platform'], kind: 'platform' }])
    await personalKeyService.exchange('pk', 'secret', NOW)
    expect(s.hydra.clientCredentialsToken).toHaveBeenCalledWith('pk', 'secret', ['admin:read', 'org:manage_users', 'mcp'], 'https://mcp.test')
  })

  it.each([
    ['an org machine key', { kind: undefined }, 'not_a_personal_key'],
    ['an expired key', { expires_at: '2026-09-28T11:00:00Z' }, 'key_expired'],
  ])('refuses %s', async (_l, over, reason) => {
    s.hydra.getClient.mockResolvedValue(key(over))
    await expect(personalKeyService.exchange('pk', 'secret', NOW)).rejects.toEqual(new PersonalKeyRefused(reason))
    expect(s.hydra.clientCredentialsToken).not.toHaveBeenCalled()
  })

  it('refuses while MCP is switched off or the org is out of scope, and works again once back on — the key is kept', async () => {
    s.hydra.getClient.mockResolvedValue(key())
    s.mcpConfig = { mcp: JSON.stringify({ enabled: false }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toEqual(new PersonalKeyRefused('mcp_disabled'))
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true, allowedOrgs: ['22222222-2222-2222-2222-222222222222'] }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toEqual(new PersonalKeyRefused('mcp_org_not_allowed'))
    expect(s.hydra.clientCredentialsToken).not.toHaveBeenCalled()
    s.mcpConfig = { mcp: JSON.stringify({ enabled: true }) }
    resetMcpSettingsCache()
    await expect(personalKeyService.exchange('pk', 's', NOW)).resolves.toMatchObject({ access_token: 'ory_at_x' })
    expect(s.hydra.deleteClient).not.toHaveBeenCalled()
  })

  it('refuses an unknown key, a forbidden org, a disabled holder, and a wrong secret', async () => {
    const { HydraApiError } = await import('../../../services/hydra.service.js')
    s.hydra.getClient.mockRejectedValue(new HydraApiError(404, 'gone'))
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toMatchObject({ reason: 'unknown_key' })
    s.hydra.getClient.mockResolvedValue(key())
    s.policy.mockResolvedValueOnce({ personal_keys: 'forbidden' })
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toMatchObject({ reason: 'personal_keys_forbidden' })
    s.identity.mockResolvedValueOnce({ id: 'user-1', state: 'inactive', traits: { email: 'ann@acme.io' } })
    await expect(personalKeyService.exchange('pk', 's', NOW)).rejects.toMatchObject({ reason: 'subject_inactive' })
    s.hydra.clientCredentialsToken.mockRejectedValueOnce(new HydraApiError(401, 'bad secret'))
    await expect(personalKeyService.exchange('pk', 'wrong', NOW)).rejects.toMatchObject({ reason: 'key_refused' })
  })
})

describe('data.api_clients', () => {
  it('lists org keys by client_id with org, sorted scopes and expiry — never personal or org-less clients', async () => {
    s.hydra.listAllClients.mockResolvedValue([
      { client_id: 'ci', scope: 'payroll:write payroll:read', metadata: { organization_id: 'acme', expires_at: '2027-01-01T00:00:00Z' } },
      { client_id: 'pk', scope: 'payroll:read', metadata: { organization_id: 'acme', kind: 'personal', subject: 'u' } },
      { client_id: 'kuma-login', scope: 'openid', metadata: {} },
    ])
    expect(await apiClientsDataset()).toEqual({ ci: { org: 'acme', scopes: ['payroll:read', 'payroll:write'], expires_at: '2027-01-01T00:00:00Z' } })
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
