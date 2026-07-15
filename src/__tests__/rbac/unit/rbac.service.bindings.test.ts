import { describe, it, expect, beforeEach, vi } from 'vitest'

const { redisMock, redisModule } = vi.hoisted(() => {
  class InlineRedisMock {
    private store = new Map<string, string>()
    private hashStore = new Map<string, Map<string, string>>()
    private setStore = new Map<string, Set<string>>()
    async get(key: string) { return this.store.get(key) ?? null }
    async set(key: string, value: string) { this.store.set(key, value); return 'OK' as const }
    async del(...keys: string[]) { let c = 0; for (const k of keys) { if (this.store.delete(k)) c++; if (this.hashStore.delete(k)) c++; if (this.setStore.delete(k)) c++ } return c }
    async hget(key: string, field: string) { return this.hashStore.get(key)?.get(field) ?? null }
    async hset(key: string, field: string, value: string) { if (!this.hashStore.has(key)) this.hashStore.set(key, new Map()); const isNew = !this.hashStore.get(key)!.has(field); this.hashStore.get(key)!.set(field, value); return isNew ? 1 : 0 }
    async hdel(key: string, ...fields: string[]) { const h = this.hashStore.get(key); if (!h) return 0; let c = 0; for (const f of fields) { if (h.delete(f)) c++ } return c }
    async hgetall(key: string) { const h = this.hashStore.get(key); if (!h) return {}; return Object.fromEntries(h.entries()) }
    async sadd(key: string, ...members: string[]) { if (!this.setStore.has(key)) this.setStore.set(key, new Set()); let c = 0; for (const m of members) { if (!this.setStore.get(key)!.has(m)) { this.setStore.get(key)!.add(m); c++ } } return c }
    async srem(key: string, ...members: string[]) { const s = this.setStore.get(key); if (!s) return 0; let c = 0; for (const m of members) { if (s.delete(m)) c++ } return c }
    async smembers(key: string) { const s = this.setStore.get(key); return s ? Array.from(s) : [] }
    async sismember(key: string, member: string) { const s = this.setStore.get(key); return s?.has(member) ? 1 : 0 }
    async ping() { return 'PONG' }
    async quit() { return 'OK' as const }
    clear() { this.store.clear(); this.hashStore.clear(); this.setStore.clear() }
  }
  const mock = new InlineRedisMock()
  return {
    redisMock: mock,
    redisModule: {
      redisClientService: { getClient: () => mock, isHealthy: vi.fn().mockResolvedValue(true), disconnect: vi.fn().mockResolvedValue(undefined), isConnected: true },
      getRedisClient: () => mock,
    },
  }
})

vi.mock('../../../services/redis-client.service.js', () => redisModule)

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    listIdentities: vi.fn().mockResolvedValue({ identities: [] }),
    getAllIdentitiesWithGroups: vi.fn(),
    getAllIdentitiesWithBindings: vi.fn(),
    removeGroupFromAllUsers: vi.fn().mockResolvedValue(0),
  },
}))

import { RbacService } from '../../../services/rbac.service.js'
import { kratosService } from '../../../services/kratos.service.js'

// Helper to build the per-identity binding shape the Kratos scan returns.
function binding(
  groups: string[],
  organizations: string[] = [],
  primaryOrganization: string | null = null,
) {
  return { groups, organizations, primaryOrganization }
}

describe('RbacService - getBindingsFromKratos', () => {
  let service: RbacService

  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
    service = new RbacService()
  })

  it('should return the full bindings shape with group_membership', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([
        ['admin@example.com', binding(['admins', 'users'])],
        ['dev@example.com', binding(['devs', 'users'])],
      ])
    )
    const result = await service.getBindingsFromKratos()
    expect(result).toEqual({
      emails: {},
      group_membership: {
        'admin@example.com': ['admins', 'users'],
        'dev@example.com': ['devs', 'users'],
      },
      user_organizations: {},
      user_organization_primary: {},
    })
  })

  it('should return empty maps when no identities', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(new Map())
    const result = await service.getBindingsFromKratos()
    expect(result).toEqual({
      emails: {},
      group_membership: {},
      user_organizations: {},
      user_organization_primary: {},
    })
  })

  it('should build user_organizations from metadata_admin.organizations', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([
        ['multi@example.com', binding(['users'], ['org-a', 'org-b'], null)],
      ])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.user_organizations).toEqual({ 'multi@example.com': ['org-a', 'org-b'] })
  })

  it('should union the primary org into user_organizations for legacy users (root organization_id only)', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([
        ['legacy@example.com', binding(['users'], [], 'org-c')],
      ])
    )
    const result = await service.getBindingsFromKratos()
    // No metadata_admin.organizations, but the primary org must still surface
    // so the tenant gate treats the user as a member of their own org.
    expect(result.user_organizations).toEqual({ 'legacy@example.com': ['org-c'] })
    expect(result.user_organization_primary).toEqual({ 'legacy@example.com': 'org-c' })
  })

  it('should dedupe the primary org when it already appears in metadata_admin.organizations', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([
        ['dupe@example.com', binding(['users'], ['org-a', 'org-b'], 'org-a')],
      ])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.user_organizations).toEqual({ 'dupe@example.com': ['org-a', 'org-b'] })
  })

  it('should append the primary org (order-stable) when not already a member', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([
        ['append@example.com', binding(['users'], ['org-a', 'org-b'], 'org-c')],
      ])
    )
    const result = await service.getBindingsFromKratos()
    // membership order preserved, primary appended last
    expect(result.user_organizations).toEqual({ 'append@example.com': ['org-a', 'org-b', 'org-c'] })
  })

  it('should build user_organization_primary from the primary organization', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([
        ['legacy@example.com', binding(['users'], [], 'org-c')],
      ])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.user_organization_primary).toEqual({ 'legacy@example.com': 'org-c' })
  })

  it('should omit users with no organizations and no primary org', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([
        ['orgless@example.com', binding(['users'], [], null)],
      ])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.group_membership).toHaveProperty('orgless@example.com')
    expect(result.user_organizations).toEqual({})
    expect(result.user_organization_primary).toEqual({})
  })

  it('should keep group_membership and org maps independent per user', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([
        ['multi@example.com', binding(['admins', 'users'], ['org-a'], 'org-a')],
        ['legacy@example.com', binding(['devs'], [], 'org-c')],
        ['orgless@example.com', binding(['users'], [], null)],
      ])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.group_membership).toEqual({
      'multi@example.com': ['admins', 'users'],
      'legacy@example.com': ['devs'],
      'orgless@example.com': ['users'],
    })
    // legacy's primary org is unioned in even though it has no
    // metadata_admin.organizations; orgless has neither, so it is omitted.
    expect(result.user_organizations).toEqual({
      'multi@example.com': ['org-a'],
      'legacy@example.com': ['org-c'],
    })
    expect(result.user_organization_primary).toEqual({
      'multi@example.com': 'org-a',
      'legacy@example.com': 'org-c',
    })
  })

  it('should propagate Kratos errors', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockRejectedValueOnce(
      new Error('Kratos unavailable')
    )
    await expect(service.getBindingsFromKratos()).rejects.toThrow('Kratos unavailable')
  })

  it('should always include an empty emails object', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithBindings).mockResolvedValueOnce(
      new Map([['user@example.com', binding(['users'])]])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.emails).toEqual({})
    expect(Object.keys(result.emails)).toHaveLength(0)
  })
})
