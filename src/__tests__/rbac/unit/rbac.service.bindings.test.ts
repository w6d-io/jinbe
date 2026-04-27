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
    removeGroupFromAllUsers: vi.fn().mockResolvedValue(0),
  },
}))

import { RbacService } from '../../../services/rbac.service.js'
import { kratosService } from '../../../services/kratos.service.js'

describe('RbacService - getBindingsFromKratos', () => {
  let service: RbacService

  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
    service = new RbacService()
  })

  it('should return bindings format with group_membership', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithGroups).mockResolvedValueOnce(
      new Map([
        ['admin@example.com', ['admins', 'users']],
        ['dev@example.com', ['devs', 'users']],
      ])
    )
    const result = await service.getBindingsFromKratos()
    expect(result).toEqual({
      emails: {},
      group_membership: {
        'admin@example.com': ['admins', 'users'],
        'dev@example.com': ['devs', 'users'],
      },
    })
  })

  it('should return empty group_membership when no identities', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithGroups).mockResolvedValueOnce(new Map())
    const result = await service.getBindingsFromKratos()
    expect(result).toEqual({ emails: {}, group_membership: {} })
  })

  it('should handle single user correctly', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithGroups).mockResolvedValueOnce(
      new Map([['solo@example.com', ['users']]])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.group_membership).toHaveProperty('solo@example.com')
    expect(result.group_membership['solo@example.com']).toEqual(['users'])
  })

  it('should propagate Kratos errors', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithGroups).mockRejectedValueOnce(
      new Error('Kratos unavailable')
    )
    await expect(service.getBindingsFromKratos()).rejects.toThrow('Kratos unavailable')
  })

  it('should handle users with multiple groups', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithGroups).mockResolvedValueOnce(
      new Map([['superuser@example.com', ['super_admins', 'admins', 'devs', 'users']]])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.group_membership['superuser@example.com']).toEqual([
      'super_admins', 'admins', 'devs', 'users',
    ])
  })

  it('should always include empty emails object', async () => {
    vi.mocked(kratosService.getAllIdentitiesWithGroups).mockResolvedValueOnce(
      new Map([['user@example.com', ['users']]])
    )
    const result = await service.getBindingsFromKratos()
    expect(result.emails).toEqual({})
    expect(Object.keys(result.emails)).toHaveLength(0)
  })
})
