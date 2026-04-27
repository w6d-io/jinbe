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
    listIdentities: vi.fn().mockResolvedValue({
      identities: [
        { id: 'user-1', traits: { email: 'admin@example.com', name: 'Admin User' }, state: 'active' },
        { id: 'user-2', traits: { email: 'dev@example.com', name: 'Developer User' }, state: 'active' },
        { id: 'user-3', traits: { email: 'viewer@example.com' }, state: 'active' },
      ],
      nextPageToken: undefined,
    }),
    getAllIdentitiesWithGroups: vi.fn().mockResolvedValue(
      new Map([
        ['admin@example.com', ['admins', 'devs']],
        ['dev@example.com', ['devs']],
        ['viewer@example.com', ['viewers']],
      ])
    ),
    removeGroupFromAllUsers: vi.fn().mockResolvedValue(0),
  },
}))

import { RbacService } from '../../../services/rbac.service.js'
import { kratosService } from '../../../services/kratos.service.js'

describe('RbacService - Users', () => {
  let service: RbacService

  beforeEach(async () => {
    vi.clearAllMocks()
    redisMock.clear()
    service = new RbacService()

    // Seed Redis with groups
    await redisMock.hset('rbac:groups', 'admins', JSON.stringify({ jinbe: ['admin'], kuma: ['admin'] }))
    await redisMock.hset('rbac:groups', 'infra', JSON.stringify({ jinbe: ['operator'], kuma: ['operator'] }))
    await redisMock.hset('rbac:groups', 'devs', JSON.stringify({ jinbe: ['editor', 'viewer'], kuma: ['editor'] }))
    await redisMock.hset('rbac:groups', 'viewers', JSON.stringify({ jinbe: ['viewer'], kuma: ['viewer'] }))
  })

  describe('getUsers', () => {
    it('should return all users with group memberships', async () => {
      const result = await service.getUsers()
      expect(result.users).toHaveLength(3)
      expect(result.users.map(u => u.email)).toContain('admin@example.com')
      expect(result.users.map(u => u.email)).toContain('dev@example.com')
      expect(result.users.map(u => u.email)).toContain('viewer@example.com')
    })

    it('should build group membership matrix correctly', async () => {
      const result = await service.getUsers()
      const adminUser = result.users.find(u => u.email === 'admin@example.com')
      expect(adminUser?.groupMembership).toEqual({
        admins: true,
        infra: false,
        devs: true,
        viewers: false,
      })
    })

    it('should handle simple array membership format', async () => {
      const result = await service.getUsers()
      const viewerUser = result.users.find(u => u.email === 'viewer@example.com')
      expect(viewerUser?.groupMembership.viewers).toBe(true)
    })

    it('should handle extended object membership format', async () => {
      const result = await service.getUsers()
      const devUser = result.users.find(u => u.email === 'dev@example.com')
      expect(devUser?.groupMembership.devs).toBe(true)
    })

    it('should enrich users with names from Kratos', async () => {
      const result = await service.getUsers()
      const adminUser = result.users.find(u => u.email === 'admin@example.com')
      expect(adminUser?.name).toBe('Admin User')
    })

    it('should continue without names if Kratos unavailable', async () => {
      vi.mocked(kratosService.listIdentities).mockRejectedValueOnce(new Error('Kratos unavailable'))
      const result = await service.getUsers()
      expect(result.users).toHaveLength(3)
      expect(result.users[0].name).toBeUndefined()
    })

    it('should return empty users array when Kratos returns no users', async () => {
      vi.mocked(kratosService.getAllIdentitiesWithGroups).mockResolvedValueOnce(new Map())
      const result = await service.getUsers()
      expect(result.users).toHaveLength(0)
    })

    it('should return empty users when Kratos has no identities', async () => {
      vi.mocked(kratosService.getAllIdentitiesWithGroups).mockResolvedValueOnce(new Map())
      const result = await service.getUsers()
      expect(result.users).toHaveLength(0)
    })
  })
})
