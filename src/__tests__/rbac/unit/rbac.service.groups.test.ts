import { describe, it, expect, beforeEach, vi } from 'vitest'

// Create hoisted mock that is available in vi.mock factories
const { redisMock, redisModule } = vi.hoisted(() => {
  // Inline minimal Redis mock for vi.mock hoisting
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
      redisClientService: {
        getClient: () => mock,
        isHealthy: vi.fn().mockResolvedValue(true),
        disconnect: vi.fn().mockResolvedValue(undefined),
        isConnected: true,
      },
      getRedisClient: () => mock,
    },
  }
})

vi.mock('../../../services/redis-client.service.js', () => redisModule)

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    listIdentities: vi.fn().mockResolvedValue({ identities: [] }),
    getAllIdentitiesWithGroups: vi.fn().mockResolvedValue(new Map()),
    removeGroupFromAllUsers: vi.fn().mockResolvedValue(0),
  },
}))

import { RbacService } from '../../../services/rbac.service.js'

describe('RbacService - Groups', () => {
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

  describe('getGroups', () => {
    it('should return all groups with service roles', async () => {
      const result = await service.getGroups()
      expect(result.groups).toHaveLength(4)
      expect(result.groups.map(g => g.name)).toContain('admins')
    })

    it('should return empty array when no groups exist', async () => {
      redisMock.clear()
      const result = await service.getGroups()
      expect(result.groups).toHaveLength(0)
    })
  })

  describe('createGroup', () => {
    it('should create new group with service roles', async () => {
      const result = await service.createGroup('test_group', { jinbe: ['viewer'] })
      expect(result.success).toBe(true)
      expect(result.message).toContain('test_group')
      expect(result.timestamp).toBeDefined()
    })

    it('should throw 409 when group already exists', async () => {
      await expect(
        service.createGroup('admins', { jinbe: ['viewer'] })
      ).rejects.toThrow('Group already exists: admins')
    })
  })

  describe('updateGroup', () => {
    it('should update existing group services', async () => {
      const result = await service.updateGroup('devs', { jinbe: ['admin'] })
      expect(result.success).toBe(true)
      expect(result.message).toContain('devs')
    })

    it('should throw 404 when group not found', async () => {
      await expect(
        service.updateGroup('nonexistent', {})
      ).rejects.toThrow('Group not found: nonexistent')
    })
  })

  describe('deleteGroup', () => {
    it('should remove group', async () => {
      const result = await service.deleteGroup('viewers')
      expect(result.success).toBe(true)
      expect(result.message).toContain('viewers')
    })

    it('should throw 404 when group not found', async () => {
      await expect(
        service.deleteGroup('nonexistent')
      ).rejects.toThrow('Group not found: nonexistent')
    })
  })
})
