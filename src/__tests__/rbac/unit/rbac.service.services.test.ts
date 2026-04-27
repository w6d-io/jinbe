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
    getAllIdentitiesWithGroups: vi.fn().mockResolvedValue(new Map()),
    removeGroupFromAllUsers: vi.fn().mockResolvedValue(0),
  },
}))

import { RbacService } from '../../../services/rbac.service.js'

describe('RbacService - Services', () => {
  let service: RbacService

  beforeEach(async () => {
    vi.clearAllMocks()
    redisMock.clear()
    service = new RbacService()

    // Seed Redis with services registry
    await redisMock.sadd('rbac:services', 'jinbe', 'kuma')

    // Seed roles
    await redisMock.set('rbac:roles:jinbe', JSON.stringify({
      admin: ['*'],
      operator: ['read', 'write', 'execute'],
      editor: ['read', 'write'],
      viewer: ['read'],
    }))
    await redisMock.set('rbac:roles:kuma', JSON.stringify({
      admin: ['*'],
      operator: ['read', 'write', 'execute'],
      editor: ['read', 'write'],
      viewer: ['read'],
    }))

    // Seed route maps
    await redisMock.set('rbac:route_map:jinbe', JSON.stringify({
      rules: [{ method: 'GET', path: '/api/jinbe/health' }],
    }))
    await redisMock.set('rbac:route_map:kuma', JSON.stringify({
      rules: [{ method: 'GET', path: '/api/kuma/health' }],
    }))

    // Seed groups (needed for createService auto-population)
    await redisMock.hset('rbac:groups', 'admins', JSON.stringify({ jinbe: ['admin'], kuma: ['admin'] }))
    await redisMock.hset('rbac:groups', 'devs', JSON.stringify({ jinbe: ['editor'], kuma: ['editor'] }))

    // Seed access rules
    await redisMock.set('rbac:oathkeeper:rules', JSON.stringify([]))
  })

  describe('getServices', () => {
    it('should return list of services', async () => {
      const result = await service.getServices()
      expect(result.services).toHaveLength(2)
      expect(result.services.map(s => s.name)).toContain('jinbe')
    })

    it('should include rolesCount and routesCount', async () => {
      const result = await service.getServices()
      const jinbeService = result.services.find(s => s.name === 'jinbe')
      expect(jinbeService?.rolesCount).toBe(4)
      expect(jinbeService?.routesCount).toBe(1)
    })
  })

  describe('createService', () => {
    it('should create new service with roles, route_map, and Oathkeeper rules', async () => {
      const result = await service.createService({ name: 'newservice' })
      expect(result.success).toBe(true)
      expect(result.message).toContain('newservice')
      expect(result.timestamp).toBeDefined()
    })

    it('should throw 409 when service already exists', async () => {
      await expect(service.createService({ name: 'jinbe' })).rejects.toThrow('Service already exists')
    })
  })

  describe('deleteService', () => {
    it('should delete service and cascade from groups', async () => {
      const result = await service.deleteService('jinbe')
      expect(result.success).toBe(true)
      expect(result.message).toContain('jinbe')
    })

    it('should throw 404 when service not found', async () => {
      await expect(service.deleteService('nonexistent')).rejects.toThrow('Service not found')
    })
  })

  describe('getServiceRoles', () => {
    it('should return roles for specific service', async () => {
      const result = await service.getServiceRoles('jinbe')
      expect(result.service).toBe('jinbe')
      expect(result.roles).toHaveLength(4)
    })

    it('should throw 404 when service not found', async () => {
      await expect(service.getServiceRoles('nonexistent')).rejects.toThrow('Service not found')
    })
  })
})
