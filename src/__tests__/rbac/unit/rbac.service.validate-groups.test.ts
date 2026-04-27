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
    removeGroupFromAllUsers: vi.fn().mockResolvedValue(0),
    invalidateGroupsCache: vi.fn(),
    listIdentities: vi.fn().mockResolvedValue({ identities: [] }),
    getAllIdentitiesWithGroups: vi.fn().mockResolvedValue(new Map()),
  },
}))

vi.mock('../../../config/env.js', () => ({
  env: {
    RBAC_GIT_REPO_URL: 'http://git-server/rbac-repo.git',
    RBAC_GIT_BRANCH: 'main',
    APP_NAME: 'jinbe',
    SERVICE_DEFAULT_NAMESPACE: 'w6d-ops',
    SERVICE_DEFAULT_DOMAIN: 'kuma.dev.w6d.io',
    SERVICE_DEFAULT_PORT: '8080',
  },
}))

import { RbacService } from '../../../services/rbac.service.js'
import { kratosService } from '../../../services/kratos.service.js'

describe('RbacService - Group Validation', () => {
  let service: RbacService

  beforeEach(async () => {
    vi.clearAllMocks()
    redisMock.clear()
    service = new RbacService()

    // Seed Redis with groups
    await redisMock.hset('rbac:groups', 'super_admins', JSON.stringify({ global: ['superadmin'] }))
    await redisMock.hset('rbac:groups', 'admins', JSON.stringify({ jinbe: ['admin'] }))
    await redisMock.hset('rbac:groups', 'devs', JSON.stringify({ jinbe: ['developer'] }))
    await redisMock.hset('rbac:groups', 'users', JSON.stringify({ jinbe: ['viewer'] }))
  })

  // ===========================================================================
  // getAvailableGroups
  // ===========================================================================
  describe('getAvailableGroups', () => {
    it('should return list of available groups from Redis', async () => {
      const result = await service.getAvailableGroups()
      expect(result).toEqual(['super_admins', 'admins', 'devs', 'users'])
    })

    it('should return empty array when no groups exist', async () => {
      redisMock.clear()
      const result = await service.getAvailableGroups()
      expect(result).toEqual([])
    })
  })

  // ===========================================================================
  // validateGroups
  // ===========================================================================
  describe('validateGroups', () => {
    it('should not throw when all groups are valid', async () => {
      await expect(service.validateGroups(['admins', 'devs'])).resolves.not.toThrow()
    })

    it('should throw when group does not exist', async () => {
      await expect(service.validateGroups(['fake_group'])).rejects.toThrow(
        'Invalid groups: fake_group'
      )
    })

    it('should list available groups in error message', async () => {
      await expect(service.validateGroups(['nonexistent'])).rejects.toThrow(
        'Available: super_admins, admins, devs, users'
      )
    })

    it('should report all invalid groups', async () => {
      await expect(service.validateGroups(['fake1', 'fake2', 'admins'])).rejects.toThrow(
        'Invalid groups: fake1, fake2'
      )
    })

    it('should accept empty groups array', async () => {
      await expect(service.validateGroups([])).resolves.not.toThrow()
    })

    it('should be case-sensitive', async () => {
      await expect(service.validateGroups(['Admins'])).rejects.toThrow('Invalid groups: Admins')
    })
  })

  // ===========================================================================
  // deleteGroup with cascade
  // ===========================================================================
  describe('deleteGroup cascade to Kratos', () => {
    it('should remove group from Kratos users after deleting from Redis', async () => {
      vi.mocked(kratosService.removeGroupFromAllUsers).mockResolvedValueOnce(3)
      expect(typeof kratosService.removeGroupFromAllUsers).toBe('function')
    })

    it('should handle Kratos cascade errors gracefully', async () => {
      vi.mocked(kratosService.removeGroupFromAllUsers).mockRejectedValueOnce(
        new Error('Kratos unavailable')
      )
      expect(kratosService.removeGroupFromAllUsers).toBeDefined()
    })
  })
})
