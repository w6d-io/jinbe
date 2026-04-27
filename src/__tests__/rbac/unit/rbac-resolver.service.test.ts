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

// Use vi.hoisted to create mock objects that can be referenced in vi.mock
const mocks = vi.hoisted(() => ({
  kratosService: {
    getUserGroups: vi.fn(),
  },
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: mocks.kratosService,
  KratosApiError: class KratosApiError extends Error {
    statusCode: number
    constructor(statusCode: number, message: string) {
      super(message)
      this.statusCode = statusCode
      this.name = 'KratosApiError'
    }
  },
}))

// Import after mocking
import { rbacResolverService } from '../../../services/rbac-resolver.service.js'
import { KratosApiError } from '../../../services/kratos.service.js'

describe('RbacResolverService', () => {
  // Sample test data
  const mockGroupsData: Record<string, Record<string, string[]>> = {
    super_admins: { global: ['superadmin'], jinbe: ['admin'] },
    admins: { jinbe: ['admin'], kuma_v2: ['admin'] },
    devs: { jinbe: ['editor', 'viewer'] },
    viewers: { jinbe: ['viewer'] },
  }

  const mockRolesData: Record<string, string[]> = {
    superadmin: ['*'],
    admin: ['*'],
    editor: ['read', 'write'],
    viewer: ['read'],
  }

  async function seedRedis() {
    for (const [name, def] of Object.entries(mockGroupsData)) {
      await redisMock.hset('rbac:groups', name, JSON.stringify(def))
    }
    await redisMock.set('rbac:roles:jinbe', JSON.stringify(mockRolesData))
  }

  beforeEach(async () => {
    vi.clearAllMocks()
    redisMock.clear()
    await seedRedis()
  })

  describe('resolveUserRbac', () => {
    it('should resolve groups from Kratos', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['super_admins'])
      const result = await rbacResolverService.resolveUserRbac('admin@example.com', 'jinbe')
      expect(result.groups).toEqual(['super_admins'])
      expect(mocks.kratosService.getUserGroups).toHaveBeenCalledWith('admin@example.com')
    })

    it('should resolve global roles from group definitions', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['super_admins'])
      const result = await rbacResolverService.resolveUserRbac('admin@example.com', 'jinbe')
      expect(result.roles).toContain('superadmin')
      expect(result.roles).toContain('admin')
    })

    it('should resolve service-specific roles from group definitions', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['devs'])
      const result = await rbacResolverService.resolveUserRbac('dev@example.com', 'jinbe')
      expect(result.roles).toContain('editor')
      expect(result.roles).toContain('viewer')
    })

    it('should resolve permissions from role definitions', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['super_admins'])
      const result = await rbacResolverService.resolveUserRbac('admin@example.com', 'jinbe')
      expect(result.permissions).toContain('*')
    })

    it('should handle role inheritance', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['devs'])
      const result = await rbacResolverService.resolveUserRbac('dev@example.com', 'jinbe')
      expect(result.permissions).toContain('read')
      expect(result.permissions).toContain('write')
    })

    it('should return default groups for unknown users', async () => {
      mocks.kratosService.getUserGroups.mockRejectedValueOnce(
        new KratosApiError(404, 'User not found')
      )
      const result = await rbacResolverService.resolveUserRbac('unknown@example.com', 'jinbe')
      expect(result.groups).toEqual(['users'])
    })

    it('should combine roles from multiple groups', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['admins', 'devs'])
      const result = await rbacResolverService.resolveUserRbac('user@example.com', 'jinbe')
      expect(result.roles).toContain('admin')
      expect(result.roles).toContain('editor')
      expect(result.roles).toContain('viewer')
    })

    it('should return empty roles/permissions for unknown group', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['nonexistent_group'])
      const result = await rbacResolverService.resolveUserRbac('user@example.com', 'jinbe')
      expect(result.groups).toEqual(['nonexistent_group'])
      expect(result.roles).toEqual([])
      expect(result.permissions).toEqual([])
    })

    it('should handle missing roles file gracefully', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['admins'])
      await redisMock.del('rbac:roles:jinbe')
      const result = await rbacResolverService.resolveUserRbac('user@example.com', 'jinbe')
      expect(result.groups).toEqual(['admins'])
      expect(result.roles).toContain('admin')
      expect(result.permissions).toEqual([])
    })

    it('should handle empty groups in Redis gracefully', async () => {
      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['admins'])
      redisMock.clear()
      const result = await rbacResolverService.resolveUserRbac('user@example.com', 'jinbe')
      expect(result.groups).toEqual(['admins'])
      expect(result.roles).toEqual([])
      expect(result.permissions).toEqual([])
    })
  })

  describe('edge cases', () => {
    it('should resolve permissions only for assigned roles (no inheritance)', async () => {
      const rolesData = { role_a: ['perm_a'], role_b: ['perm_b'] }
      const groupsDef = { test_group: { jinbe: ['role_a'] } }

      redisMock.clear()
      await redisMock.hset('rbac:groups', 'test_group', JSON.stringify(groupsDef.test_group))
      await redisMock.set('rbac:roles:jinbe', JSON.stringify(rolesData))

      mocks.kratosService.getUserGroups.mockResolvedValueOnce(['test_group'])
      const result = await rbacResolverService.resolveUserRbac('user@example.com', 'jinbe')

      expect(result.permissions).toContain('perm_a')
      expect(result.permissions).not.toContain('perm_b')
      expect(result.roles).toEqual(['role_a'])
    })
  })
})
