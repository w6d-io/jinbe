import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createAccessRulesFixture, createOathkeeperRule } from '../fixtures/access-rules.fixture.js'

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

describe('RbacService - Access Rules', () => {
  let service: RbacService

  beforeEach(async () => {
    vi.clearAllMocks()
    redisMock.clear()
    service = new RbacService()

    // Seed Redis with access rules
    const rules = createAccessRulesFixture()
    await redisMock.set('rbac:oathkeeper:rules', JSON.stringify(rules))
  })

  describe('getAccessRules', () => {
    it('should return all Oathkeeper rules', async () => {
      const result = await service.getAccessRules()
      expect(result.rules.length).toBeGreaterThan(0)
      expect(result.rules.map(r => r.id)).toContain('jinbe')
    })
  })

  describe('getAccessRule', () => {
    it('should return specific rule by ID', async () => {
      const result = await service.getAccessRule('jinbe')
      expect(result.rule.id).toBe('jinbe')
    })

    it('should throw 404 when rule not found', async () => {
      await expect(service.getAccessRule('nonexistent')).rejects.toThrow('Access rule not found')
    })
  })

  describe('createAccessRule', () => {
    it('should add new rule to rules array', async () => {
      const newRule = createOathkeeperRule('newrule')
      const result = await service.createAccessRule(newRule)
      expect(result.success).toBe(true)
      expect(result.message).toContain('newrule')
      expect(result.timestamp).toBeDefined()
    })

    it('should throw 409 when rule ID already exists', async () => {
      const duplicateRule = createOathkeeperRule('jinbe')
      await expect(service.createAccessRule(duplicateRule)).rejects.toThrow("Access rule 'jinbe' already exists")
    })
  })

  describe('updateAccessRule', () => {
    it('should update existing rule', async () => {
      const updatedRule = createOathkeeperRule('jinbe', { upstream: { url: 'http://updated:9000' } })
      const result = await service.updateAccessRule('jinbe', updatedRule)
      expect(result.success).toBe(true)
      expect(result.message).toContain('jinbe')
    })

    it('should throw 404 when rule not found', async () => {
      const rule = createOathkeeperRule('nonexistent')
      await expect(service.updateAccessRule('nonexistent', rule)).rejects.toThrow('Access rule not found')
    })
  })

  describe('deleteAccessRule', () => {
    it('should remove rule from array', async () => {
      const result = await service.deleteAccessRule('jinbe')
      expect(result.success).toBe(true)
      expect(result.message).toContain('jinbe')
    })

    it('should throw 404 when rule not found', async () => {
      await expect(service.deleteAccessRule('nonexistent')).rejects.toThrow('Access rule not found')
    })
  })
})
