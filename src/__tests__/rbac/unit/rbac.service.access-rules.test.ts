import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  createAccessRulesFixture,
  createOathkeeperRule,
  createJwtAuthRule,
} from '../fixtures/access-rules.fixture.js'

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
import { env } from '../../../config/env.js'

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

  // Fail-closed guard: with the default enabled sets (cookie_session,noop /
  // allow,remote_json / noop,header / redirect,json), a rule referencing any
  // other handler must be rejected before it can reach Redis — otherwise
  // Oathkeeper would reject the whole ruleset at load and drop the gateway.
  describe('fail-closed handler validation', () => {
    it('should reject creating a rule with a non-enabled authenticator (jwt) as 400', async () => {
      const badRule = createJwtAuthRule('jwt-service')
      await expect(service.createAccessRule(badRule)).rejects.toMatchObject({
        statusCode: 400,
        message: expect.stringContaining("'jwt'"),
      })
      // and it names the allowed options for that stage
      await expect(service.createAccessRule(badRule)).rejects.toThrow(/cookie_session/)
      // nothing was written
      const after = await service.getAccessRules()
      expect(after.rules.map((r) => r.id)).not.toContain('jwt-service')
    })

    it('should reject updating an existing rule to use a non-enabled handler as 400', async () => {
      const badUpdate = createOathkeeperRule('jinbe', { authorizer: { handler: 'deny' } })
      await expect(service.updateAccessRule('jinbe', badUpdate)).rejects.toMatchObject({
        statusCode: 400,
      })
      // original rule is untouched (still remote_json)
      const { rule } = await service.getAccessRule('jinbe')
      expect(rule.authorizer.handler).toBe('remote_json')
    })

    it('should reject a non-enabled error handler as 400', async () => {
      const badRule = createOathkeeperRule('with-bad-error', {
        errors: [{ handler: 'not_a_handler' }],
      })
      await expect(service.createAccessRule(badRule)).rejects.toMatchObject({ statusCode: 400 })
    })

    it('should accept a rule whose handlers are all enabled', async () => {
      const goodRule = createOathkeeperRule('good-service')
      const result = await service.createAccessRule(goodRule)
      expect(result.success).toBe(true)
    })
  })

  // P0 safety net: remote_json's config is PER-SERVICE (payload embeds
  // "app":"<service>" so OPA authorizes against that service's roles). A bare or
  // app-less remote_json would silently authorize against the wrong service, so
  // jinbe backfills the correct per-service config before persisting — while
  // preserving any already-present valid config verbatim.
  describe('remote_json config backfill', () => {
    it('backfills a bare {handler:"remote_json"} on CREATE with per-service config', async () => {
      // createOathkeeperRule defaults to a bare remote_json authorizer (no config)
      const bare = createOathkeeperRule('payments', { authorizer: { handler: 'remote_json' } })
      expect(bare.authorizer.config).toBeUndefined()

      await service.createAccessRule(bare)

      const { rule } = await service.getAccessRule('payments')
      expect(rule.authorizer.handler).toBe('remote_json')
      const cfg = rule.authorizer.config as { remote?: string; payload?: string }
      expect(cfg.remote).toBe(env.OPA_AUTHZ_REMOTE)
      expect(cfg.payload).toContain('"app":"payments"')
    })

    it('backfills a bare {handler:"remote_json"} on UPDATE with per-service config', async () => {
      // Seed a payments rule, then overwrite it with a bare remote_json update to
      // prove the UPDATE path re-supplies the per-service config.
      await service.createAccessRule(createOathkeeperRule('payments'))
      await service.updateAccessRule('payments', {
        ...createOathkeeperRule('payments'),
        authorizer: { handler: 'remote_json' },
      })

      const { rule } = await service.getAccessRule('payments')
      const cfg = rule.authorizer.config as { remote?: string; payload?: string }
      expect(cfg.remote).toBe(env.OPA_AUTHZ_REMOTE)
      expect(cfg.payload).toContain('"app":"payments"')
    })

    it('leaves a complete/custom remote_json config UNCHANGED', async () => {
      const custom = {
        remote: 'http://custom-opa:9999/v1/data/custom/allow',
        payload: '{"input":{"app":"custom-app","note":"handcrafted"}}',
        forward_response_headers_to_upstream: ['X-Foo'],
      }
      const rule = createOathkeeperRule('payments', {
        authorizer: { handler: 'remote_json', config: { ...custom } },
      })

      await service.createAccessRule(rule)

      const { rule: stored } = await service.getAccessRule('payments')
      expect(stored.authorizer.config).toEqual(custom)
    })

    it('derives a hyphenated service from the registry, not the first id segment', async () => {
      // Register a hyphenated service; a sub-rule id (order-service-reports) must
      // resolve to "order-service" (longest registered prefix), never "order".
      await redisMock.sadd('rbac:services', 'order-service')
      const bare = createOathkeeperRule('order-service-reports', {
        authorizer: { handler: 'remote_json' },
      })

      await service.createAccessRule(bare)

      const { rule } = await service.getAccessRule('order-service-reports')
      const cfg = rule.authorizer.config as { payload?: string }
      expect(cfg.payload).toContain('"app":"order-service"')
      expect(cfg.payload).not.toContain('"app":"order"')
    })
  })

  // errors[] is first-class: it must survive a full create → get round-trip and
  // be served back unchanged (Oathkeeper reads it from the same store).
  describe('errors round-trip', () => {
    it('should persist and return the errors[] array through create/get', async () => {
      const rule = createOathkeeperRule('svc-with-errors', {
        errors: [
          { handler: 'redirect', config: { to: 'https://app.example.com/login' } },
          { handler: 'json', config: { verbose: true } },
        ],
      })
      await service.createAccessRule(rule)

      const { rule: fetched } = await service.getAccessRule('svc-with-errors')
      expect(fetched.errors).toBeDefined()
      expect(fetched.errors).toHaveLength(2)
      expect(fetched.errors?.[0]).toEqual({
        handler: 'redirect',
        config: { to: 'https://app.example.com/login' },
      })
      expect(fetched.errors?.[1]).toEqual({ handler: 'json', config: { verbose: true } })

      // and it appears in the full list served to Oathkeeper
      const all = await service.getAccessRules()
      const served = all.rules.find((r) => r.id === 'svc-with-errors')
      expect(served?.errors).toHaveLength(2)
    })
  })
})
