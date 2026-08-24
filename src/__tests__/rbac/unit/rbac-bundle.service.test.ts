import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createOathkeeperRule, createJwtAuthRule } from '../fixtures/access-rules.fixture.js'

const { redisMock, redisModule } = vi.hoisted(() => {
  class InlineRedisMock {
    private store = new Map<string, string>()
    private hashStore = new Map<string, Map<string, string>>()
    private setStore = new Map<string, Set<string>>()
    private listStore = new Map<string, string[]>()
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
    async lpush(key: string, ...values: string[]) { if (!this.listStore.has(key)) this.listStore.set(key, []); const l = this.listStore.get(key)!; for (const v of values) l.unshift(v); return l.length }
    async ltrim(key: string, start: number, stop: number) { const l = this.listStore.get(key); if (l) { const end = stop < 0 ? l.length + stop + 1 : stop + 1; this.listStore.set(key, l.slice(start, end)) } return 'OK' as const }
    async lrange(key: string, start: number, stop: number) { const l = this.listStore.get(key) ?? []; const end = stop < 0 ? l.length + stop + 1 : stop + 1; return l.slice(start, end) }
    async ping() { return 'PONG' }
    async quit() { return 'OK' as const }
    clear() { this.store.clear(); this.hashStore.clear(); this.setStore.clear(); this.listStore.clear() }
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

// import() propagates to OPAL/OPA and emits audit events — both are out of
// scope here, so stub them (invalidateBundle would hit Redis streams + OPAL).
vi.mock('../../../services/rbac.service.js', () => ({
  rbacService: { invalidateBundle: vi.fn().mockResolvedValue(undefined) },
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))

import { rbacBundleService, BundleValidationError, type AuthBundle } from '../../../services/rbac-bundle.service.js'
import { redisRbacRepository, type OathkeeperRule } from '../../../services/redis-rbac.repository.js'

function makeBundle(overrides: Partial<AuthBundle['rbac']> = {}): AuthBundle {
  return {
    version: '1',
    exportedAt: new Date().toISOString(),
    rbac: {
      services: ['jinbe'],
      groups: { admins: { jinbe: ['admin'] } },
      roles: { jinbe: { admin: ['*'] } },
      routeMaps: { jinbe: { rules: [] } },
      oathkeeperRules: [createOathkeeperRule('jinbe') as OathkeeperRule],
      orgServiceMap: {},
      ...overrides,
    },
  }
}

describe('RbacBundleService — import validation, history, rollback', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
  })

  // Fail-closed: with the default enabled sets (cookie_session,noop /
  // allow,remote_json / noop,header / redirect,json), a bundle carrying a rule
  // that references any other handler must be rejected BEFORE any Redis write.
  describe('fail-closed import validation', () => {
    it('rejects a bundle with a rule using a disabled handler (jwt) — nothing written', async () => {
      // Pre-existing state that must survive the rejected import untouched.
      await redisRbacRepository.setAccessRules([createOathkeeperRule('existing') as OathkeeperRule])
      await redisRbacRepository.setGroup('old-group', { jinbe: ['viewer'] })

      const bad = makeBundle({
        oathkeeperRules: [
          createOathkeeperRule('good-rule') as OathkeeperRule,
          createJwtAuthRule('jwt-rule') as OathkeeperRule,
        ],
      })

      const err = await rbacBundleService.import(bad).catch((e) => e)
      expect(err).toBeInstanceOf(BundleValidationError)
      expect(err.statusCode).toBe(400)
      // names WHICH rule failed and why
      expect(err.failures).toHaveLength(1)
      expect(err.failures[0].id).toBe('jwt-rule')
      expect(err.failures[0].reason).toContain("'jwt'")
      expect(err.failures[0].reason).toContain('cookie_session')

      // nothing was written: rules, groups and services untouched, no history entry
      const rules = await redisRbacRepository.getAccessRules()
      expect(rules.map((r) => r.id)).toEqual(['existing'])
      expect(await redisRbacRepository.getGroups()).toEqual({ 'old-group': { jinbe: ['viewer'] } })
      expect(await redisRbacRepository.getServices()).toEqual([])
      expect(await redisRbacRepository.getImportHistory()).toHaveLength(0)
    })

    it('rejects a structurally malformed rule with a schema reason', async () => {
      const malformed = { id: 'broken', match: { url: 'x', methods: ['GET'] } } as unknown as OathkeeperRule
      const err = await rbacBundleService.import(makeBundle({ oathkeeperRules: [malformed] })).catch((e) => e)
      expect(err).toBeInstanceOf(BundleValidationError)
      expect(err.failures[0].id).toBe('broken')
      expect(err.failures[0].reason).toContain('schema:')
      expect(err.failures[0].reason).toContain('upstream')
    })

    it('accepts a bundle whose rules all use enabled handlers', async () => {
      const result = await rbacBundleService.import(makeBundle())
      expect(result.rbac.oathkeeperRules).toBe(1)
      const rules = await redisRbacRepository.getAccessRules()
      expect(rules.map((r) => r.id)).toEqual(['jinbe'])
    })
  })

  describe('import history (rbac:import:history)', () => {
    it('pushes a pre-import snapshot on every import, newest first, with actor + reason', async () => {
      await rbacBundleService.import(makeBundle(), { email: 'admin@example.com' })
      await rbacBundleService.import(makeBundle({ services: ['jinbe', 'kuma'] }))

      const history = await redisRbacRepository.getImportHistory()
      expect(history).toHaveLength(2)
      // newest first: the second import's snapshot captured the FIRST bundle's state
      expect(history[0].reason).toBe('pre-import')
      expect(history[0].actor).toBeNull()
      expect((history[0].bundle as AuthBundle).rbac.services).toEqual(['jinbe'])
      // the first import's snapshot captured the empty pre-state
      expect(history[1].actor).toBe('admin@example.com')
      expect((history[1].bundle as AuthBundle).rbac.services).toEqual([])
    })

    it('caps the history at 10 entries (LTRIM)', async () => {
      for (let i = 0; i < 12; i++) {
        await rbacBundleService.import(makeBundle({ groups: { [`g${i}`]: { jinbe: ['viewer'] } } }))
      }
      const history = await redisRbacRepository.getImportHistory()
      expect(history).toHaveLength(10)
      // head is the snapshot taken before the LAST import → holds import #10's group
      expect(Object.keys((history[0].bundle as AuthBundle).rbac.groups)).toEqual(['g10'])
    })

    it('lists history without the bundle payload but with per-section counts', async () => {
      await rbacBundleService.import(makeBundle())
      await rbacBundleService.import(makeBundle({ services: ['jinbe', 'kuma'] }))

      const list = await rbacBundleService.listImportHistory()
      expect(list).toHaveLength(2)
      expect(list[0]).not.toHaveProperty('bundle')
      // head snapshot = state after the first import
      expect(list[0].counts.services).toBe(1)
      expect(list[0].counts.oathkeeperRules).toBe(1)
      expect(list[1].counts.services).toBe(0)
    })
  })

  describe('rollback', () => {
    it('restores the previous state from a history entry and snapshots pre-rollback state', async () => {
      const bundleA = makeBundle({ groups: { 'team-a': { jinbe: ['admin'] } } })
      const bundleB = makeBundle({
        services: ['jinbe', 'kuma'],
        groups: { 'team-b': { kuma: ['viewer'] } },
        oathkeeperRules: [createOathkeeperRule('jinbe') as OathkeeperRule, createOathkeeperRule('kuma') as OathkeeperRule],
      })
      await rbacBundleService.import(bundleA)
      await rbacBundleService.import(bundleB)

      // head of history = snapshot taken before B was applied → state A
      const [preB] = await rbacBundleService.listImportHistory()
      const { entry, result } = await rbacBundleService.rollback(preB.id, { email: 'admin@example.com' })
      expect(entry.id).toBe(preB.id)
      expect(result.rbac.services).toBe(1)

      // state A is back (full restore: kuma pruned, team-b gone)
      expect(await redisRbacRepository.getServices()).toEqual(['jinbe'])
      expect(await redisRbacRepository.getGroups()).toEqual({ 'team-a': { jinbe: ['admin'] } })
      expect((await redisRbacRepository.getAccessRules()).map((r) => r.id)).toEqual(['jinbe'])

      // and the rollback itself snapshotted state B first (reason pre-rollback)
      const history = await redisRbacRepository.getImportHistory()
      expect(history[0].reason).toBe('pre-rollback')
      expect(history[0].actor).toBe('admin@example.com')
      expect((history[0].bundle as AuthBundle).rbac.services).toEqual(['jinbe', 'kuma'])
    })

    it('throws 404 for an unknown history entry id', async () => {
      await expect(rbacBundleService.rollback('nope')).rejects.toMatchObject({ statusCode: 404 })
    })
  })

  describe('compensation on mid-way failure', () => {
    it('restores the pre-import snapshot when a Redis write throws mid-way', async () => {
      await rbacBundleService.import(makeBundle({ groups: { 'team-a': { jinbe: ['admin'] } } }))

      // Fail the rules write of the NEXT import only; the compensating
      // applyBundle falls through to the real implementation.
      const spy = vi.spyOn(redisRbacRepository, 'setAccessRules').mockRejectedValueOnce(new Error('redis down'))

      const bundleB = makeBundle({ services: ['jinbe', 'kuma'], groups: { 'team-b': { kuma: ['viewer'] } } })
      await expect(rbacBundleService.import(bundleB)).rejects.toThrow('redis down')

      // pre-import state was restored (kuma pruned back out, team-a back)
      expect(await redisRbacRepository.getServices()).toEqual(['jinbe'])
      expect(await redisRbacRepository.getGroups()).toEqual({ 'team-a': { jinbe: ['admin'] } })
      spy.mockRestore()
    })
  })
})
