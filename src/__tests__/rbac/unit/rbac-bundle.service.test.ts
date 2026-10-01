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
// A person's import clears the escalation guard (grant only what you hold), which asks OPA.
vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())

import { rbacBundleService, BundleValidationError, type AuthBundle } from '../../../services/rbac-bundle.service.js'
import { redisRbacRepository, type OathkeeperRule } from '../../../services/redis-rbac.repository.js'
import { opaWorld, refused, resetOpaWorld } from '../../helpers/opa-authz-mock.js'

const ADMIN = { id: 'id-admin', email: 'admin@example.com' }

/** ADMIN holds billing's admin role before importing, as OPA resolves it. */
async function adminHoldsBilling() {
  await redisRbacRepository.setRoles('billing', { admin: ['billing:write'] })
  await redisRbacRepository.setGroup('admins', { billing: ['admin'] })
  opaWorld.groups[ADMIN.email] = ['admins']
  opaWorld.permissions[ADMIN.email] = ['billing:write']
}

function makeBundle(overrides: Partial<AuthBundle['rbac']> = {}): AuthBundle {
  return {
    version: '1',
    exportedAt: new Date().toISOString(),
    rbac: {
      services: ['billing'],
      groups: { admins: { billing: ['admin'] } },
      roles: { billing: { admin: ['billing:write'] } },
      routeMaps: { billing: { rules: [] } },
      oathkeeperRules: [createOathkeeperRule('billing') as OathkeeperRule],
      ...overrides,
    },
  }
}

describe('RbacBundleService — import validation, history, rollback', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
    resetOpaWorld()
  })

  // Fail-closed: with the default enabled sets (cookie_session,noop /
  // allow,remote_json / noop,header / redirect,json), a bundle carrying a rule
  // that references any other handler must be rejected BEFORE any Redis write.
  describe('fail-closed import validation', () => {
    it('rejects a bundle with a rule using a disabled handler (jwt) — nothing written', async () => {
      // Pre-existing state that must survive the rejected import untouched.
      await redisRbacRepository.setAccessRules([createOathkeeperRule('existing') as OathkeeperRule])
      await redisRbacRepository.setGroup('old-group', { billing: ['viewer'] })

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
      expect(await redisRbacRepository.getGroups()).toEqual({ 'old-group': { billing: ['viewer'] } })
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
      expect(rules.map((r) => r.id)).toEqual(['billing'])
    })
  })

  describe('group bindings (group-bindings.ts)', () => {
    it('rejects 422 a group binding a role its service will not define — nothing written', async () => {
      for (const groups of [{ desk: { billing: ['support'] } }]) {
        const err = await rbacBundleService.import(makeBundle({ groups })).catch((e) => e)
        expect(err.statusCode).toBe(422)
      }
      expect(await redisRbacRepository.getServices()).toEqual([])
      expect(await redisRbacRepository.getImportHistory()).toHaveLength(0)
    })

    it('reads a groups-only import against the roles already stored', async () => {
      await redisRbacRepository.setRoles('billing', { admin: ['billing:write'], viewer: ['billing:read'] })
      const ok = await rbacBundleService.import(makeBundle({ groups: { v: { billing: ['viewer'] } } }), undefined, ['groups']).catch((e) => e)
      expect(ok.statusCode).toBeUndefined()
      const err = await rbacBundleService.import(makeBundle({ groups: { v: { billing: ['editor'] } } }), undefined, ['groups']).catch((e) => e)
      expect(err.statusCode).toBe(422)
    })
  })

  describe('route ties across services', () => {
    it('rejects a bundle where two services own one route at the same rank — nothing written', async () => {
      const bad = makeBundle({
        services: ['billing', 'shop'],
        routeMaps: {
          billing: { rules: [{ method: 'GET', path: '/api/clusters/:id', permission: 'clusters:read' }] },
          shop: { rules: [{ method: 'GET', path: '/api/clusters/:clusterId' }] },
        },
      })
      const err = await rbacBundleService.import(bad).catch((e) => e)
      expect(err.statusCode).toBe(409)
      expect(err.message).toMatch(/billing|shop/)
      expect(await redisRbacRepository.getServices()).toEqual([])
      expect(await redisRbacRepository.getImportHistory()).toHaveLength(0)
    })

    it('a routeMaps-only import is checked against the services it leaves in place', async () => {
      await redisRbacRepository.addService('shop')
      await redisRbacRepository.addService('billing')
      await redisRbacRepository.setRouteMap('shop', { rules: [{ method: 'GET', path: '/api/x' }] })
      const bad = makeBundle({ routeMaps: { billing: { rules: [{ method: 'GET', path: '/api/x' }] } } })
      const err = await rbacBundleService.import(bad, undefined, ['routeMaps']).catch((e) => e)
      expect(err.statusCode).toBe(409)
      expect(await redisRbacRepository.getRouteMap('billing')).toBeNull()
    })
  })

  describe('route org_param (J-1)', () => {
    it('rejects a route whose org_param names no :param of its path — nothing written', async () => {
      const bad = makeBundle({
        routeMaps: { billing: { rules: [{ method: 'GET', path: '/api/fleet/orgs/:id', permission: 'r', org_param: 'orgId' }] } },
      })
      const err = await rbacBundleService.import(bad).catch((e) => e)
      expect(err.statusCode).toBe(400)
      expect(err.message).toMatch(/billing.*org_param/)
      expect(await redisRbacRepository.getServices()).toEqual([])
      expect(await redisRbacRepository.getImportHistory()).toHaveLength(0)
    })

    it('keeps a valid org_param through the import', async () => {
      const rules = [{ method: 'GET', path: '/api/fleet/orgs/:orgId', permission: 'r', org_param: 'orgId' }]
      await rbacBundleService.import(makeBundle({ routeMaps: { billing: { rules } } }))
      expect(await redisRbacRepository.getRouteMap('billing')).toEqual({ rules })
    })
  })

  describe('import history (rbac:import:history)', () => {
    it('pushes a pre-import snapshot on every import, newest first, with actor + reason', async () => {
      await rbacBundleService.import(makeBundle())
      await adminHoldsBilling()
      redisMock.clear()
      await adminHoldsBilling()
      await rbacBundleService.import(makeBundle(), ADMIN)
      await rbacBundleService.import(makeBundle({ services: ['billing', 'shop'] }))

      const history = await redisRbacRepository.getImportHistory()
      expect(history).toHaveLength(2)
      // newest first: the second import's snapshot captured the FIRST bundle's state
      expect(history[0].reason).toBe('pre-import')
      expect(history[0].actor).toBeNull()
      expect((history[0].bundle as AuthBundle).rbac.services).toEqual(['billing'])
      // the first import's snapshot captured the empty pre-state
      expect(history[1].actor).toBe('admin@example.com')
      expect((history[1].bundle as AuthBundle).rbac.services).toEqual([])
    })

    it('caps the history at 10 entries (LTRIM)', async () => {
      for (let i = 0; i < 12; i++) {
        await rbacBundleService.import(makeBundle({ groups: { [`g${i}`]: { billing: ['viewer'] } } }))
      }
      const history = await redisRbacRepository.getImportHistory()
      expect(history).toHaveLength(10)
      // head is the snapshot taken before the LAST import → holds import #10's group
      expect(Object.keys((history[0].bundle as AuthBundle).rbac.groups)).toEqual(['g10'])
    })

    it('lists history without the bundle payload but with per-section counts', async () => {
      await rbacBundleService.import(makeBundle())
      await rbacBundleService.import(makeBundle({ services: ['billing', 'shop'] }))

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
      const bundleA = makeBundle({ groups: { 'team-a': { billing: ['admin'] } } })
      const bundleB = makeBundle({
        services: ['billing', 'shop'],
        groups: { 'team-b': { shop: ['viewer'] } },
        oathkeeperRules: [createOathkeeperRule('billing') as OathkeeperRule, createOathkeeperRule('shop') as OathkeeperRule],
      })
      await rbacBundleService.import(bundleA)
      await rbacBundleService.import(bundleB)

      // head of history = snapshot taken before B was applied → state A
      const [preB] = await rbacBundleService.listImportHistory()
      // The actor holds what state A grants, as OPA resolves it.
      await redisRbacRepository.setGroup('admins', { billing: ['admin'] })
      await redisRbacRepository.setRoles('billing', { admin: ['billing:write'] })
      opaWorld.groups[ADMIN.email] = ['admins']
      opaWorld.permissions[ADMIN.email] = ['billing:write']
      const { entry, result } = await rbacBundleService.rollback(preB.id, ADMIN)
      expect(entry.id).toBe(preB.id)
      expect(result.rbac.services).toBe(1)

      // state A is back (full restore: kuma pruned, team-b gone)
      expect(await redisRbacRepository.getServices()).toEqual(['billing'])
      expect(await redisRbacRepository.getGroups()).toEqual({ 'team-a': { billing: ['admin'] } })
      expect((await redisRbacRepository.getAccessRules()).map((r) => r.id)).toEqual(['billing'])

      // and the rollback itself snapshotted state B first (reason pre-rollback)
      const history = await redisRbacRepository.getImportHistory()
      expect(history[0].reason).toBe('pre-rollback')
      expect(history[0].actor).toBe('admin@example.com')
      expect((history[0].bundle as AuthBundle).rbac.services).toEqual(['billing', 'shop'])
    })

    it('throws 404 for an unknown history entry id', async () => {
      await expect(rbacBundleService.rollback('nope')).rejects.toMatchObject({ statusCode: 404 })
    })
  })

  describe('compensation on mid-way failure', () => {
    it('restores the pre-import snapshot when a Redis write throws mid-way', async () => {
      await rbacBundleService.import(makeBundle({ groups: { 'team-a': { billing: ['admin'] } } }))

      // Fail the rules write of the NEXT import only; the compensating
      // applyBundle falls through to the real implementation.
      const spy = vi.spyOn(redisRbacRepository, 'setAccessRules').mockRejectedValueOnce(new Error('redis down'))

      const bundleB = makeBundle({ services: ['billing', 'shop'], groups: { 'team-b': { shop: ['viewer'] } } })
      await expect(rbacBundleService.import(bundleB)).rejects.toThrow('redis down')

      // pre-import state was restored (kuma pruned back out, team-a back)
      expect(await redisRbacRepository.getServices()).toEqual(['billing'])
      expect(await redisRbacRepository.getGroups()).toEqual({ 'team-a': { billing: ['admin'] } })
      spy.mockRestore()
    })
  })

  describe('what code defines is never imported', () => {
    it("drops jinbe's roles and route map, the staff groups, and a previous model's global and kuma", async () => {
      await rbacBundleService.import(makeBundle({
        services: ['billing', 'jinbe', 'kuma'],
        groups: { super_admins: { global: ['super_admin'] }, team: { billing: ['admin'], jinbe: ['viewer'], kuma: ['admin'] } },
        roles: { billing: { admin: ['billing:write'] }, jinbe: { viewer: ['users:read'] }, global: { super_admin: ['*'] } },
        routeMaps: { billing: { rules: [] }, jinbe: { rules: [] } },
        orgServiceMap: { acme: ['billing', 'kuma', 'jinbe'] },
      }))
      expect(await redisRbacRepository.getServices()).toEqual(['billing'])
      expect(await redisRbacRepository.getGroups()).toEqual({ team: { billing: ['admin'] } })
      expect(await redisRbacRepository.getRoles('jinbe')).toBeNull()
      expect(await redisRbacRepository.getRoles('global')).toBeNull()
      expect(await redisRbacRepository.getOrgSites()).toEqual({ acme: ['billing'] })
    })
  })

  // Grant only what you hold: an import changes no group beyond what its importer holds.
  describe('an import by a person', () => {
    const OPS = { id: 'id-ops', email: 'ops@example.com' }
    const seed = async () => {
      await rbacBundleService.import({
        ...makeBundle(),
        rbac: {
          ...makeBundle().rbac,
          groups: { 'ops-team': { billing: ['ops'] }, 'sec-team': { billing: ['security'] }, readers: { billing: ['viewer'] } },
          roles: { billing: { ops: ['zones:write', 'sites:read'], security: ['users:reset_second_factor'], viewer: ['sites:read'] } },
        },
      })
      // What OPA resolves for them in billing: the ops role.
      opaWorld.groups[OPS.email] = ['ops-team']
      opaWorld.permissions[OPS.email] = ['sites:read', 'zones:write']
      // A stand-in for the policy's verdicts (proven in opal-policies): what the proposal confers
      // beyond what the actor holds is missing.
      opaWorld.verdict = (q) => {
        const held = opaWorld.permissions[q.actor] ?? []
        const confers = q.kind === 'define_roles'
          ? Object.values(q.roles as Record<string, Record<string, string[]>>).flatMap((r) => Object.values(r).flat())
          : q.kind === 'define_group'
            ? Object.entries(q.definition as Record<string, string[]>).flatMap(([app, rs]) => rs.flatMap((r) => (q.roles as Record<string, Record<string, string[]>>)?.[app]?.[r] ?? []))
            : []
        const missing = [...new Set(confers.filter((p) => !held.includes(p)))].sort()
        return missing.length ? refused({ missing: { billing: missing } }) : null
      }
    }
    const bundleWith = async (groups: Record<string, Record<string, string[]>>) => {
      const current = await rbacBundleService.export()
      return { ...current, rbac: { ...current.rbac, groups: { ...current.rbac.groups, ...groups } } }
    }
    const refusal = async (p: Promise<unknown>) => p.then(() => null, (e) => e as { statusCode?: number; code?: string; refusal?: Record<string, unknown> })

    it('refuses a group granting what they do not hold — nothing written', async () => {
      await seed()
      const err = await refusal(rbacBundleService.import(await bundleWith({ helpdesk: { billing: ['security'] } }), OPS))
      expect(err).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
      expect(err?.refusal).toMatchObject({ missing: ['users:reset_second_factor'] })
      expect(await redisRbacRepository.getGroup('helpdesk')).toBeNull()
    })

    it('lets through an import that changes nothing beyond what they hold', async () => {
      await seed()
      await rbacBundleService.import(await bundleWith({ edge: { billing: ['ops'] } }), OPS)
      expect(await redisRbacRepository.getGroup('edge')).toEqual({ billing: ['ops'] })
    })

    it('reads what a group grants off the roles the import leaves: widening a bound role is widening the group', async () => {
      await seed()
      const current = await rbacBundleService.export()
      const bundle = { ...current, rbac: { ...current.rbac, roles: { ...current.rbac.roles, billing: { ...current.rbac.roles.billing, viewer: ['sites:read', 'users:delete'] } } } }
      const err = await refusal(rbacBundleService.import(bundle, OPS))
      expect(err).toMatchObject({ statusCode: 403, code: 'grant_exceeds_own' })
      expect(err?.refusal).toMatchObject({ missing: ['users:delete'] })
    })

    it('fails closed when OPA cannot be asked', async () => {
      await seed()
      opaWorld.down = true
      const err = await refusal(rbacBundleService.import(await bundleWith({ edge: { billing: ['ops'] } }), OPS))
      expect(err?.statusCode).toBe(503)
    })
  })
})
