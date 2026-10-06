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
    async del(...keys: string[]) { let c = 0; for (const k of keys) { if (this.store.delete(k)) c++; if (this.hashStore.delete(k)) c++; if (this.setStore.delete(k)) c++; if (this.listStore.delete(k)) c++ } return c }
    async hget(key: string, field: string) { return this.hashStore.get(key)?.get(field) ?? null }
    async hset(key: string, field: string, value: string) { if (!this.hashStore.has(key)) this.hashStore.set(key, new Map()); const isNew = !this.hashStore.get(key)!.has(field); this.hashStore.get(key)!.set(field, value); return isNew ? 1 : 0 }
    async hdel(key: string, ...fields: string[]) { const h = this.hashStore.get(key); if (!h) return 0; let c = 0; for (const f of fields) { if (h.delete(f)) c++ } return c }
    async hgetall(key: string) { const h = this.hashStore.get(key); if (!h) return {}; return Object.fromEntries(h.entries()) }
    async sadd(key: string, ...members: string[]) { if (!this.setStore.has(key)) this.setStore.set(key, new Set()); let c = 0; for (const m of members) { if (!this.setStore.get(key)!.has(m)) { this.setStore.get(key)!.add(m); c++ } } return c }
    async srem(key: string, ...members: string[]) { const s = this.setStore.get(key); if (!s) return 0; let c = 0; for (const m of members) { if (s.delete(m)) c++ } return c }
    async smembers(key: string) { const s = this.setStore.get(key); return s ? Array.from(s) : [] }
    async sismember(key: string, member: string) { const s = this.setStore.get(key); return s?.has(member) ? 1 : 0 }
    async rpush(key: string, ...values: string[]) { if (!this.listStore.has(key)) this.listStore.set(key, []); this.listStore.get(key)!.push(...values); return this.listStore.get(key)!.length }
    async eval() { return 1 }
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
// Every import publishes the applied sites again (render + gateway platform): stubbed, asserted below.
const { republish } = vi.hoisted(() => ({ republish: vi.fn() }))
vi.mock('../../../sites/republish.js', () => ({ republishAppliedSites: republish }))
vi.mock('../../../services/organisation-store/registry.js', () => ({ dropOrganisationCaches: vi.fn().mockResolvedValue(undefined) }))
// A person's import clears the escalation guard (grant only what you hold), which asks OPA.
vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())

import { rbacBundleService, type AuthBundle } from '../../../services/rbac-bundle.service.js'
import { sitesRepository, type SiteRecord, type SiteVersion } from '../../../sites/repository.js'
import { orgRolesRepository } from '../../../services/org-roles.repository.js'
import { directGrantsRepository, type DirectGrant } from '../../../services/direct-grants.repository.js'
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

/** A format-1 file (what every backup was before format 2): RBAC model plus gateway rules. */
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

/** A saved site at version `v` (applied when `applied`), with its history. */
function siteRecord(name: string, v = 2, applied = true): { record: SiteRecord; versions: SiteVersion[] } {
  const site = { name, displayName: name } as unknown as SiteRecord['site']
  const versions: SiteVersion[] = Array.from({ length: v }, (_, i) => ({ v: i + 1, at: '2026-10-01T00:00:00Z', by: 'ops@example.com', kind: 'save', etag: `e${i + 1}`, site }))
  const record: SiteRecord = { site, version: v, etag: `e${v}`, savedAt: '2026-10-01T00:00:00Z', savedBy: 'ops@example.com', ...(applied ? { applied: { version: v, at: '2026-10-01T00:00:00Z', by: 'ops@example.com', rules: [] } } : {}) }
  return { record, versions }
}
const sitesSection = (sites: Array<ReturnType<typeof siteRecord>>) => ({
  records: sites.map((s) => s.record),
  versions: Object.fromEntries(sites.map((s) => [s.record.site.name, s.versions])),
})
const grant = (name: string): DirectGrant => ({ id: `g-${name}`, scope: 'platform', app: 'billing', kind: 'role', name, grantedBy: 'ops@example.com', grantedAt: '2026-10-01T00:00:00Z' } as DirectGrant)

describe('RbacBundleService — import validation, history, rollback', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
    resetOpaWorld()
    republish.mockResolvedValue({ published: [], failed: [] })
  })

  describe('gateway rules are never restored', () => {
    it("ignores a format-1 file's rules, even a malformed one, and says so", async () => {
      await redisRbacRepository.setAccessRules([createOathkeeperRule('current') as OathkeeperRule])
      const old = makeBundle({
        oathkeeperRules: [createOathkeeperRule('stale') as OathkeeperRule, createJwtAuthRule('jwt-rule') as OathkeeperRule],
      })
      const result = await rbacBundleService.import(old)
      expect((await redisRbacRepository.getAccessRules()).map((r) => r.id)).toEqual(['current'])
      expect(result.notes.join(' ')).toMatch(/2 gateway rules were not restored/)
      expect(await redisRbacRepository.getServices()).toEqual(['billing'])
    })

    it('a snapshot taken now carries no gateway rules', async () => {
      await redisRbacRepository.setAccessRules([createOathkeeperRule('current') as OathkeeperRule])
      const bundle = await rbacBundleService.export()
      expect(bundle.version).toBe('2')
      expect(bundle.rbac).not.toHaveProperty('oathkeeperRules')
    })

    it('refuses a format it cannot read — nothing written', async () => {
      const err = await rbacBundleService.import({ ...makeBundle(), version: '3' }).catch((e) => e)
      expect(err.statusCode).toBe(400)
      expect(err.message).toMatch(/Unsupported bundle version: 3/)
      expect(await redisRbacRepository.getImportHistory()).toHaveLength(0)
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
      expect(await redisRbacRepository.getAccessRules()).toEqual([])

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

      // Fail the settings write of the NEXT import only (after its sites were written); the
      // compensating applyBundle falls through to the real implementation.
      const realHset = redisMock.hset.bind(redisMock)
      const spy = vi.spyOn(redisMock, 'hset').mockImplementation(async (key: string, field: string, value: string) => {
        if (key === 'rbac:config') throw new Error('redis down')
        return realHset(key, field, value)
      })

      const bundleB = { ...makeBundle({ services: ['billing', 'shop'], groups: { 'team-b': { shop: ['viewer'] } } }), version: '2' }
      Object.assign(bundleB.rbac, { sites: sitesSection([siteRecord('shop-front')]), settings: { mcp: '{}' } })
      await expect(rbacBundleService.import(bundleB)).rejects.toThrow('redis down')
      spy.mockRestore()

      // pre-import state was restored (shop pruned back out, team-a back, the written site taken back)
      expect(await redisRbacRepository.getServices()).toEqual(['billing'])
      expect(await redisRbacRepository.getGroups()).toEqual({ 'team-a': { billing: ['admin'] } })
      expect(await sitesRepository.list()).toEqual([])
      expect(republish).toHaveBeenCalledTimes(1)
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

    it('a role no group binds is checked too: it may be held through a direct grant', async () => {
      await seed()
      const current = await rbacBundleService.export()
      const bundle = { ...current, rbac: { ...current.rbac, roles: { ...current.rbac.roles, billing: { ...current.rbac.roles.billing, unbound: ['users:delete'] } } } }
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
  describe('applied sites are published again after every import', () => {
    it('republishes after a full restore and reports the result', async () => {
      republish.mockResolvedValueOnce({ published: ['shop-front'], failed: [{ site: 'blog', error: 'route tie' }] })
      await adminHoldsBilling()
      const result = await rbacBundleService.import(makeBundle(), ADMIN)
      expect(republish).toHaveBeenCalledTimes(1)
      expect(republish).toHaveBeenCalledWith(ADMIN)
      expect(result.sites).toEqual({ published: ['shop-front'], failed: [{ site: 'blog', error: 'route tie' }] })
    })

    it('republishes after a sectioned import and after a rollback, as the bootstrap restore (no actor)', async () => {
      await redisRbacRepository.setRoles('billing', { admin: ['billing:write'] })
      await rbacBundleService.import(makeBundle({ groups: { v: { billing: ['admin'] } } }), undefined, ['groups'])
      const [entry] = await rbacBundleService.listImportHistory()
      await rbacBundleService.rollback(entry.id)
      expect(republish).toHaveBeenCalledTimes(2)
      expect(republish).toHaveBeenLastCalledWith({ email: 'jinbe (restore)' })
    })

    it('a republish that cannot run does not undo the import: it is reported', async () => {
      republish.mockRejectedValueOnce(new Error('gateway platform unreadable'))
      const result = await rbacBundleService.import(makeBundle())
      expect(result.sites.failed).toEqual([{ site: '*', error: 'gateway platform unreadable' }])
      expect(await redisRbacRepository.getServices()).toEqual(['billing'])
    })
  })

  // A restore never deletes an organization: one created after the snapshot (a customer who signed
  // up) keeps its record and everything scoped to it. The snapshot's orgs are restored exactly.
  describe('organizations: restored exactly when in the snapshot, untouched otherwise', () => {
    const ACME = '{"id":"acme","name":"Acme","tenant":"acme"}'
    const orgGrant = (name: string, scope: string): DirectGrant => ({ ...grant(name), id: `g-${name}-${scope}`, scope })
    const claim = (domain: string, org: string) => JSON.stringify({ domain, org, token: 't', verified: true, claimedAt: '2026-10-01T00:00:00Z' })
    const seedOrgData = async () => {
      await redisRbacRepository.setOrgSites('acme', ['billing'])
      await redisRbacRepository.setOrgSites('new-org', ['billing'])
      await orgRolesRepository.setForMember('acme', 'id-keep', ['billing:admin'])
      await orgRolesRepository.setForMember('acme', 'id-stale', ['billing:admin'])
      await orgRolesRepository.setForMember('new-org', 'id-x', ['billing:admin'])
      await directGrantsRepository.restore('id-keep', [grant('admin')])
      await directGrantsRepository.restore('id-stale', [grant('admin'), orgGrant('admin', 'acme'), orgGrant('admin', 'new-org')])
      await redisMock.hset('rbac:organisations', 'acme', '{"id":"acme","name":"Acme renamed","tenant":"acme"}')
      await redisMock.hset('rbac:organisations', 'new-org', '{"id":"new-org","name":"Signed up later","tenant":"new"}')
      await redisMock.hset('rbac:signup:org_sites', 'acme', '["shop"]')
      await redisMock.hset('rbac:signup:org_sites', 'new-org', '["shop"]')
      await redisMock.hset('rbac:org_domains', 'acme-old.test', claim('acme-old.test', 'acme'))
      await redisMock.hset('rbac:org_domains', 'new.test', claim('new.test', 'new-org'))
    }
    const snapshotWithAcmeOnly = () => {
      const b = { ...makeBundle({
        orgSites: { acme: ['billing'] },
        orgAssignments: { acme: { 'id-keep': ['billing:admin'] } },
        directGrants: { 'id-keep': [grant('admin')] },
      }), version: '2' }
      Object.assign(b.rbac, {
        organizations: { registry: { acme: ACME } },
        signup: { orgSites: {}, domains: { 'acme.test': claim('acme.test', 'acme'), 'new.test': claim('new.test', 'acme') } },
      })
      return b
    }

    it('a full restore: the snapshot\'s orgs exactly, an org created since untouched', async () => {
      await seedOrgData()
      await rbacBundleService.import(snapshotWithAcmeOnly())
      // acme: back to the snapshot
      expect(await redisMock.hget('rbac:organisations', 'acme')).toBe(ACME)
      expect(await orgRolesRepository.getForOrg('acme')).toEqual({ 'id-keep': ['billing:admin'] })
      expect(await redisMock.hget('rbac:signup:org_sites', 'acme')).toBeNull()
      expect(await redisMock.hget('rbac:org_domains', 'acme-old.test')).toBeNull()
      expect(await redisMock.hget('rbac:org_domains', 'acme.test')).toBe(claim('acme.test', 'acme'))
      // new-org: record, entitlements, roles, sign-up sites, its domain claim and its grants kept
      expect(await redisMock.hget('rbac:organisations', 'new-org')).not.toBeNull()
      expect(await redisRbacRepository.getOrgSites()).toEqual({ acme: ['billing'], 'new-org': ['billing'] })
      expect(await orgRolesRepository.getForOrg('new-org')).toEqual({ 'id-x': ['billing:admin'] })
      expect(await redisMock.hget('rbac:signup:org_sites', 'new-org')).toBe('["shop"]')
      expect(await redisMock.hget('rbac:org_domains', 'new.test')).toBe(claim('new.test', 'new-org'))
      // platform grants and acme's exactly the file's; the grant in new-org stays
      expect(await directGrantsRepository.getFor('id-keep')).toHaveLength(1)
      expect((await directGrantsRepository.getFor('id-stale')).map((g) => g.scope)).toEqual(['new-org'])
    })

    it('a sectioned import of the same file removes nothing', async () => {
      await seedOrgData()
      await rbacBundleService.import(snapshotWithAcmeOnly(), undefined, ['orgSites', 'orgAssignments', 'directGrants', 'organizations', 'signup'])
      expect(Object.keys(await redisRbacRepository.getOrgSites()).sort()).toEqual(['acme', 'new-org'])
      expect(Object.keys(await orgRolesRepository.getForOrg('acme')).sort()).toEqual(['id-keep', 'id-stale'])
      expect(await directGrantsRepository.getFor('id-stale')).toHaveLength(3)
      expect(Object.keys(await redisMock.hgetall('rbac:organisations')).sort()).toEqual(['acme', 'new-org'])
      expect(Object.keys(await redisMock.hgetall('rbac:org_domains')).sort()).toEqual(['acme-old.test', 'acme.test', 'new.test'])
    })

    it('organization deployments are neither in a snapshot nor restored', async () => {
      await redisMock.hset('rbac:organisations', 'acme', ACME)
      await redisMock.hset('rbac:organisation_deployments', 'acme', '{"billing":true}')
      const bundle = await rbacBundleService.export()
      expect(bundle.rbac.organizations).toEqual({ registry: { acme: ACME } })
      const older = { ...makeBundle(), version: '2' }
      Object.assign(older.rbac, { organizations: { registry: { acme: ACME }, deployments: { acme: '{"billing":false}' } } })
      await rbacBundleService.import(older)
      expect(await redisMock.hget('rbac:organisation_deployments', 'acme')).toBe('{"billing":true}')
    })

    it('a failed import takes back the organization records it added', async () => {
      const realHset = redisMock.hset.bind(redisMock)
      const spy = vi.spyOn(redisMock, 'hset').mockImplementation(async (key: string, field: string, value: string) => {
        if (key === 'rbac:signup:org_sites') throw new Error('redis down')
        return realHset(key, field, value)
      })
      const b = snapshotWithAcmeOnly()
      Object.assign(b.rbac, { signup: { orgSites: { acme: '["shop"]' }, domains: {} } })
      await expect(rbacBundleService.import(b)).rejects.toThrow('redis down')
      spy.mockRestore()
      expect(await redisMock.hgetall('rbac:organisations')).toEqual({})
    })
  })

  describe('the stores beside the model (format 2)', () => {
    const seedStores = async () => {
      const shop = siteRecord('shop-front', 3)
      await sitesRepository.put(shop.record, shop.versions)
      await redisMock.hset('rbac:config', 'mcp', '{"enabled":true}')
      await redisMock.hset('rbac:config', 'sign_in_protection', '{"captcha":"off"}')
      await redisMock.hset('rbac:organisations', 'acme', '{"id":"acme","name":"Acme","tenant":"acme"}')
      await redisMock.hset('rbac:signup:org_sites', 'acme', '["shop-front"]')
      await redisMock.hset('rbac:org_domains', 'acme.test', '{"domain":"acme.test","org":"acme","verified":true}')
      await redisMock.hset('rbac:services:meta', 'billing', '{"description":"Billing"}')
      await redisMock.hset('rbac:services:meta', 'jinbe', '{"system":true}')
      await redisMock.hset('rbac:groups:meta', 'admins', '{"description":"Admins"}')
      await redisMock.hset('rbac:groups:meta', 'super_admins', '{"system":true}')
    }

    it('round-trip: what is exported comes back after a restore on an empty store', async () => {
      await seedStores()
      const before = await rbacBundleService.export()
      expect(before.rbac.sites?.records.map((r) => r.site.name)).toEqual(['shop-front'])
      expect(before.rbac.sites?.versions['shop-front']).toHaveLength(3)
      // What code defines is not in a snapshot.
      expect(before.rbac.metadata).toEqual({ services: { billing: '{"description":"Billing"}' }, groups: { admins: '{"description":"Admins"}' } })

      redisMock.clear()
      const result = await rbacBundleService.import(JSON.parse(JSON.stringify(before)))
      expect(result.stores.sites).toEqual({ restored: ['shop-front'], kept: [] })
      expect(result.notes).toEqual([])
      const after = await rbacBundleService.export()
      expect({ ...after.rbac }).toEqual({ ...before.rbac })
      expect((await sitesRepository.get('shop-front'))?.applied?.version).toBe(3)
    })

    it('a site that exists now is kept as it is; a site gone since is written back', async () => {
      const live = siteRecord('shop-front', 5)
      await sitesRepository.put(live.record, live.versions)
      const snapshot = { ...makeBundle(), version: '2' }
      Object.assign(snapshot.rbac, { sites: sitesSection([siteRecord('shop-front', 2), siteRecord('blog', 1)]) })
      const result = await rbacBundleService.import(snapshot)
      expect(result.stores.sites).toEqual({ restored: ['blog'], kept: ['shop-front'] })
      expect((await sitesRepository.get('shop-front'))?.version).toBe(5)
      expect(await sitesRepository.versions('shop-front')).toHaveLength(5)
      expect(await sitesRepository.versions('blog')).toHaveLength(1)
    })

    it('a full restore makes settings exactly the file\'s; a sectioned one only writes over', async () => {
      await redisMock.hset('rbac:config', 'mcp', '{"enabled":false}')
      await redisMock.hset('rbac:config', 'added_later', '1')
      const snapshot = { ...makeBundle(), version: '2' }
      Object.assign(snapshot.rbac, { settings: { mcp: '{"enabled":true}' } })
      await rbacBundleService.import(snapshot, undefined, ['settings'])
      expect(await redisMock.hgetall('rbac:config')).toEqual({ mcp: '{"enabled":true}', added_later: '1' })
      await rbacBundleService.import(snapshot)
      expect(await redisMock.hgetall('rbac:config')).toEqual({ mcp: '{"enabled":true}' })
    })

    it('refuses a malformed store section before anything is written', async () => {
      const snapshot = { ...makeBundle(), version: '2' }
      const bad = siteRecord('shop-front', 2)
      Object.assign(snapshot.rbac, { settings: { mcp: { enabled: true } }, sites: { records: [bad.record], versions: { 'shop-front': bad.versions.slice(0, 1) } } })
      const err = await rbacBundleService.import(snapshot).catch((e) => e)
      expect(err.statusCode).toBe(400)
      expect(err.message).toMatch(/settings: must map/)
      expect(err.message).toMatch(/shop-front: version 2 is not its last saved version/)
      expect(await redisRbacRepository.getImportHistory()).toHaveLength(0)
    })
  })

  describe('a format-1 file still restores', () => {
    it('leaves what it lacks as it is, and says so', async () => {
      await redisMock.hset('rbac:config', 'mcp', '{"enabled":true}')
      await redisMock.hset('rbac:organisations', 'acme', '{"id":"acme","name":"Acme","tenant":"acme"}')
      await redisRbacRepository.setOrgSites('acme', ['billing'])
      const shop = siteRecord('shop-front')
      await sitesRepository.put(shop.record, shop.versions)

      const result = await rbacBundleService.import(makeBundle())

      expect(await redisRbacRepository.getServices()).toEqual(['billing'])
      expect(await redisMock.hgetall('rbac:config')).toEqual({ mcp: '{"enabled":true}' })
      expect(Object.keys(await redisMock.hgetall('rbac:organisations'))).toEqual(['acme'])
      expect(await redisRbacRepository.getOrgSites()).toEqual({ acme: ['billing'] })
      expect(await sitesRepository.get('shop-front')).not.toBeNull()
      expect(result.notes.join(' ')).toMatch(/format 1\) has no orgSites, orgAssignments, directGrants, sites, settings, organizations, signup, metadata: left as they are/)
      expect(republish).toHaveBeenCalledTimes(1)
    })
  })
})
