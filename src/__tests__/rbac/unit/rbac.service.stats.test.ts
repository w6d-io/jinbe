import { describe, it, expect, beforeEach, vi } from 'vitest'

// Hoisted in-memory Redis mock (mirrors the other rbac.service tests). set()
// ignores the trailing EX/args, which is exactly what getStats/setStats need.
const { redisMock, redisModule } = vi.hoisted(() => {
  class InlineRedisMock {
    store = new Map<string, string>()
    hashes = new Map<string, Record<string, string>>()
    async get(key: string) { return this.store.get(key) ?? null }
    async set(key: string, value: string) { this.store.set(key, value); return 'OK' as const }
    async del(...keys: string[]) { let c = 0; for (const k of keys) { if (this.store.delete(k)) c++ } return c }
    async hgetall(key: string) { return this.hashes.get(key) ?? ({} as Record<string, string>) }
    async ping() { return 'PONG' }
    async quit() { return 'OK' as const }
    clear() { this.store.clear(); this.hashes.clear() }
  }
  const mock = new InlineRedisMock()
  return {
    redisMock: mock,
    redisModule: {
      redisClientService: { getClient: () => mock, isHealthy: vi.fn().mockResolvedValue(true), disconnect: vi.fn(), isConnected: true },
      getRedisClient: () => mock,
    },
  }
})

vi.mock('../../../services/redis-client.service.js', () => redisModule)

const { getAllIdentitiesWithBindings } = vi.hoisted(() => ({ getAllIdentitiesWithBindings: vi.fn() }))
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getAllIdentitiesWithBindings,
    invalidateGroupsCache: vi.fn(),
  },
}))

// The enforced store is off unless a test says otherwise: stats fall back to the display copy.
const { allGroupMemberships } = vi.hoisted(() => ({ allGroupMemberships: vi.fn(() => Promise.reject(new Error('store off'))) }))
vi.mock('../../../services/organisation-store.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../services/organisation-store.js')>()),
  allGroupMemberships,
}))

vi.mock('../../../services/realtime.service.js', () => ({
  realtimeService: { publish: vi.fn() },
}))

import { RbacService } from '../../../services/rbac.service.js'

const STATS_KEY = 'rbac:stats'
const flush = () => new Promise((r) => setTimeout(r, 0))

describe('RbacService.getDirectoryStats — invalidation defeats an in-flight refresh (#10)', () => {
  let service: RbacService

  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
    service = new RbacService()
  })

  it('does NOT persist stats from a refresh that started before an invalidation', async () => {
    // The background refresh blocks on the bindings read until we release it.
    let releaseBindings!: () => void
    getAllIdentitiesWithBindings.mockReturnValueOnce(
      new Promise((r) => { releaseBindings = () => r(new Map()) }),
    )

    // Cold cache → getDirectoryStats runs the (single-flight) refresh.
    const statsP = service.getDirectoryStats()
    await flush() // let getStats() resolve and the refresh capture its epoch + start reading

    // A mutation invalidates while the refresh is mid-flight (its bindings
    // pre-image is now stale).
    await service.invalidateDirectoryStats()

    // Refresh completes with the stale pre-image.
    releaseBindings()
    await statsP

    // It must NOT have cached — otherwise stale counts get pinned "fresh" ~15s.
    expect(await redisMock.get(STATS_KEY)).toBeNull()
  })

  it('persists stats when no invalidation races (control)', async () => {
    getAllIdentitiesWithBindings.mockResolvedValueOnce(new Map())
    await service.getDirectoryStats() // cold → refresh → should cache
    expect(await redisMock.get(STATS_KEY)).not.toBeNull()
  })
})

describe('RbacService.getDirectoryStats — who is "in no group and can reach nothing"', () => {
  const binding = (id: string, groups: string[], active = true) => ({ id, name: null, groups, active, organizations: [], primaryOrganization: null })

  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
    allGroupMemberships.mockRejectedValue(new Error('store off')) // → the display copy (b.groups)
  })

  it('counts only active people with the default membership and no org role', async () => {
    getAllIdentitiesWithBindings.mockResolvedValueOnce(new Map([
      ['alone@x.io', binding('i-1', ['users'])],
      ['inactive@x.io', binding('i-2', ['users'], false)],
      ['granted@x.io', binding('i-3', ['users'])],
      ['orgadmin@x.io', binding('i-4', ['users'])],
      ['admin@x.io', binding('i-5', ['users', 'super_admins'])],
    ]))
    redisMock.hashes.set('rbac:org_grants', { 'org-1': JSON.stringify({ 'Granted@X.io': ['fleet_pilots'] }) })
    redisMock.hashes.set('rbac:org_admins', { 'org-2': JSON.stringify(['orgadmin@x.io']) })
    const stats = await new RbacService().getDirectoryStats()
    expect(stats).toMatchObject({ total: 5, active: 4, unassigned: 1 })
  })

  it('reads memberships from the enforced store when it answers', async () => {
    getAllIdentitiesWithBindings.mockResolvedValueOnce(new Map([
      ['a@x.io', binding('i-1', ['users'])], // the display copy is behind: the store says pilots
      ['b@x.io', binding('i-2', ['users', 'pilots'])], // the store holds nothing for b
    ]))
    allGroupMemberships.mockResolvedValueOnce(new Map([['i-1', ['pilots']]]))
    expect((await new RbacService().getDirectoryStats()).unassigned).toBe(1)
  })
})
