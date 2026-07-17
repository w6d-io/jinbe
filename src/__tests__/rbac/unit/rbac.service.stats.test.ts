import { describe, it, expect, beforeEach, vi } from 'vitest'

// Hoisted in-memory Redis mock (mirrors the other rbac.service tests). set()
// ignores the trailing EX/args, which is exactly what getStats/setStats need.
const { redisMock, redisModule } = vi.hoisted(() => {
  class InlineRedisMock {
    store = new Map<string, string>()
    async get(key: string) { return this.store.get(key) ?? null }
    async set(key: string, value: string) { this.store.set(key, value); return 'OK' as const }
    async del(...keys: string[]) { let c = 0; for (const k of keys) { if (this.store.delete(k)) c++ } return c }
    async hgetall() { return {} as Record<string, string> }
    async ping() { return 'PONG' }
    async quit() { return 'OK' as const }
    clear() { this.store.clear() }
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
