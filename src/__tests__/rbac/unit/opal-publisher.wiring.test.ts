import { describe, it, expect, beforeEach, vi } from 'vitest'

// Every path that changes what OPA reads must hand the change to the OPAL publisher.
const { schedule, redisMock } = vi.hoisted(() => {
  const hashes = new Map<string, Map<string, string>>()
  const redisMock = {
    async get() { return null },
    async set() { return 'OK' },
    async del() { return 1 },
    async hset(key: string, field: string, value: string) { if (!hashes.has(key)) hashes.set(key, new Map()); hashes.get(key)!.set(field, value); return 1 },
    async hget(key: string, field: string) { return hashes.get(key)?.get(field) ?? null },
    async hdel(key: string, field: string) { return hashes.get(key)?.delete(field) ? 1 : 0 },
    async hgetall(key: string) { return Object.fromEntries(hashes.get(key) ?? []) },
    async smembers() { return [] },
    async sadd() { return 1 },
    async srem() { return 1 },
    clear() { hashes.clear() },
  }
  return { schedule: vi.fn(), redisMock }
})

vi.mock('../../../services/opal-publisher.js', () => ({ opalPublisher: { schedule, refreshAll: vi.fn() } }))
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => redisMock,
  redisClientService: { getClient: () => redisMock, isHealthy: vi.fn().mockResolvedValue(true), isConnected: true },
}))
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getAllIdentitiesWithGroups: vi.fn().mockResolvedValue(new Map()),
    getAllIdentitiesWithBindings: vi.fn().mockResolvedValue(new Map()),
    invalidateGroupsCache: vi.fn(),
  },
}))

import { RbacService } from '../../../services/rbac.service.js'
import { siteLoginStore } from '../../../sites/login-store.js'

describe('OPAL push wiring', () => {
  beforeEach(() => {
    redisMock.clear()
    schedule.mockClear()
  })

  it('every RBAC publish (invalidateBundle) queues a push, named after the event', async () => {
    await new RbacService().invalidateBundle('site.permissions_published', { type: 'site', id: 'shop' })
    expect(schedule).toHaveBeenCalledWith('site.permissions_published')
  })

  it('user group edits queue a push', async () => {
    await new RbacService().notifyBindingsChanged('groups_updated')
    expect(schedule).toHaveBeenCalledWith('user.groups_updated')
  })

  it('a site_login write or removal queues a push, since it may land after the permissions push', async () => {
    await siteLoginStore.set('shop', { min_aal: 'aal2', scope: 'all', routes: [], clients: 'exempt' })
    await siteLoginStore.set('shop', null)
    expect(schedule).toHaveBeenNthCalledWith(1, 'site_login.shop')
    expect(schedule).toHaveBeenNthCalledWith(2, 'site_login.shop')
  })
})
