import { describe, it, expect, beforeEach, vi } from 'vitest'

// ---------------------------------------------------------------------------
// Repository-level tests for the org → service BUNDLE map.
//
// Focus: writes emit the JSON-array shape, reads normalize BOTH the new array
// shape AND legacy scalar values (pre-migration data) to string[], and the
// single-service resolver (getServiceForOrg) preserves the old scalar
// behaviour by returning the bundle's first entry.
// ---------------------------------------------------------------------------

const { redisMock, redisModule } = vi.hoisted(() => {
  class InlineRedisMock {
    private hashStore = new Map<string, Map<string, string>>()
    async hget(key: string, field: string) { return this.hashStore.get(key)?.get(field) ?? null }
    async hset(key: string, field: string, value: string) {
      if (!this.hashStore.has(key)) this.hashStore.set(key, new Map())
      const isNew = !this.hashStore.get(key)!.has(field)
      this.hashStore.get(key)!.set(field, value)
      return isNew ? 1 : 0
    }
    async hdel(key: string, ...fields: string[]) {
      const h = this.hashStore.get(key)
      if (!h) return 0
      let c = 0
      for (const f of fields) if (h.delete(f)) c++
      return c
    }
    async hgetall(key: string) {
      const h = this.hashStore.get(key)
      if (!h) return {}
      return Object.fromEntries(h.entries())
    }
    // Raw seed helper for legacy-shape fixtures (bypasses setOrgServiceMapping).
    seedRaw(key: string, field: string, value: string) {
      if (!this.hashStore.has(key)) this.hashStore.set(key, new Map())
      this.hashStore.get(key)!.set(field, value)
    }
    rawValue(key: string, field: string) { return this.hashStore.get(key)?.get(field) ?? null }
    clear() { this.hashStore.clear() }
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

import { redisRbacRepository } from '../../../services/redis-rbac.repository.js'

const KEY = 'rbac:org_service_map'
const ORG_A = '11111111-1111-1111-1111-111111111111'
const ORG_B = '22222222-2222-2222-2222-222222222222'

describe('RedisRbacRepository — org → service bundle map', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    redisMock.clear()
  })

  describe('setOrgServiceMapping (write) + getOrgServiceMap (read)', () => {
    it('stores a bundle as a JSON array and reads it back as string[]', async () => {
      await redisRbacRepository.setOrgServiceMapping(ORG_A, ['kuma', 'fleet'])

      // Persisted shape is the JSON array (what OPA now consumes).
      expect(redisMock.rawValue(KEY, ORG_A)).toBe('["kuma","fleet"]')

      const map = await redisRbacRepository.getOrgServiceMap()
      expect(map).toEqual({ [ORG_A]: ['kuma', 'fleet'] })
    })

    it('stores a single-service bundle as a one-element array', async () => {
      await redisRbacRepository.setOrgServiceMapping(ORG_A, ['kuma'])
      expect(redisMock.rawValue(KEY, ORG_A)).toBe('["kuma"]')
      expect(await redisRbacRepository.getOrgServiceMap()).toEqual({ [ORG_A]: ['kuma'] })
    })

    it('deduplicates while preserving order', async () => {
      await redisRbacRepository.setOrgServiceMapping(ORG_A, ['kuma', 'fleet', 'kuma'])
      expect(await redisRbacRepository.getOrgServiceMap()).toEqual({ [ORG_A]: ['kuma', 'fleet'] })
    })

    it('drops empty / non-string entries defensively', async () => {
      await redisRbacRepository.setOrgServiceMapping(ORG_A, ['kuma', '', 'fleet'])
      expect(await redisRbacRepository.getOrgServiceMap()).toEqual({ [ORG_A]: ['kuma', 'fleet'] })
    })

    it('an empty bundle removes the mapping', async () => {
      await redisRbacRepository.setOrgServiceMapping(ORG_A, ['kuma'])
      await redisRbacRepository.setOrgServiceMapping(ORG_A, [])
      expect(redisMock.rawValue(KEY, ORG_A)).toBeNull()
      expect(await redisRbacRepository.getOrgServiceMap()).toEqual({})
    })
  })

  describe('legacy scalar read path (backward compatibility)', () => {
    it('normalizes a pre-migration scalar value to a single-element array', async () => {
      redisMock.seedRaw(KEY, ORG_A, 'kuma') // legacy: bare service name, not JSON
      const map = await redisRbacRepository.getOrgServiceMap()
      expect(map).toEqual({ [ORG_A]: ['kuma'] })
    })

    it('serves a mix of legacy scalar and new array values correctly', async () => {
      redisMock.seedRaw(KEY, ORG_A, 'kuma')                 // legacy scalar
      redisMock.seedRaw(KEY, ORG_B, '["fleet","kuma"]')     // new array
      const map = await redisRbacRepository.getOrgServiceMap()
      expect(map).toEqual({ [ORG_A]: ['kuma'], [ORG_B]: ['fleet', 'kuma'] })
    })

    it('treats a legacy value that is valid JSON but not an array as a scalar name', async () => {
      // A bare "123"/"true"/"null" parses as JSON but is not an array; it must
      // be read as the legacy service name, never silently dropped.
      redisMock.seedRaw(KEY, ORG_A, 'null')
      redisMock.seedRaw(KEY, ORG_B, '123')
      const map = await redisRbacRepository.getOrgServiceMap()
      expect(map).toEqual({ [ORG_A]: ['null'], [ORG_B]: ['123'] })
    })
  })

  describe('getServiceForOrg (single-service resolver)', () => {
    it('returns the first service of a bundle', async () => {
      await redisRbacRepository.setOrgServiceMapping(ORG_A, ['kuma', 'fleet'])
      expect(await redisRbacRepository.getServiceForOrg(ORG_A)).toBe('kuma')
    })

    it('returns the legacy scalar unchanged', async () => {
      redisMock.seedRaw(KEY, ORG_A, 'kuma')
      expect(await redisRbacRepository.getServiceForOrg(ORG_A)).toBe('kuma')
    })

    it('returns null for an unmapped org', async () => {
      expect(await redisRbacRepository.getServiceForOrg(ORG_A)).toBeNull()
    })
  })

  describe('deleteOrgServiceMapping', () => {
    it('removes a mapping and reports whether one existed', async () => {
      await redisRbacRepository.setOrgServiceMapping(ORG_A, ['kuma'])
      expect(await redisRbacRepository.deleteOrgServiceMapping(ORG_A)).toBe(true)
      expect(await redisRbacRepository.getOrgServiceMap()).toEqual({})
      expect(await redisRbacRepository.deleteOrgServiceMapping(ORG_A)).toBe(false)
    })
  })
})
