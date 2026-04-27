import { vi } from 'vitest'

/**
 * In-memory Redis mock for testing
 *
 * Implements the subset of ioredis commands used by RedisRbacRepository
 */
export class RedisMock {
  private store = new Map<string, string>()
  private hashStore = new Map<string, Map<string, string>>()
  private setStore = new Map<string, Set<string>>()
  private streams = new Map<string, Array<{ id: string; fields: Record<string, string> }>>()

  // String operations
  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null
  }

  async set(key: string, value: string): Promise<'OK'> {
    this.store.set(key, value)
    return 'OK'
  }

  async del(...keys: string[]): Promise<number> {
    let count = 0
    for (const key of keys) {
      if (this.store.delete(key)) count++
      if (this.hashStore.delete(key)) count++
      if (this.setStore.delete(key)) count++
    }
    return count
  }

  // Hash operations
  async hget(key: string, field: string): Promise<string | null> {
    return this.hashStore.get(key)?.get(field) ?? null
  }

  async hset(key: string, field: string, value: string): Promise<number> {
    if (!this.hashStore.has(key)) this.hashStore.set(key, new Map())
    const isNew = !this.hashStore.get(key)!.has(field)
    this.hashStore.get(key)!.set(field, value)
    return isNew ? 1 : 0
  }

  async hdel(key: string, ...fields: string[]): Promise<number> {
    const hash = this.hashStore.get(key)
    if (!hash) return 0
    let count = 0
    for (const field of fields) {
      if (hash.delete(field)) count++
    }
    return count
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    const hash = this.hashStore.get(key)
    if (!hash) return {}
    return Object.fromEntries(hash.entries())
  }

  // Set operations
  async sadd(key: string, ...members: string[]): Promise<number> {
    if (!this.setStore.has(key)) this.setStore.set(key, new Set())
    let count = 0
    for (const member of members) {
      if (!this.setStore.get(key)!.has(member)) {
        this.setStore.get(key)!.add(member)
        count++
      }
    }
    return count
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    const set = this.setStore.get(key)
    if (!set) return 0
    let count = 0
    for (const member of members) {
      if (set.delete(member)) count++
    }
    return count
  }

  async smembers(key: string): Promise<string[]> {
    const set = this.setStore.get(key)
    return set ? Array.from(set) : []
  }

  async sismember(key: string, member: string): Promise<number> {
    const set = this.setStore.get(key)
    return set?.has(member) ? 1 : 0
  }

  // Stream operations
  async xadd(key: string, id: string, ...fieldValues: string[]): Promise<string> {
    if (!this.streams.has(key)) this.streams.set(key, [])
    const fields: Record<string, string> = {}
    for (let i = 0; i < fieldValues.length; i += 2) {
      fields[fieldValues[i]] = fieldValues[i + 1]
    }
    const streamId = id === '*' ? `${Date.now()}-0` : id
    this.streams.get(key)!.push({ id: streamId, fields })
    return streamId
  }

  async xrange(key: string, _start: string, _end: string, ...args: string[]): Promise<Array<[string, string[]]>> {
    const stream = this.streams.get(key) || []
    const count = args.includes('COUNT') ? parseInt(args[args.indexOf('COUNT') + 1]) : stream.length
    return stream.slice(0, count).map(entry => {
      const flat: string[] = []
      for (const [k, v] of Object.entries(entry.fields)) {
        flat.push(k, v)
      }
      return [entry.id, flat]
    })
  }

  async xlen(key: string): Promise<number> {
    return (this.streams.get(key) || []).length
  }

  // Utility
  async ping(): Promise<string> {
    return 'PONG'
  }

  async quit(): Promise<'OK'> {
    return 'OK'
  }

  /**
   * Clear all data (for test isolation)
   */
  clear(): void {
    this.store.clear()
    this.hashStore.clear()
    this.setStore.clear()
    this.streams.clear()
  }
}

/**
 * Create mock for redis-client.service module
 */
export function createRedisMock(): { mock: RedisMock; setup: () => void } {
  const mock = new RedisMock()

  const setup = () => {
    vi.mock('../../../services/redis-client.service.js', () => ({
      redisClientService: {
        getClient: () => mock,
        isHealthy: vi.fn().mockResolvedValue(true),
        disconnect: vi.fn().mockResolvedValue(undefined),
        isConnected: true,
      },
      getRedisClient: () => mock,
    }))
  }

  return { mock, setup }
}

/**
 * Create a hoisted Redis mock for use with vi.hoisted + vi.mock pattern.
 *
 * Usage in test files:
 * ```ts
 * const { redisMock, redisModule } = vi.hoisted(() => hoistedRedisMock())
 * vi.mock('../../../services/redis-client.service.js', () => redisModule)
 * ```
 *
 * NOTE: This function is designed to be called inside vi.hoisted() where
 * external imports are not available. It creates an inline mock class.
 */
export function hoistedRedisMock() {
  class InlineRedisMock {
    store = new Map<string, string>()
    hashStore = new Map<string, Map<string, string>>()
    setStore = new Map<string, Set<string>>()

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
    async ping() { return 'PONG' }
    async quit() { return 'OK' as const }
    clear() { this.store.clear(); this.hashStore.clear(); this.setStore.clear() }
  }

  const mock = new InlineRedisMock()
  return {
    redisMock: mock,
    redisModule: {
      redisClientService: {
        getClient: () => mock,
        isHealthy: () => Promise.resolve(true),
        disconnect: () => Promise.resolve(undefined),
        isConnected: true,
      },
      getRedisClient: () => mock,
    },
  }
}
