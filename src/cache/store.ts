import type Redis from 'ioredis'
import { getRedisClient } from '../services/redis-client.service.js'

/**
 * Where the shared cache keeps its entries: Redis (shared by every replica) or process memory (tests,
 * and a deployment without Redis). The engine (swr.ts) only speaks this interface.
 *
 * Every Redis call is bounded: a slow or absent Redis must cost a cache miss, never a request, so an
 * operation that has not answered in OP_TIMEOUT_MS rejects and the engine computes from upstream.
 */
export interface CacheStore {
  get(key: string): Promise<string | null>
  mget(keys: string[]): Promise<Array<string | null>>
  set(key: string, value: string, ttlMs: number): Promise<void>
  /** SET NX PX: true when this caller now holds the key. */
  setNx(key: string, value: string, ttlMs: number): Promise<boolean>
  del(key: string): Promise<void>
  /** Deletes the key only while it still holds `value` (releasing one's own lock). */
  delIfEquals(key: string, value: string): Promise<void>
  incr(key: string): Promise<number>
  /** INCR with an expiry: the invalidation counter of one key. */
  bump(key: string, ttlMs: number): Promise<number>
  /**
   * Writes `value` only while `tombKey` still reads `expected` (what it read when the refresh began):
   * a refresh that began before its key was invalidated must not put back what the invalidation
   * removed. Atomic, and a counter rather than a timestamp so replica clocks never matter.
   */
  writeUnlessInvalidated(key: string, value: string, ttlMs: number, tombKey: string, expected: string): Promise<boolean>
  publish(channel: string, message: string): Promise<void>
  subscribe(channel: string, onMessage: (message: string) => void): void
  /**
   * Whether invalidations published by other replicas are being received right now. While true, a
   * fresh in-process copy may be served without asking the store; `onBusGap` runs whenever delivery
   * was interrupted (messages may have been missed).
   */
  busHealthy(): boolean
  onBusGap(fn: () => void): void
}

const OP_TIMEOUT_MS = 250

function bounded<T>(p: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('cache store timeout')), OP_TIMEOUT_MS)
    timer.unref?.()
  })
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer))
}

const WRITE_UNLESS_INVALIDATED = `
if (redis.call('GET', KEYS[2]) or '0') ~= ARGV[3] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1`

const BUMP = `
local n = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return n`

const DEL_IF_EQUALS = `
if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end
return 0`

export class RedisCacheStore implements CacheStore {
  private sub: Redis | null = null
  private handlers = new Map<string, Set<(message: string) => void>>()
  private subscribed = false
  private gapHandlers = new Set<() => void>()

  constructor(private readonly client: () => Redis = getRedisClient) {}

  async get(key: string) {
    return bounded(this.client().get(key))
  }
  async mget(keys: string[]) {
    if (keys.length === 0) return []
    return bounded(this.client().mget(...keys))
  }
  async set(key: string, value: string, ttlMs: number) {
    await bounded(this.client().set(key, value, 'PX', Math.max(1, Math.round(ttlMs))))
  }
  async setNx(key: string, value: string, ttlMs: number) {
    return (await bounded(this.client().set(key, value, 'PX', Math.max(1, Math.round(ttlMs)), 'NX'))) === 'OK'
  }
  async del(key: string) {
    await bounded(this.client().del(key))
  }
  async delIfEquals(key: string, value: string) {
    await bounded(this.client().eval(DEL_IF_EQUALS, 1, key, value))
  }
  async incr(key: string) {
    return bounded(this.client().incr(key))
  }
  async bump(key: string, ttlMs: number) {
    return Number(await bounded(this.client().eval(BUMP, 1, key, String(Math.max(1, Math.round(ttlMs))))))
  }
  async writeUnlessInvalidated(key: string, value: string, ttlMs: number, tombKey: string, expected: string) {
    const r = await bounded(
      this.client().eval(WRITE_UNLESS_INVALIDATED, 2, key, tombKey, value, String(Math.max(1, Math.round(ttlMs))), expected),
    )
    return r === 1
  }
  async publish(channel: string, message: string) {
    await bounded(this.client().publish(channel, message))
  }
  subscribe(channel: string, onMessage: (message: string) => void) {
    let set = this.handlers.get(channel)
    if (!set) {
      set = new Set()
      this.handlers.set(channel, set)
      try {
        if (!this.sub) {
          this.sub = this.client().duplicate()
          this.sub.on('message', (ch: string, msg: string) => {
            for (const h of this.handlers.get(ch) ?? []) h(msg)
          })
          this.sub.on('error', () => {})
          // Anything published while we were not listening is lost: say so, so copies are dropped.
          this.sub.on('close', () => {
            if (!this.subscribed) return
            this.subscribed = false
            for (const fn of this.gapHandlers) fn()
          })
          // ioredis re-subscribes on reconnect; delivery resumes once it is ready again.
          this.sub.on('ready', () => {
            this.subscribed = true
          })
        }
        this.sub.subscribe(channel).then(() => { this.subscribed = true }).catch(() => {})
      } catch {
        // No Redis: invalidations stay local to this replica, and the TTLs bound the rest.
      }
    }
    set.add(onMessage)
  }
  busHealthy() {
    return this.subscribed && this.sub?.status === 'ready'
  }
  onBusGap(fn: () => void) {
    this.gapHandlers.add(fn)
  }
}

/** Process-local store with the same semantics (TTL, NX, the invalidation guard, pub/sub). */
export class MemoryCacheStore implements CacheStore {
  private data = new Map<string, { value: string; expiresAt: number }>()
  private handlers = new Map<string, Set<(message: string) => void>>()

  private live(key: string) {
    const e = this.data.get(key)
    if (!e) return null
    if (Date.now() >= e.expiresAt) {
      this.data.delete(key)
      return null
    }
    return e
  }
  async get(key: string) {
    return this.live(key)?.value ?? null
  }
  async mget(keys: string[]) {
    return keys.map((k) => this.live(k)?.value ?? null)
  }
  async set(key: string, value: string, ttlMs: number) {
    this.data.set(key, { value, expiresAt: Date.now() + ttlMs })
  }
  async setNx(key: string, value: string, ttlMs: number) {
    if (this.live(key)) return false
    this.data.set(key, { value, expiresAt: Date.now() + ttlMs })
    return true
  }
  async del(key: string) {
    this.data.delete(key)
  }
  async delIfEquals(key: string, value: string) {
    if (this.live(key)?.value === value) this.data.delete(key)
  }
  async incr(key: string) {
    const next = Number(this.live(key)?.value ?? 0) + 1
    this.data.set(key, { value: String(next), expiresAt: Number.POSITIVE_INFINITY })
    return next
  }
  async bump(key: string, ttlMs: number) {
    const next = Number(this.live(key)?.value ?? 0) + 1
    this.data.set(key, { value: String(next), expiresAt: Date.now() + ttlMs })
    return next
  }
  async writeUnlessInvalidated(key: string, value: string, ttlMs: number, tombKey: string, expected: string) {
    if ((this.live(tombKey)?.value ?? '0') !== expected) return false
    await this.set(key, value, ttlMs)
    return true
  }
  async publish(channel: string, message: string) {
    for (const h of this.handlers.get(channel) ?? []) h(message)
  }
  subscribe(channel: string, onMessage: (message: string) => void) {
    let set = this.handlers.get(channel)
    if (!set) this.handlers.set(channel, (set = new Set()))
    set.add(onMessage)
  }
  busHealthy() {
    return true
  }
  onBusGap() {}
  /** Test seam. */
  clear() {
    this.data.clear()
  }
}
