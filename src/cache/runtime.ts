import { randomUUID } from 'node:crypto'
import { env } from '../config/env.js'
import { MemoryCacheStore, RedisCacheStore, type CacheStore } from './store.js'

/**
 * The cache engine's process-wide state (swr.ts): configuration and kill switch, the store, the
 * registry of namespaces, and the invalidation channel every replica listens on.
 */

/** What a namespace exposes to the invalidation channel. */
export interface Invalidatable {
  dropLocal(key?: string): void
  resetLocal(): void
}

export const CHANNEL = 'jinbe:cache:invalidate'
export const ORIGIN = randomUUID()

// ── configuration (env, with a test seam) ──────────────────────────────────────

// Read defensively: a suite that mocks the env module with a few keys must still get a working cache.
const fromEnv = () => ({
  enabled: env.CACHE_ENABLED !== false,
  disabled: new Set<string>(env.CACHE_DISABLED_NAMESPACES ?? []),
})
let config = fromEnv()
let store: CacheStore | null = null
let busReady = false
const registry = new Map<string, Invalidatable>()
const listeners = new Map<string, Set<(key?: string) => void>>()

export function getStore(): CacheStore {
  if (!store) store = env.CACHE_STORE === 'redis' ? new RedisCacheStore() : new MemoryCacheStore()
  return store
}

/** Whether a namespace is cached at all (the kill switch). */
export function cacheEnabled(namespace: string): boolean {
  return config.enabled && !config.disabled.has(namespace)
}

export function ensureBus(): void {
  if (busReady) return
  busReady = true
  getStore().onBusGap(() => {
    for (const c of registry.values()) c.dropLocal()
  })
  getStore().subscribe(CHANNEL, (message) => {
    let msg: { ns?: string; key?: string; origin?: string }
    try {
      msg = JSON.parse(message)
    } catch {
      return
    }
    if (!msg.ns || msg.origin === ORIGIN) return
    applyLocally(msg.ns, msg.key)
  })
}

export function applyLocally(namespace: string, key?: string): void {
  registry.get(namespace)?.dropLocal(key)
  for (const fn of listeners.get(namespace) ?? []) {
    try {
      fn(key)
    } catch {
      // a listener's failure is its own
    }
  }
}

/** Runs `fn` whenever this namespace is invalidated, on any replica. */
export function onInvalidate(namespace: string, fn: (key?: string) => void): void {
  let set = listeners.get(namespace)
  if (!set) listeners.set(namespace, (set = new Set()))
  set.add(fn)
}

/** Called by each namespace once, so invalidations reach it. */
export function registerCache(namespace: string, cache: Invalidatable): void {
  registry.set(namespace, cache)
}

/** Test seam: the kill switch, and a fresh store. */
export function configureCache(opts: { enabled?: boolean; disabled?: string[]; store?: CacheStore } = {}): void {
  const base = fromEnv()
  config = {
    enabled: opts.enabled ?? base.enabled,
    disabled: opts.disabled ? new Set(opts.disabled) : base.disabled,
  }
  if (opts.store) {
    store = opts.store
    busReady = false
  }
}

/** Test seam: forget every cached value in the process (and the memory store). */
export function resetCaches(): void {
  for (const c of registry.values()) c.resetLocal()
  if (store instanceof MemoryCacheStore) store.clear()
}

