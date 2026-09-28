import { randomUUID } from 'node:crypto'
import { getRedisClient } from '../services/redis-client.service.js'
import type { Connect, HomeModuleName, ModuleReason, SourceDetail } from './types.js'

/**
 * The Home's stale-while-revalidate cache (home-data §3.6), SHARED in Redis so replicas agree and a
 * slow source is paid once per cluster, not once per pod.
 *
 *   home:v1:<module>:<epoch>:<scopeKey>[:<window>] → { asOf, freshMs, result }
 *
 * A value is fresh for `freshMs`, then served with `stale:true` while one refresh runs; it expires
 * outright at 10 × freshMs, so a dead refresher surfaces as stale and then as unavailable, never as a
 * value that looks current. Refreshes are single-flight twice over: in-process (one promise per key)
 * and across replicas (SET NX lock, so only one pod computes).
 *
 * Invalidation bumps a per-module epoch that is part of the key: no SCAN, no DEL pattern, and a
 * refresh that started before the bump writes under the old epoch where nobody reads it.
 */

export type ModuleResult<T = unknown> =
  | { status: 'ok'; data: T; sources: Record<string, SourceDetail> }
  | { status: 'unavailable'; reason: ModuleReason; sources: Record<string, SourceDetail>; connect?: Connect }

export interface Stored<T = unknown> {
  /** ms epoch the result was computed at. */
  asOf: number
  freshMs: number
  result: ModuleResult<T>
}

const PREFIX = 'home:v1'
const LOCK_MS = 30_000
const TTL_FACTOR = 10

export const epochKey = (module: HomeModuleName) => `${PREFIX}:epoch:${module}`
export const cacheKey = (module: HomeModuleName, epoch: string, scopeKey: string, window?: string) =>
  `${PREFIX}:${module}:${epoch}:${scopeKey}${window ? `:${window}` : ''}`

/** One round trip for every module's epoch. Unreadable → '0' (the cache then simply misses). */
export async function readEpochs(modules: readonly HomeModuleName[]): Promise<Record<string, string>> {
  const out: Record<string, string> = {}
  try {
    const values = await getRedisClient().mget(...modules.map(epochKey))
    modules.forEach((m, i) => { out[m] = values[i] ?? '0' })
  } catch {
    for (const m of modules) out[m] = '0'
  }
  return out
}

/** One round trip for every cached module. A Redis blip reads as a miss, never as an error. */
export async function readMany(keys: string[]): Promise<Array<Stored | null>> {
  if (keys.length === 0) return []
  try {
    const values = await getRedisClient().mget(...keys)
    return values.map((v) => {
      if (!v) return null
      try {
        return JSON.parse(v) as Stored
      } catch {
        return null
      }
    })
  } catch {
    return keys.map(() => null)
  }
}

export const isFresh = (s: Stored, now = Date.now()) => now - s.asOf < s.freshMs

const inflight = new Map<string, Promise<Stored | null>>()

/**
 * Computes and stores one key, once. Resolves with what was stored, or null when another replica
 * holds the lock (it will write the value; this caller serves what it has). A compute that throws
 * never overwrites a good value — that value goes on being served, stale, until it expires — and on
 * a cold key it is stored as `source_down` for one fresh window so a dead source is not hammered.
 */
export function refresh<T>(key: string, freshMs: number, compute: () => Promise<ModuleResult<T>>): Promise<Stored<T> | null> {
  const running = inflight.get(key)
  if (running) return running as Promise<Stored<T> | null>
  const p = (async (): Promise<Stored<T> | null> => {
    const redis = getRedisClient()
    const lockKey = `${PREFIX}:lock:${key}`
    const token = randomUUID()
    let locked = true
    try {
      locked = (await redis.set(lockKey, token, 'PX', LOCK_MS, 'NX')) === 'OK'
    } catch {
      // Redis down: compute anyway (the answer is still worth returning), store nothing.
      locked = true
    }
    if (!locked) return null
    try {
      let stored: Stored<T>
      try {
        stored = { asOf: Date.now(), freshMs, result: await compute() }
      } catch {
        const previous = (await readMany([key]))[0]
        if (previous?.result.status === 'ok') return previous as Stored<T>
        stored = { asOf: Date.now(), freshMs, result: { status: 'unavailable', reason: 'source_down', sources: {} } }
      }
      await redis.set(key, JSON.stringify(stored), 'PX', freshMs * TTL_FACTOR).catch(() => {})
      return stored
    } finally {
      // Only our own lock: one that expired and was taken by another replica is theirs.
      try {
        if ((await redis.get(lockKey)) === token) await redis.del(lockKey)
      } catch {
        // it expires on its own
      }
    }
  })()
  inflight.set(key, p)
  void p.finally(() => { if (inflight.get(key) === p) inflight.delete(key) }).catch(() => {})
  return p
}

/**
 * Drops every cached value of these modules (a mutation changed what they show). Best-effort and
 * synchronous for the caller: a failed bump only means the change shows at the next fresh window.
 */
export function invalidateHome(modules: readonly HomeModuleName[]): void {
  try {
    const redis = getRedisClient()
    for (const m of modules) void redis.incr(epochKey(m)).catch(() => {})
  } catch {
    // no Redis client: nothing cached either
  }
}

/** Test seam. */
export function resetHomeCacheState(): void {
  inflight.clear()
}

/** The current cached value of one module for one partition, if any (a module reading another's). */
export async function peek(module: HomeModuleName, scopeKey: string, window?: string): Promise<Stored | null> {
  const epochs = await readEpochs([module])
  return (await readMany([cacheKey(module, epochs[module], scopeKey, window)]))[0]
}
