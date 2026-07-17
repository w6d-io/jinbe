import { randomUUID } from 'node:crypto'
import { getRedisClient } from './redis-client.service.js'

/**
 * Compare-and-delete: only release the lock if we still own it. Prevents a
 * caller whose critical section overran the TTL (so the lock was reclaimed by
 * someone else) from deleting the new owner's lock.
 */
const RELEASE_LUA =
  "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"

export interface LockOptions {
  /** Auto-expiry so a crashed holder can't deadlock the key. Must exceed the
   *  worst-case critical-section time. Default 10s. */
  ttlMs?: number
  /** Max time to wait to acquire before failing closed. Default 5s. */
  waitMs?: number
  /** Poll interval while waiting. Default 50ms. */
  retryMs?: number
}

/**
 * Run `fn` while holding a Redis mutex `rbac:lock:<name>`.
 *
 * Serializes read-modify-write sections that would otherwise lose updates when
 * two callers GET → mutate-in-memory → SET the same key/hash concurrently (the
 * last writer clobbers the first's committed change despite both returning 200).
 *
 * Fail-closed: if the lock can't be acquired within `waitMs`, this THROWS
 * (statusCode 503) rather than proceeding unserialized — a refused mutation the
 * caller can retry is safer than a silent lost update.
 */
export async function withRedisLock<T>(
  name: string,
  fn: () => Promise<T>,
  opts: LockOptions = {},
): Promise<T> {
  const ttlMs = opts.ttlMs ?? 10_000
  const waitMs = opts.waitMs ?? 5_000
  const retryMs = opts.retryMs ?? 50
  const redis = getRedisClient()
  const key = `rbac:lock:${name}`
  const token = randomUUID()
  const deadline = Date.now() + waitMs

  let acquired = false
  for (;;) {
    // SET key token NX PX ttl — atomic acquire; returns 'OK' or null.
    const res = await redis.set(key, token, 'PX', ttlMs, 'NX')
    if (res === 'OK') {
      acquired = true
      break
    }
    if (Date.now() >= deadline) break
    await new Promise((r) => setTimeout(r, retryMs))
  }
  if (!acquired) {
    throw Object.assign(
      new Error(`Could not acquire lock '${name}' within ${waitMs}ms — another operation is in progress; please retry.`),
      { statusCode: 503 },
    )
  }

  try {
    return await fn()
  } finally {
    // Best-effort release; if it fails, the TTL reaps the lock.
    try {
      await redis.eval(RELEASE_LUA, 1, key, token)
    } catch {
      /* ignore — TTL guarantees eventual release */
    }
  }
}
