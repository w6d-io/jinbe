import { describe, it, expect, beforeEach, vi } from 'vitest'

/**
 * Fake Redis implementing exactly the two commands withRedisLock uses:
 *   SET key val PX <ms> NX   (atomic acquire; returns null if held+alive)
 *   EVAL <lua> 1 key token   (compare-and-del release)
 * with TTL expiry, so we can exercise acquire / contention / release /
 * fail-closed without a real server.
 */
class FakeRedis {
  store = new Map<string, { val: string; expireAt: number }>()

  async set(key: string, val: string, ...args: unknown[]): Promise<'OK' | null> {
    let px: number | undefined
    let nx = false
    for (let i = 0; i < args.length; i++) {
      if (args[i] === 'PX') px = Number(args[i + 1])
      if (args[i] === 'NX') nx = true
    }
    const now = Date.now()
    const cur = this.store.get(key)
    const alive = cur && cur.expireAt > now
    if (nx && alive) return null
    this.store.set(key, { val, expireAt: px ? now + px : Number.POSITIVE_INFINITY })
    return 'OK'
  }

  async eval(_lua: string, _numKeys: number, key: string, token: string): Promise<number> {
    const cur = this.store.get(key)
    if (cur && cur.val === token) {
      this.store.delete(key)
      return 1
    }
    return 0
  }

  /** Plant a foreign lock (as if another holder owns it) for `ttlMs`. */
  plant(key: string, val: string, ttlMs: number): void {
    this.store.set(key, { val, expireAt: Date.now() + ttlMs })
  }
}

const fake = new FakeRedis()
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => fake,
  redisClientService: { getClient: () => fake },
}))

import { withRedisLock } from '../../../services/redis-lock.js'

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms))

describe('withRedisLock', () => {
  beforeEach(() => fake.store.clear())

  it('acquires a free lock, runs fn, returns its value, and releases', async () => {
    const out = await withRedisLock('k', async () => 42)
    expect(out).toBe(42)
    // released → key gone → immediately re-acquirable
    expect(fake.store.has('rbac:lock:k')).toBe(false)
    const again = await withRedisLock('k', async () => 'ok')
    expect(again).toBe('ok')
  })

  it('serializes contended holders — the second waits for the first to release', async () => {
    const order: string[] = []
    let releaseA!: () => void
    const aHeld = new Promise<void>((r) => (releaseA = r))

    const a = withRedisLock('shared', async () => {
      order.push('A:start')
      await aHeld // hold the lock until the test releases it
      order.push('A:end')
      return 'A'
    })

    // Give A time to acquire, then start B (short poll interval).
    await delay(20)
    const b = withRedisLock('shared', async () => {
      order.push('B:start')
      return 'B'
    }, { retryMs: 5, waitMs: 2000 })

    // While A holds, B must NOT have started.
    await delay(40)
    expect(order).toEqual(['A:start'])

    releaseA()
    const [ra, rb] = await Promise.all([a, b])
    expect(ra).toBe('A')
    expect(rb).toBe('B')
    // B only ran after A finished and released.
    expect(order).toEqual(['A:start', 'A:end', 'B:start'])
  })

  it('fails closed (throws) when the lock cannot be acquired within waitMs', async () => {
    // A foreign holder owns the lock for longer than B is willing to wait.
    fake.plant('rbac:lock:busy', 'someone-else', 1000)
    await expect(
      withRedisLock('busy', async () => 'should-not-run', { waitMs: 100, retryMs: 10 }),
    ).rejects.toThrow(/Could not acquire lock/)
  })

  it('release is compare-and-del: never deletes a lock owned by another token', async () => {
    // Simulate our critical section overrunning the TTL so another holder
    // reclaims the key; our release must not delete their lock.
    let planted = false
    const p = withRedisLock('overrun', async () => {
      fake.plant('rbac:lock:overrun', 'new-owner', 5000) // someone else now owns it
      planted = true
      return 'done'
    }, { ttlMs: 50 })
    const r = await p
    expect(r).toBe('done')
    expect(planted).toBe(true)
    // The new owner's lock survives our release (token mismatch → eval no-op).
    expect(fake.store.get('rbac:lock:overrun')?.val).toBe('new-owner')
  })

  it('releases even when fn throws', async () => {
    await expect(withRedisLock('boom', async () => { throw new Error('x') })).rejects.toThrow('x')
    expect(fake.store.has('rbac:lock:boom')).toBe(false)
    // re-acquirable after the throwing section released
    await expect(withRedisLock('boom', async () => 'recovered')).resolves.toBe('recovered')
  })
})
