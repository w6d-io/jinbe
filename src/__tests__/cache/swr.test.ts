import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { register } from 'prom-client'
import { SwrCache, configureCache, onInvalidate, resetCaches } from '../../cache/swr.js'
import { MemoryCacheStore, type CacheStore } from '../../cache/store.js'

/**
 * The shared read cache engine: freshness, single-flight, invalidation (key, namespace, cross-replica),
 * the kill switch, and degrading when Redis is gone.
 */

let store: MemoryCacheStore
let n = 0
const ns = () => `test.${++n}`
const deferred = <T>() => {
  let resolve!: (v: T) => void
  const promise = new Promise<T>((r) => { resolve = r })
  return { promise, resolve }
}

beforeEach(() => {
  store = new MemoryCacheStore()
  configureCache({ enabled: true, disabled: [], store })
})
afterEach(() => {
  vi.useRealTimers()
  configureCache({ enabled: true, disabled: [] })
  resetCaches()
})

describe('freshness', () => {
  it('serves a fresh entry without asking again, then stale while ONE refresh runs', async () => {
    vi.useFakeTimers()
    const cache = new SwrCache<number>({ namespace: ns(), freshMs: 1_000, staleMs: 10_000 })
    let v = 0
    const load = vi.fn(async () => ++v)
    expect(await cache.get('k', load)).toBe(1)
    expect(await cache.get('k', load)).toBe(1)
    expect(load).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(1_500)
    // Stale: answered at once with the old value, refreshed behind.
    expect(await cache.get('k', load)).toBe(1)
    await vi.waitFor(() => expect(load).toHaveBeenCalledTimes(2))
    expect(await cache.get('k', load)).toBe(2)
  })

  it('expires outright after staleMs', async () => {
    vi.useFakeTimers()
    const cache = new SwrCache<number>({ namespace: ns(), freshMs: 1_000, staleMs: 2_000 })
    let v = 0
    const load = vi.fn(async () => ++v)
    await cache.get('k', load)
    vi.advanceTimersByTime(2_500)
    expect(await cache.get('k', load)).toBe(2)
  })

  it('maxAgeMs: a caller that cannot use stale data waits for the refresh', async () => {
    vi.useFakeTimers()
    const cache = new SwrCache<number>({ namespace: ns(), freshMs: 10_000, staleMs: 60_000 })
    let v = 0
    const load = vi.fn(async () => ++v)
    await cache.get('k', load)
    vi.advanceTimersByTime(6_000)
    expect(await cache.get('k', load)).toBe(1) // fresh for a display caller
    expect(await cache.get('k', load, { maxAgeMs: 5_000 })).toBe(2) // too old for this one
  })

  it('a value computed on one replica is served from the shared store on another', async () => {
    const name = ns()
    const a = new SwrCache<string>({ namespace: name, freshMs: 5_000, staleMs: 60_000 })
    await a.get('k', async () => 'from-a')
    a.resetLocal() // what a second process sees: nothing in memory, the store shared
    const load = vi.fn(async () => 'from-b')
    expect(await a.get('k', load)).toBe('from-a')
    expect(load).not.toHaveBeenCalled()
  })
})

describe('single-flight', () => {
  it('concurrent misses share one upstream call', async () => {
    const cache = new SwrCache<string>({ namespace: ns(), freshMs: 5_000, staleMs: 60_000 })
    const gate = deferred<string>()
    const load = vi.fn(() => gate.promise)
    const all = Promise.all(Array.from({ length: 20 }, () => cache.get('k', load)))
    await new Promise((r) => setTimeout(r, 5))
    gate.resolve('v')
    expect(await all).toEqual(Array(20).fill('v'))
    expect(load).toHaveBeenCalledTimes(1)
  })

  it('waits for the replica holding the refresh lock instead of asking the upstream again', async () => {
    const name = ns()
    const cache = new SwrCache<string>({ namespace: name, freshMs: 5_000, staleMs: 60_000 })
    await store.setNx(`cache:v1:lock:${name}:0:k`, 'other-replica', 30_000)
    const load = vi.fn(async () => 'mine')
    const pending = cache.get('k', load)
    await new Promise((r) => setTimeout(r, 30))
    await store.set(`cache:v1:${name}:0:k`, JSON.stringify({ a: Date.now(), v: 'theirs' }), 60_000)
    expect(await pending).toBe('theirs')
    expect(load).not.toHaveBeenCalled()
  })

  it('getMany loads every missing key in ONE call and serves the rest from cache', async () => {
    const cache = new SwrCache<string>({ namespace: ns(), freshMs: 5_000, staleMs: 60_000 })
    const loadMany = vi.fn(async (keys: string[]) => new Map(keys.filter((k) => k !== 'ghost').map((k) => [k, k.toUpperCase()])))
    const first = await cache.getMany(['a', 'b', 'ghost'], loadMany)
    expect([...first]).toEqual([['a', 'A'], ['b', 'B']])
    const second = await cache.getMany(['a', 'b', 'c'], loadMany)
    expect(second.get('c')).toBe('C')
    expect(loadMany).toHaveBeenCalledTimes(2)
    expect(loadMany.mock.calls[1][0]).toEqual(['c'])
  })
})

describe('batch single-flight', () => {
  it('stale keys are refreshed by ONE batch however many reads see them stale', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const cache = new SwrCache<string>({ namespace: ns(), freshMs: 1_000, staleMs: 60_000 })
    const loadMany = vi.fn(async (keys: string[]) => new Map(keys.map((k) => [k, k])))
    await cache.getMany(['a', 'b'], loadMany)
    vi.setSystemTime(Date.now() + 2_000)
    const gate = deferred<void>()
    loadMany.mockImplementationOnce(async (keys: string[]) => { await gate.promise; return new Map(keys.map((k) => [k, k + '2'])) })
    await cache.getMany(['a', 'b'], loadMany)
    await cache.getMany(['a', 'b'], loadMany)
    await cache.getMany(['a', 'b'], loadMany)
    expect(loadMany).toHaveBeenCalledTimes(2)
    gate.resolve()
  })

  it('a missing key already being loaded by another batch is waited for, not asked again', async () => {
    const cache = new SwrCache<string>({ namespace: ns(), freshMs: 5_000, staleMs: 60_000 })
    const gate = deferred<void>()
    const loadMany = vi.fn(async (keys: string[]) => { await gate.promise; return new Map(keys.map((k) => [k, k])) })
    const first = cache.getMany(['a', 'b'], loadMany)
    await new Promise((r) => setTimeout(r, 5))
    const second = cache.getMany(['b', 'c'], loadMany)
    await new Promise((r) => setTimeout(r, 5))
    gate.resolve()
    expect([...(await second).keys()].sort()).toEqual(['b', 'c'])
    await first
    expect(loadMany).toHaveBeenCalledTimes(2)
    expect(loadMany.mock.calls[1][0]).toEqual(['c'])
  })
})

describe('failures', () => {
  it('a failed refresh never replaces a good value, and a failed cold read is not cached', async () => {
    vi.useFakeTimers()
    const cache = new SwrCache<string>({ namespace: ns(), freshMs: 1_000, staleMs: 60_000 })
    await cache.get('k', async () => 'good')
    vi.advanceTimersByTime(2_000)
    const failing = vi.fn(async () => { throw new Error('upstream down') })
    expect(await cache.get('k', failing)).toBe('good')
    await vi.waitFor(() => expect(failing).toHaveBeenCalledTimes(1))
    expect(await cache.get('k', failing)).toBe('good')

    await expect(cache.get('cold', failing)).rejects.toThrow('upstream down')
    expect(await cache.get('cold', async () => 'recovered')).toBe('recovered')
  })

  it('without Redis: computes, keeps a fresh copy in process, never throws a store error', async () => {
    const down = async () => { throw new Error('ECONNREFUSED') }
    const broken: CacheStore = {
      get: down, mget: down, set: down, setNx: down, del: down, delIfEquals: down, incr: down, bump: down,
      writeUnlessInvalidated: down, publish: down, subscribe: () => {}, busHealthy: () => false, onBusGap: () => {},
    }
    configureCache({ store: broken })
    const cache = new SwrCache<number>({ namespace: ns(), freshMs: 5_000, staleMs: 60_000 })
    const load = vi.fn(async () => 7)
    expect(await cache.get('k', load)).toBe(7)
    expect(await cache.get('k', load)).toBe(7)
    expect(load).toHaveBeenCalledTimes(1)
    await expect(cache.invalidate('k')).resolves.toBeUndefined()
  })
})

describe('invalidation', () => {
  it('one key: the next read asks again, immediately', async () => {
    const cache = new SwrCache<number>({ namespace: ns(), freshMs: 60_000, staleMs: 600_000 })
    let v = 0
    const load = async () => ++v
    await cache.get('k', load)
    await cache.get('other', load)
    await cache.invalidate('k')
    expect(await cache.get('k', load)).toBe(3)
    expect(await cache.get('other', load)).toBe(2)
  })

  it('a read issued right after a NOT-awaited invalidation still does not see the old value', async () => {
    const cache = new SwrCache<number>({ namespace: ns(), freshMs: 60_000, staleMs: 600_000 })
    let v = 0
    const load = async () => ++v
    await cache.get('k', load)
    void cache.invalidate('k')
    expect(await cache.get('k', load)).toBe(2)
  })

  it('a refresh that began before the invalidation does not put its value back', async () => {
    const name = ns()
    const cache = new SwrCache<string>({ namespace: name, freshMs: 60_000, staleMs: 600_000 })
    const gate = deferred<string>()
    const slow = cache.get('k', () => gate.promise)
    await new Promise((r) => setTimeout(r, 5))
    await cache.invalidate('k')
    gate.resolve('before-the-change')
    expect(await slow).toBe('before-the-change') // its own caller asked before the change
    expect(await store.get(`cache:v1:${name}:0:k`)).toBeNull()
    expect(await cache.get('k', async () => 'after')).toBe('after')
  })

  it('the whole namespace: every key, on every replica, through the epoch', async () => {
    const name = ns()
    const cache = new SwrCache<number>({ namespace: name, freshMs: 60_000, staleMs: 600_000 })
    let v = 0
    const load = async () => ++v
    await cache.get('a', load)
    await cache.get('b', load)
    await cache.invalidate()
    expect(await store.get(`cache:v1:epoch:${name}`)).toBe('1')
    expect(await cache.get('a', load)).toBe(3)
    expect(await cache.get('b', load)).toBe(4)
  })

  it('another replica’s invalidation reaches this one over pub/sub (in-process copies and listeners)', async () => {
    const name = ns()
    const cache = new SwrCache<number>({ namespace: name, freshMs: 60_000, staleMs: 600_000, local: true })
    const heard = vi.fn()
    onInvalidate(name, heard)
    let v = 0
    const load = async () => ++v
    await cache.get('k', load)
    await store.publish('jinbe:cache:invalidate', JSON.stringify({ ns: name, key: 'k', origin: 'another-replica' }))
    expect(heard).toHaveBeenCalledWith('k')
    expect(await cache.get('k', load)).toBe(2)
  })

  it('a fresh in-process copy is served without Redis only while invalidations are being received', async () => {
    const name = ns()
    const cache = new SwrCache<number>({ namespace: name, freshMs: 60_000, staleMs: 600_000 })
    await cache.get('k', async () => 1)
    const get = vi.spyOn(store, 'get')
    await cache.get('k', async () => 2)
    expect(get).not.toHaveBeenCalled()

    // Delivery interrupted: the copy may have missed an invalidation, so the store is asked.
    vi.spyOn(store, 'busHealthy').mockReturnValue(false)
    await store.incr(`cache:v1:epoch:${name}`) // another replica invalidated meanwhile
    expect(await cache.get('k', async () => 3)).toBe(3)
  })

  it('a local namespace never writes to the shared store', async () => {
    const name = ns()
    const cache = new SwrCache<string>({ namespace: name, freshMs: 60_000, staleMs: 60_000, local: true })
    const spy = vi.spyOn(store, 'writeUnlessInvalidated')
    await cache.get('k', async () => 'secret-ish')
    expect(spy).not.toHaveBeenCalled()
  })
})

describe('kill switch', () => {
  it('CACHE_ENABLED=false: every read goes upstream, nothing is stored', async () => {
    configureCache({ enabled: false })
    const cache = new SwrCache<number>({ namespace: ns(), freshMs: 60_000, staleMs: 600_000 })
    let v = 0
    const load = vi.fn(async () => ++v)
    expect(await cache.get('k', load)).toBe(1)
    expect(await cache.get('k', load)).toBe(2)
    const many = vi.fn(async (keys: string[]) => new Map(keys.map((k) => [k, 0])))
    await cache.getMany(['a'], many)
    await cache.getMany(['a'], many)
    expect(many).toHaveBeenCalledTimes(2)
  })

  it('CACHE_DISABLED_NAMESPACES turns off one namespace and leaves the others', async () => {
    const off = ns()
    const on = ns()
    configureCache({ disabled: [off] })
    const a = new SwrCache<number>({ namespace: off, freshMs: 60_000, staleMs: 600_000 })
    const b = new SwrCache<number>({ namespace: on, freshMs: 60_000, staleMs: 600_000 })
    const la = vi.fn(async () => 1)
    const lb = vi.fn(async () => 1)
    await a.get('k', la); await a.get('k', la)
    await b.get('k', lb); await b.get('k', lb)
    expect(la).toHaveBeenCalledTimes(2)
    expect(lb).toHaveBeenCalledTimes(1)
  })
})

describe('metrics', () => {
  it('counts hit / miss / stale / bypass and refreshes by namespace', async () => {
    const name = ns()
    const cache = new SwrCache<number>({ namespace: name, freshMs: 60_000, staleMs: 600_000 })
    await cache.get('k', async () => 1)
    await cache.get('k', async () => 1)
    const text = await register.metrics()
    expect(text).toContain(`jinbe_cache_requests_total{namespace="${name}",result="miss"} 1`)
    expect(text).toContain(`jinbe_cache_requests_total{namespace="${name}",result="hit"} 1`)
    expect(text).toContain(`jinbe_cache_refresh_total{namespace="${name}",outcome="ok"} 1`)
  })
})
