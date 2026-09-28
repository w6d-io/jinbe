import { randomUUID } from 'node:crypto'
import { cacheInvalidations, cacheRefreshDuration, cacheRefreshes, cacheRequests } from '../telemetry/metrics.js'
import { CHANNEL, ORIGIN, applyLocally, cacheEnabled, ensureBus, getStore, registerCache } from './runtime.js'

export { cacheEnabled, configureCache, onInvalidate, resetCaches } from './runtime.js'

/**
 * The shared read cache: stale-while-revalidate over slow upstream reads, one engine for all of them.
 *
 *   cache:v1:<namespace>:<epoch>:<key> → { a: asOf, v: value }
 *
 * An entry is FRESH for `freshMs` and served as is; then STALE until `staleMs`, served at once while
 * one refresh runs in the background; then gone. A caller that cannot use stale data (the OPAL feed,
 * an authorization answer) passes `maxAgeMs` and waits for a refresh instead.
 *
 * Refreshes are single-flight twice over: one promise per key in the process, and a Redis lock across
 * replicas (a replica that finds the lock taken waits for the holder's value rather than paying the
 * upstream a second time). A refresh that fails never replaces a good value.
 *
 * Invalidation is explicit and by event:
 *   - a whole namespace bumps its epoch, which is part of every key: no SCAN, no DEL pattern, and a
 *     refresh that started before the bump writes under the old epoch where nobody reads;
 *   - one key deletes its value and bumps its invalidation counter, and a refresh only writes if the
 *     counter still reads what it read when it began, so a slow refresh cannot put back what the
 *     invalidation removed.
 * Both are published on a pub/sub channel so every replica drops its in-process copy (L1) and
 * in-process single-flight at once. The epoch/counter in Redis are the source of truth; the channel
 * only makes the in-process layer follow without a round trip per read.
 *
 * What goes in: RAW UPSTREAM DATA keyed by what it is about (the directory, an identity id, an org
 * id, an OPA question) — never a view computed for a caller, never a session or a credential. Views
 * are computed per request from the cached data, so the cache cannot hand one caller another's view.
 *
 * Kill switch: CACHE_ENABLED=false (or the namespace in CACHE_DISABLED_NAMESPACES) makes every read go
 * straight to the upstream, with no in-process caching or single-flight either.
 *
 * Redis failures degrade, never fail: a read that cannot reach Redis uses the process-local copy while
 * it is fresh and otherwise computes from the upstream.
 */

/**
 * The oldest snapshot of an upstream (the Kratos directory) a cache DERIVED from it (the stats, the access review, the Home) may be
 * computed from: a stale-while-revalidate over another would otherwise stamp a ten-minute-old
 * directory as fresh.
 */
export const DERIVED_MAX_AGE_MS = 30_000

export interface CacheSpec<T> {
  namespace: string
  /** Served without a refresh for this long. */
  freshMs: number
  /** Served (stale, refreshing) until this age; then the entry no longer exists. >= freshMs. */
  staleMs: number
  /** Process-local only: never written to the shared store (authorization answers). */
  local?: boolean
  /** Cross-replica refresh lock lifetime. */
  lockMs?: number
  /** JSON-safe form of a value, and back (a Map, for instance). */
  encode?: (value: T) => unknown
  decode?: (raw: unknown) => T
  /** Process-local entries kept, oldest dropped first. */
  l1Max?: number
}

export interface ReadOptions {
  /** Entries older than this are not served: the read waits for a refresh. */
  maxAgeMs?: number
}

interface L1Entry<T> {
  asOf: number
  value: T
  epoch: string
  gen: number
}

const PREFIX = 'cache:v1'
const WAIT_STEP_MS = 25
const WAIT_MAX_MS = 5_000

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export class SwrCache<T> {
  readonly namespace: string
  private readonly spec: Required<Omit<CacheSpec<T>, 'encode' | 'decode'>> & Pick<CacheSpec<T>, 'encode' | 'decode'>
  private l1 = new Map<string, L1Entry<T>>()
  private inflight = new Map<string, Promise<T>>()
  /** Keys a getMany batch is loading right now: later batches wait for them instead of asking again. */
  private batchInflight = new Map<string, Promise<T | undefined>>()
  private nsGen = 0
  private keyGen = new Map<string, number>()
  /** Invalidations still being recorded in Redis: reads wait for them, so none sees what they drop. */
  private pending = new Set<Promise<void>>()

  constructor(spec: CacheSpec<T>) {
    this.namespace = spec.namespace
    this.spec = {
      local: false,
      lockMs: 30_000,
      l1Max: 500,
      ...spec,
      staleMs: Math.max(spec.staleMs, spec.freshMs),
    }
    registerCache(spec.namespace, this)
  }

  // ── keys ──

  private epochKey() {
    return `${PREFIX}:epoch:${this.namespace}`
  }
  private valueKey(epoch: string, key: string) {
    return `${PREFIX}:${this.namespace}:${epoch}:${key}`
  }
  private tombKey(epoch: string, key: string) {
    return `${PREFIX}:tomb:${this.namespace}:${epoch}:${key}`
  }
  private lockKey(epoch: string, key: string) {
    return `${PREFIX}:lock:${this.namespace}:${epoch}:${key}`
  }
  private gen(key: string) {
    return this.nsGen * 1_000_003 + (this.keyGen.get(key) ?? 0)
  }

  private serialise(asOf: number, value: T): string {
    return JSON.stringify({ a: asOf, v: this.spec.encode ? this.spec.encode(value) : value })
  }
  private parse(raw: string | null): { asOf: number; value: T } | null {
    if (!raw) return null
    try {
      const o = JSON.parse(raw) as { a?: number; v?: unknown }
      if (typeof o.a !== 'number') return null
      return { asOf: o.a, value: this.spec.decode ? this.spec.decode(o.v) : (o.v as T) }
    } catch {
      return null
    }
  }

  private remember(key: string, entry: L1Entry<T>) {
    this.l1.delete(key)
    this.l1.set(key, entry)
    if (this.l1.size > this.spec.l1Max) {
      const oldest = this.l1.keys().next().value
      if (oldest !== undefined) this.l1.delete(oldest)
    }
  }

  /** Drops the in-process copy (one key, or all) and detaches any refresh already running for it. */
  dropLocal(key?: string): void {
    if (key === undefined) {
      this.nsGen++
      this.l1.clear()
      this.batchInflight.clear()
    } else {
      this.keyGen.set(key, (this.keyGen.get(key) ?? 0) + 1)
      this.l1.delete(key)
      this.batchInflight.delete(key)
    }
  }

  private async readEpoch(): Promise<string | null> {
    if (this.spec.local) return 'L'
    try {
      return (await getStore().get(this.epochKey())) ?? '0'
    } catch {
      return null
    }
  }

  // ── reads ──

  /** The value for `key`, from the cache when it may be served, else from `load` (once). */
  async get(key: string, load: () => Promise<T>, opts: ReadOptions = {}): Promise<T> {
    const ns = this.namespace
    if (!cacheEnabled(ns)) {
      cacheRequests.inc({ namespace: ns, result: 'bypass' })
      return load()
    }
    ensureBus()
    if (this.pending.size) await Promise.all(this.pending)
    const maxAge = Math.min(opts.maxAgeMs ?? this.spec.staleMs, this.spec.staleMs)
    const now = Date.now()
    const gen = this.gen(key)

    // Fast path: a fresh in-process copy, while other replicas' invalidations are reaching this one
    // (they drop it the moment they arrive), is served without a round trip to Redis.
    const cached = this.l1.get(key)
    if (cached && cached.gen === gen && !this.spec.local && getStore().busHealthy() && now - cached.asOf < Math.min(this.spec.freshMs, maxAge)) {
      cacheRequests.inc({ namespace: ns, result: 'hit' })
      return cached.value
    }

    const epoch = await this.readEpoch()
    const degraded = epoch === null

    const local = this.l1.get(key)
    if (local && local.gen === gen && (degraded || local.epoch === epoch)) {
      const age = now - local.asOf
      if (age < Math.min(this.spec.freshMs, maxAge)) {
        cacheRequests.inc({ namespace: ns, result: 'hit' })
        return local.value
      }
      // A process-local namespace serves its own stale copy. A shared one reads Redis below (a newer
      // value may be there), and without Redis only fresh copies are trusted: nobody can tell this
      // replica about invalidations then.
      if (this.spec.local && age < maxAge) {
        cacheRequests.inc({ namespace: ns, result: 'stale' })
        void this.refresh(key, epoch!, load, true).catch(() => {})
        return local.value
      }
    }

    if (!degraded && !this.spec.local) {
      let shared: { asOf: number; value: T } | null = null
      try {
        shared = this.parse(await getStore().get(this.valueKey(epoch, key)))
      } catch {
        shared = null
      }
      if (shared) {
        const age = now - shared.asOf
        if (this.gen(key) === gen) this.remember(key, { ...shared, epoch, gen })
        if (age < Math.min(this.spec.freshMs, maxAge)) {
          cacheRequests.inc({ namespace: ns, result: 'hit' })
          return shared.value
        }
        if (age < maxAge) {
          cacheRequests.inc({ namespace: ns, result: 'stale' })
          void this.refresh(key, epoch, load, true).catch(() => {})
          return shared.value
        }
      }
    }

    cacheRequests.inc({ namespace: ns, result: 'miss' })
    return this.refresh(key, degraded ? null : epoch!, load, false, maxAge)
  }

  /**
   * Many keys at once, loading every missing one in ONE upstream call (`loadMany` answers the keys it
   * found; a key it leaves out is simply absent from the result and not cached).
   */
  async getMany(keys: readonly string[], loadMany: (keys: string[]) => Promise<Map<string, T>>, opts: ReadOptions = {}): Promise<Map<string, T>> {
    const ns = this.namespace
    const unique = [...new Set(keys)]
    if (!cacheEnabled(ns)) {
      cacheRequests.inc({ namespace: ns, result: 'bypass' }, unique.length)
      return unique.length ? loadMany(unique) : new Map()
    }
    ensureBus()
    if (this.pending.size) await Promise.all(this.pending)
    const maxAge = Math.min(opts.maxAgeMs ?? this.spec.staleMs, this.spec.staleMs)
    const now = Date.now()
    const epoch = await this.readEpoch()
    const degraded = epoch === null
    const out = new Map<string, T>()
    const need: string[] = []
    const stale: string[] = []

    const pending: string[] = []
    for (const key of unique) {
      const local = this.l1.get(key)
      if (local && local.gen === this.gen(key) && (degraded || local.epoch === epoch) && now - local.asOf < Math.min(this.spec.freshMs, maxAge)) {
        out.set(key, local.value)
      } else pending.push(key)
    }
    if (pending.length && !degraded && !this.spec.local) {
      let raws: Array<string | null> = []
      try {
        raws = await getStore().mget(pending.map((k) => this.valueKey(epoch, k)))
      } catch {
        raws = []
      }
      pending.forEach((key, i) => {
        const shared = this.parse(raws[i] ?? null)
        if (!shared || now - shared.asOf >= maxAge) {
          need.push(key)
          return
        }
        this.remember(key, { ...shared, epoch, gen: this.gen(key) })
        out.set(key, shared.value)
        if (now - shared.asOf >= this.spec.freshMs) stale.push(key)
      })
    } else need.push(...pending)

    cacheRequests.inc({ namespace: ns, result: 'hit' }, unique.length - need.length - stale.length)
    if (stale.length) {
      cacheRequests.inc({ namespace: ns, result: 'stale' }, stale.length)
      const idle = stale.filter((k) => !this.batchInflight.has(k))
      if (idle.length) void this.loadBatch(idle, epoch, loadMany).catch(() => {})
    }
    if (need.length) {
      cacheRequests.inc({ namespace: ns, result: 'miss' }, need.length)
      const joined = need.filter((k) => this.batchInflight.has(k))
      const own = need.filter((k) => !this.batchInflight.has(k))
      const [mine, theirs] = await Promise.all([
        own.length ? this.loadBatch(own, epoch, loadMany) : Promise.resolve(new Map<string, T>()),
        Promise.all(joined.map(async (k) => [k, await this.batchInflight.get(k)] as const)),
      ])
      for (const [k, v] of mine) out.set(k, v)
      for (const [k, v] of theirs) if (v !== undefined) out.set(k, v)
    }
    return out
  }

  private loadBatch(keys: string[], epoch: string | null, loadMany: (keys: string[]) => Promise<Map<string, T>>): Promise<Map<string, T>> {
    const p = this.runBatch(keys, epoch, loadMany)
    for (const key of keys) {
      const one = p.then((found) => found.get(key), () => undefined)
      this.batchInflight.set(key, one)
      void one.finally(() => { if (this.batchInflight.get(key) === one) this.batchInflight.delete(key) })
    }
    return p
  }

  private async runBatch(keys: string[], epoch: string | null, loadMany: (keys: string[]) => Promise<Map<string, T>>): Promise<Map<string, T>> {
    const shared = epoch !== null && !this.spec.local
    const gens = keys.map((k) => this.gen(k))
    let tombs: Array<string | null> = []
    if (shared) tombs = await getStore().mget(keys.map((k) => this.tombKey(epoch, k))).catch(() => [])
    const startedAt = Date.now()
    const stop = cacheRefreshDuration.startTimer({ namespace: this.namespace })
    let found: Map<string, T>
    try {
      found = await loadMany(keys)
      cacheRefreshes.inc({ namespace: this.namespace, outcome: 'ok' })
    } catch (err) {
      cacheRefreshes.inc({ namespace: this.namespace, outcome: 'error' })
      throw err
    } finally {
      stop()
    }
    await Promise.all(keys.map(async (key, i) => {
      if (!found.has(key)) return
      const value = found.get(key) as T
      if (this.gen(key) === gens[i]) this.remember(key, { asOf: startedAt, value, epoch: epoch ?? '?', gen: gens[i] })
      if (!shared) return
      await getStore()
        .writeUnlessInvalidated(this.valueKey(epoch, key), this.serialise(startedAt, value), this.spec.staleMs, this.tombKey(epoch, key), tombs[i] ?? '0')
        .catch(() => false)
    }))
    return found
  }

  /**
   * Computes one key once. `epoch === null` means Redis is unreachable: compute, keep it in process,
   * store nothing. A background refresh that finds another replica refreshing simply leaves it to it.
   */
  private refresh(key: string, epoch: string | null, load: () => Promise<T>, background: boolean, maxAge = this.spec.staleMs): Promise<T> {
    const gen = this.gen(key)
    const flightKey = `${epoch ?? '?'}|${gen}|${key}`
    const running = this.inflight.get(flightKey)
    if (running) return running

    const shared = epoch !== null && !this.spec.local
    const p = (async (): Promise<T> => {
      const s = getStore()
      const token = randomUUID()
      let locked = true
      let tomb = '0'
      if (shared) {
        try {
          locked = await s.setNx(this.lockKey(epoch, key), token, this.spec.lockMs)
        } catch {
          locked = true
        }
        if (!locked) {
          if (background) {
            cacheRefreshes.inc({ namespace: this.namespace, outcome: 'skipped' })
            throw new Error('refresh held by another replica')
          }
          // Another replica is computing this key: wait for its value rather than asking again.
          const deadline = Date.now() + Math.min(this.spec.lockMs, WAIT_MAX_MS)
          while (Date.now() < deadline) {
            await sleep(WAIT_STEP_MS)
            const [raw, lock] = await s.mget([this.valueKey(epoch, key), this.lockKey(epoch, key)]).catch(() => [null, null])
            const got = this.parse(raw)
            if (got && Date.now() - got.asOf < maxAge) {
              if (this.gen(key) === gen) this.remember(key, { ...got, epoch, gen })
              return got.value
            }
            if (!lock) break
          }
        }
        tomb = (await s.get(this.tombKey(epoch, key)).catch(() => null)) ?? '0'
      }

      const startedAt = Date.now()
      const stop = cacheRefreshDuration.startTimer({ namespace: this.namespace })
      let value: T
      try {
        value = await load()
        cacheRefreshes.inc({ namespace: this.namespace, outcome: 'ok' })
      } catch (err) {
        cacheRefreshes.inc({ namespace: this.namespace, outcome: 'error' })
        throw err
      } finally {
        stop()
        if (shared && locked) void s.delIfEquals(this.lockKey(epoch, key), token).catch(() => {})
      }

      // Only a refresh nobody invalidated in the meantime may be remembered.
      if (this.gen(key) === gen) this.remember(key, { asOf: startedAt, value, epoch: epoch ?? '?', gen })
      if (shared) {
        await s
          .writeUnlessInvalidated(this.valueKey(epoch, key), this.serialise(startedAt, value), this.spec.staleMs, this.tombKey(epoch, key), tomb)
          .catch(() => false)
      }
      return value
    })()
    this.inflight.set(flightKey, p)
    void p.finally(() => { if (this.inflight.get(flightKey) === p) this.inflight.delete(flightKey) }).catch(() => {})
    return p
  }

  // ── invalidation ──

  /**
   * Drops one key, or the whole namespace, on every replica. Resolves once the shared store records
   * it, so a read made after `await invalidate()` never sees what was dropped. Best-effort: a Redis
   * failure leaves the TTLs to bound the staleness, and is never thrown at the mutation that asked.
   */
  invalidate(key?: string): Promise<void> {
    const ns = this.namespace
    cacheInvalidations.inc({ namespace: ns, scope: key === undefined ? 'all' : 'key' })
    applyLocally(ns, key)
    if (!cacheEnabled(ns)) return Promise.resolve()
    ensureBus()
    const p = this.record(key)
    this.pending.add(p)
    void p.finally(() => this.pending.delete(p))
    return p
  }

  private async record(key?: string): Promise<void> {
    const ns = this.namespace
    const s = getStore()
    try {
      if (!this.spec.local) {
        if (key === undefined) {
          await s.incr(this.epochKey())
        } else {
          const epoch = (await s.get(this.epochKey())) ?? '0'
          await s.bump(this.tombKey(epoch, key), Math.max(this.spec.staleMs, this.spec.lockMs))
          await s.del(this.valueKey(epoch, key))
        }
      }
      await s.publish(CHANNEL, JSON.stringify({ ns, key, origin: ORIGIN }))
    } catch {
      // bounded by the TTLs
    }
  }

  /** Test seam. */
  resetLocal(): void {
    this.l1.clear()
    this.inflight.clear()
    this.batchInflight.clear()
    this.keyGen.clear()
    this.pending.clear()
    this.nsGen = 0
  }
}
