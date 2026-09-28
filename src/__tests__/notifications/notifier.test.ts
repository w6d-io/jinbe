import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import type Redis from 'ioredis'
import { NotificationService, DEAD_LETTER_KEY, retryDelayMs, HttpNotifier, NotifyError } from '../../services/notifications/index.js'
import type { EntityEvent, Notifier } from '../../services/notifications/index.js'
import { componentLogger } from '../../telemetry/logger.js'
import { notificationsDeadLettered } from '../../telemetry/metrics.js'

const OUTBOX = 'notifications:outbox'

/** Just enough of a Redis for the outbox: one stream + group, its pending list, a lock, a hash. */
function fakeRedis() {
  let seq = 0
  const streams = new Map<string, [string, string[]][]>()
  const pel = new Map<string, { deliveredAt: number; deliveries: number }>()
  const kv = new Map<string, { value: string; until: number }>()
  const hash = new Map<string, string>()
  const stream = (k: string) => streams.get(k) ?? streams.set(k, []).get(k)!
  const alive = (k: string) => { const e = kv.get(k); return e && e.until > Date.now() ? e : undefined }
  const api = {
    streams, pel, hash,
    async xadd(key: string, ...args: string[]) {
      const at = args.indexOf('*')
      const id = `${Date.now()}-${seq++}`
      stream(key).push([id, args.slice(at + 1)])
      return id
    },
    async xgroup() { return 'OK' },
    async xreadgroup(...args: string[]) {
      const count = Number(args[args.indexOf('COUNT') + 1])
      const fresh = stream(OUTBOX).filter(([id]) => !pel.has(id) && !acked.has(id)).slice(0, count)
      for (const [id] of fresh) pel.set(id, { deliveredAt: Date.now(), deliveries: 1 })
      return fresh.length ? [[OUTBOX, fresh]] : null
    },
    async xpending(_key: string, _group: string, ...range: string[]) {
      if (range.length === 0) return [pel.size]
      return [...pel.entries()].map(([id, p]) => [id, 'jinbe', Date.now() - p.deliveredAt, p.deliveries])
    },
    async xclaim(_key: string, _group: string, _consumer: string, minIdle: string, id: string) {
      const p = pel.get(id)
      if (!p || Date.now() - p.deliveredAt < Number(minIdle)) return []
      p.deliveredAt = Date.now()
      p.deliveries++
      return [[id, stream(OUTBOX).find(([sid]) => sid === id)?.[1] ?? null]]
    },
    async xack(_key: string, _group: string, id: string) { acked.add(id); return pel.delete(id) ? 1 : 0 },
    async xlen(key: string) { return stream(key).length },
    async set(key: string, value: string, _px: string, ttl: number, _nx: string) {
      if (alive(key)) return null
      kv.set(key, { value, until: Date.now() + ttl })
      return 'OK'
    },
    async eval(script: string, _n: number, key: string, holder: string, ttl?: string) {
      const e = alive(key)
      if (!e || e.value !== holder) return 0
      if (script.includes('pexpire')) e.until = Date.now() + Number(ttl)
      else kv.delete(key)
      return 1
    },
    async hget(_k: string, f: string) { return hash.get(f) ?? null },
    async hset(_k: string, f: string, v: string) { hash.set(f, v); return 1 },
    async hdel(_k: string, f: string) { return hash.delete(f) ? 1 : 0 },
    multi() {
      const ops: (() => Promise<unknown>)[] = []
      const chain = {
        xadd: (...a: string[]) => { ops.push(() => api.xadd(...(a as [string, ...string[]]))); return chain },
        xack: (k: string, g: string, id: string) => { ops.push(() => api.xack(k, g, id)); return chain },
        hdel: (k: string, f: string) => { ops.push(() => api.hdel(k, f)); return chain },
        exec: async () => { for (const op of ops) await op() },
      }
      return chain
    },
  }
  const acked = new Set<string>()
  return api
}

const event = (): Omit<EntityEvent, 'timestamp'> => ({ action: 'created', entity_type: 'user', payload: { id: 'u1' } })

function failing(reason = 'POST http://jinbe-service:8080/ingest: getaddrinfo ENOTFOUND jinbe-service', permanent = false): Notifier {
  return { name: 'http', notify: vi.fn().mockRejectedValue(new NotifyError(reason, { permanent })) }
}

async function deadCount(reason: string): Promise<number> {
  return (await notificationsDeadLettered.get()).values.find((v) => v.labels.reason === reason)?.value ?? 0
}

describe('NotificationService — bounded retries and dead letter', () => {
  const log = componentLogger('notifications')
  let redis: ReturnType<typeof fakeRedis>

  beforeEach(() => {
    vi.useFakeTimers({ now: new Date('2026-09-28T12:00:00Z') })
    redis = fakeRedis()
    vi.spyOn(log, 'warn').mockImplementation(() => {})
    vi.spyOn(log, 'debug').mockImplementation(() => {})
    vi.spyOn(log, 'info').mockImplementation(() => {})
  })
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  function service(notifier: Notifier, opts: ConstructorParameters<typeof NotificationService>[0] = {}) {
    const svc = new NotificationService({ maxAttempts: 4, retryBaseMs: 1_000, retryMaxMs: 60_000, holder: 'pod-a', ...opts })
    svc.setRedis(redis as unknown as Redis)
    svc.register(notifier)
    // Driven step by step rather than through the timed loop.
    ;(svc as unknown as { running: boolean }).running = true
    return svc as unknown as NotificationService & {
      holdLock(): Promise<boolean>
      retryDue(): Promise<void>
    }
  }

  async function firstDelivery(svc: ReturnType<typeof service>) {
    const results = await redis.xreadgroup('GROUP', 'g', 'jinbe', 'COUNT', '10')
    for (const [id, fields] of results![0][1]) {
      await (svc as unknown as { processMessage(id: string, f: string[], a: number): Promise<void> }).processMessage(id, fields, 1)
    }
  }

  it('retries with growing delays, then dead-letters with the reason after maxAttempts', async () => {
    const notifier = failing()
    const svc = service(notifier)
    const before = await deadCount('attempts_exhausted')
    await svc.emit(event())
    await firstDelivery(svc)
    const [id] = [...redis.pel.keys()]

    // Not due yet: nothing is retried before its delay, however often the loop passes.
    await svc.retryDue()
    await svc.retryDue()
    expect(notifier.notify).toHaveBeenCalledTimes(1)

    for (let attempt = 1; attempt < 4; attempt++) {
      vi.advanceTimersByTime(retryDelayMs(id, attempt, 1_000, 60_000))
      await svc.retryDue()
      expect(notifier.notify).toHaveBeenCalledTimes(attempt + 1)
    }

    expect(redis.pel.size).toBe(0)
    const [[, fields]] = redis.streams.get(DEAD_LETTER_KEY)!
    const dead = Object.fromEntries(fields.reduce<string[][]>((a, v, i) => (i % 2 ? a[a.length - 1].push(v) : a.push([v]), a), []))
    expect(dead).toMatchObject({ why: 'attempts_exhausted', attempts: '4', outbox_id: id, reason: expect.stringContaining('ENOTFOUND jinbe-service') })
    expect(JSON.parse(dead.data).payload).toEqual({ id: 'u1' })
    expect(await deadCount('attempts_exhausted')).toBe(before + 1)

    // One warn for the first failure, one for the dead letter; the retries in between are debug.
    const warns = vi.mocked(log.warn).mock.calls.map((c) => c[1])
    expect(warns).toEqual(['notification delivery failed, will retry', 'notification dead-lettered'])
    expect(log.debug).toHaveBeenCalledTimes(2)
    expect(redis.hash.size).toBe(0)
  })

  it('dead-letters at once when the receiver refuses the event', async () => {
    const notifier = failing('POST http://x/ingest: HTTP 400 bad payload', true)
    const svc = service(notifier)
    await svc.emit(event())
    await firstDelivery(svc)
    expect(redis.pel.size).toBe(0)
    expect(redis.streams.get(DEAD_LETTER_KEY)).toHaveLength(1)
    expect(notifier.notify).toHaveBeenCalledTimes(1)
  })

  it('dead-letters an event older than maxAgeMs instead of dropping it, with the last failure', async () => {
    const notifier = failing()
    const svc = service(notifier, { maxAgeMs: 10_000, maxAttempts: 50 })
    await svc.emit(event())
    await firstDelivery(svc)
    vi.advanceTimersByTime(60_000)
    await svc.retryDue()
    const [[, fields]] = redis.streams.get(DEAD_LETTER_KEY)!
    expect(fields).toContain('expired')
    expect(fields.find((f) => f.startsWith('undelivered after'))).toContain('last failure: http: POST http://jinbe-service')
  })

  it('acks on success and forgets the failure reason', async () => {
    const notifier: Notifier = { name: 'http', notify: vi.fn().mockRejectedValueOnce(new NotifyError('down')).mockResolvedValue({ acknowledged: true }) }
    const svc = service(notifier)
    await svc.emit(event())
    await firstDelivery(svc)
    expect(redis.hash.size).toBe(1)
    const [id] = [...redis.pel.keys()]
    vi.advanceTimersByTime(retryDelayMs(id, 1, 1_000, 60_000))
    await svc.retryDue()
    expect(redis.pel.size).toBe(0)
    expect(redis.hash.size).toBe(0)
    expect(redis.streams.get(DEAD_LETTER_KEY)).toBeUndefined()
  })

  it('one replica consumes: the second cannot take the lock until the first stops renewing it', async () => {
    const a = service(failing(), { holder: 'pod-a', lockTtlMs: 30_000 })
    const b = service(failing(), { holder: 'pod-b', lockTtlMs: 30_000 })
    expect(await a.holdLock()).toBe(true)
    expect(await b.holdLock()).toBe(false)
    vi.advanceTimersByTime(20_000)
    expect(await a.holdLock()).toBe(true) // renewed
    vi.advanceTimersByTime(20_000)
    expect(await b.holdLock()).toBe(false)
    vi.advanceTimersByTime(31_000)
    expect(await b.holdLock()).toBe(true)
    expect(await a.holdLock()).toBe(false)
  })
})

describe('retryDelayMs', () => {
  it('grows exponentially with jitter between half and all of the ceiling, capped', () => {
    for (let attempt = 1; attempt <= 12; attempt++) {
      const ceiling = Math.min(60_000, 1_000 * 2 ** (attempt - 1))
      const d = retryDelayMs('1-0', attempt, 1_000, 60_000)
      expect(d).toBeGreaterThanOrEqual(ceiling / 2)
      expect(d).toBeLessThanOrEqual(ceiling)
    }
    // Stable per event and attempt, different across events: replicas and passes agree, events spread.
    expect(retryDelayMs('1-0', 3, 1_000, 60_000)).toBe(retryDelayMs('1-0', 3, 1_000, 60_000))
    const spread = new Set(Array.from({ length: 20 }, (_, i) => retryDelayMs(`${i}-0`, 5, 1_000, 60_000)))
    expect(spread.size).toBeGreaterThan(10)
  })
})

describe('HttpNotifier — failure reasons', () => {
  afterEach(() => vi.unstubAllGlobals())
  const ev = { ...event(), timestamp: new Date().toISOString() }

  it('names the target and the network cause instead of "fetch failed", without credentials', async () => {
    const cause = Object.assign(new Error('getaddrinfo ENOTFOUND jinbe-service'), { code: 'ENOTFOUND' })
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(Object.assign(new TypeError('fetch failed'), { cause })))
    const err = await new HttpNotifier({ url: 'http://user:pw@jinbe-service:8080/' }).notify(ev).catch((e) => e)
    expect(err).toBeInstanceOf(NotifyError)
    expect(err.message).toBe('POST http://jinbe-service:8080/ingest: getaddrinfo ENOTFOUND jinbe-service')
    expect(err.permanent).toBe(false)
  })

  it('treats a 4xx refusal as permanent and a 5xx / 429 as retryable', async () => {
    const answer = (status: number) => vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('nope', { status })))
    answer(422)
    expect(await new HttpNotifier({ url: 'http://r' }).notify(ev).catch((e) => e.permanent)).toBe(true)
    answer(503)
    expect(await new HttpNotifier({ url: 'http://r' }).notify(ev).catch((e) => e.permanent)).toBe(false)
    answer(429)
    expect(await new HttpNotifier({ url: 'http://r' }).notify(ev).catch((e) => e.message)).toBe('POST http://r/ingest: HTTP 429 nope')
  })
})
