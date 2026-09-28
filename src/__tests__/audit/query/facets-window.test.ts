import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { LokiUnavailableError, setLokiClient, type LokiClient, type LokiSample, type LokiSeries } from '../../../audit/query/loki.js'
import { countsOver, facets, histogramStep, summary, toBuckets } from '../../../audit/query/reader.js'

// The audit page's counts are asked the way Loki's results cache keeps them (range queries at a
// fixed step for the whole steps, instant queries for the two partial edges), and they must add up
// to exactly what one instant query over the window would say.

type Call = { kind: 'instant'; query: string; at: number } | { kind: 'range'; query: string; start: number; end: number; step: number }

/** A Loki over a fixed list of events (seconds), answering count queries by `result`/`event`. */
class CountingLoki implements LokiClient {
  calls: Call[] = []
  events: Array<{ t: number; metric: Record<string, string> }> = []
  refuseGrouped = false
  private count(fromExcl: number, toIncl: number): LokiSample[] {
    const by = new Map<string, LokiSample>()
    for (const e of this.events) {
      if (e.t <= fromExcl || e.t > toIncl) continue
      const k = JSON.stringify(e.metric)
      const cur = by.get(k)
      if (cur) cur.value++
      else by.set(k, { metric: e.metric, value: 1 })
    }
    return [...by.values()]
  }
  private refuse(query: string) {
    if (this.refuseGrouped && query.includes('sum by (event, category')) throw new LokiUnavailableError('loki answered 400', 400)
  }
  async queryRange() { return [] }
  async instant(query: string, at: number): Promise<LokiSample[]> {
    this.calls.push({ kind: 'instant', query, at })
    this.refuse(query)
    const range = Number(/\[(\d+)s\]\)\)*$/.exec(query)?.[1] ?? /\[(\d+)s\]/.exec(query)![1])
    return this.count(at - range, at)
  }
  async range(query: string, start: number, end: number, step: number): Promise<LokiSeries[]> {
    this.calls.push({ kind: 'range', query, start, end, step })
    this.refuse(query)
    const out = new Map<string, LokiSeries>()
    for (let t = start; t <= end; t += step) {
      for (const s of this.count(t - step, t)) {
        const k = JSON.stringify(s.metric)
        const series = out.get(k) ?? { metric: s.metric, values: [] }
        series.values.push([t, s.value])
        out.set(k, series)
      }
    }
    return [...out.values()]
  }
}

const loki = new CountingLoki()
beforeEach(() => { loki.calls = []; loki.events = []; loki.refuseGrouped = false; setLokiClient(loki) })
afterAll(() => setLokiClient(null))

const H = 3600
const T0 = 1_790_000_000 - (1_790_000_000 % H) // on the hour

describe('histogramStep', () => {
  it('draws a range in at most 60 bars, from a closed list of widths', () => {
    expect(histogramStep(H)).toBe(60)
    expect(histogramStep(24 * H)).toBe(H)
    expect(histogramStep(7 * 24 * H)).toBe(3 * H)
    expect(histogramStep(30 * 24 * H)).toBe(12 * H)
    expect(histogramStep(90 * 24 * H)).toBe(86_400)
  })
})

describe('countsOver', () => {
  it('whole steps as one step-aligned range query, the partial edges as instant queries — and the totals are exact', async () => {
    const from = (T0 - 5 * H + 600) * 1000 // 10 min past an hour
    const to = (T0 + 1200) * 1000 // 20 min past the hour
    loki.events = [
      { t: T0 - 5 * H + 300, metric: { result: 'success' } }, // before the window
      { t: T0 - 5 * H + 900, metric: { result: 'success' } }, // head edge
      { t: T0 - 2 * H, metric: { result: 'denied' } }, // exactly on a boundary: counted once
      { t: T0 - H + 1, metric: { result: 'success' } },
      { t: T0 + 600, metric: { result: 'denied' } }, // tail edge
      { t: T0 + 1800, metric: { result: 'success' } }, // after the window
    ]
    const w = await countsOver('{x}', 'result', from, to, H)
    const range = loki.calls.find((c) => c.kind === 'range') as Extract<Call, { kind: 'range' }>
    expect(range.step).toBe(H)
    expect(range.start % H).toBe(0)
    expect(range.end % H).toBe(0)
    const instants = loki.calls.filter((c) => c.kind === 'instant').map((c) => /\[(\d+)s\]/.exec(c.query)![1])
    expect(instants.sort()).toEqual(['1200', '3000'])
    const total = Object.fromEntries(w.total.map((s) => [s.metric.result, s.value]))
    expect(total).toEqual({ success: 2, denied: 2 })
  })

  it('a window inside one step is one instant query', async () => {
    loki.events = [{ t: T0 + 100, metric: { result: 'success' } }]
    const w = await countsOver('{x}', 'result', (T0 + 60) * 1000, (T0 + 600) * 1000, H)
    expect(loki.calls.map((c) => c.kind)).toEqual(['instant'])
    expect(w.total[0].value).toBe(1)
  })

  it('never asks a step wider than an hour: wider bars are sums of hourly points', async () => {
    await countsOver('{x}', 'result', (T0 - 7 * 24 * H) * 1000, T0 * 1000, 6 * H)
    expect((loki.calls.find((c) => c.kind === 'range') as Extract<Call, { kind: 'range' }>).step).toBe(H)
  })
})

describe('toBuckets', () => {
  it('files each point under the bucket its last second falls in; t is the bucket START', async () => {
    loki.events = [
      { t: T0 - 3 * H + 10, metric: { result: 'success' } },
      { t: T0 - 1, metric: { result: 'denied' } },
      { t: T0 - 2, metric: { result: 'failure' } },
    ]
    const from = (T0 - 3 * H) * 1000
    const to = T0 * 1000
    const buckets = toBuckets(await countsOver('{x}', 'result', from, to, H), from, to, H)
    expect(buckets.map((b) => b.t)).toEqual([T0 - 3 * H, T0 - 2 * H, T0 - H].map((t) => new Date(t * 1000).toISOString()))
    expect(buckets[0]).toMatchObject({ total: 1, failed: 0, denied: 0 })
    expect(buckets[2]).toMatchObject({ total: 2, failed: 2, denied: 1 })
  })
})

describe('facets', () => {
  const week = [(T0 - 7 * 24 * H) * 1000, (T0 + 900) * 1000] as const

  it('one grouped count for the five small facets, one for actor ids; counts, total and histogram agree', async () => {
    loki.events = [
      { t: T0 - 24 * H, metric: { event: 'access.denied', category: 'access', result: 'denied', site: '', actor_type: 'anonymous', actor_id: '' } },
      { t: T0 - 2 * H, metric: { event: 'site.applied', category: 'authz', result: 'success', site: 'echo', actor_type: 'user', actor_id: 'u1' } },
      { t: T0 + 60, metric: { event: 'site.synced', category: 'authz', result: 'success', site: 'echo', actor_type: 'system', actor_id: '' } },
    ]
    const r = await facets({}, ...week)
    expect(r.total).toBe(3)
    expect(r.facets.actor_type.map((c) => c.key).sort()).toEqual(['anonymous', 'system', 'user'])
    expect(r.facets.site).toEqual([{ key: 'echo', count: 2 }])
    expect(r.series.reduce((a, b) => a + b.total, 0)).toBe(3)
    expect(r.series.reduce((a, b) => a + b.denied, 0)).toBe(1)
    const shapes = new Set(loki.calls.map((c) => /sum by \(([^)]+)\)/.exec(c.query)![1]))
    expect([...shapes].sort()).toEqual(['actor_id', 'event, category, result, site, actor_type'])
  })

  it('too many combinations for Loki (400): falls back to one top-k per facet, still with a histogram', async () => {
    loki.refuseGrouped = true
    loki.events = [{ t: T0 - H, metric: { event: 'site.applied', category: 'authz', result: 'success', site: 'echo', actor_type: 'user', actor_id: 'u1' } }]
    const r = await facets({}, ...week)
    expect(r.facets.event).toEqual([{ key: 'site.applied', count: 1 }])
    expect(loki.calls.some((c) => c.query.startsWith('topk(21, sum by (event)'))).toBe(true)
    expect(r.series.length).toBeGreaterThan(0)
  })

  it('a Loki outage is not a fallback: it surfaces', async () => {
    const down: LokiClient = {
      queryRange: async () => [],
      instant: async () => { throw new LokiUnavailableError('connect ECONNREFUSED') },
      range: async () => { throw new LokiUnavailableError('connect ECONNREFUSED') },
    }
    setLokiClient(down)
    await expect(facets({}, ...week)).rejects.toBeInstanceOf(LokiUnavailableError)
  })
})

describe('summary', () => {
  it('byCategory and byResult from one count; prev over the window before; series of buckets', async () => {
    const now = (T0 + 900) * 1000
    loki.events = [
      { t: T0 - 2 * H, metric: { category: 'authz', result: 'success', target_id: 'x', actor_id: 'u1' } },
      { t: T0 - 30 * H, metric: { category: 'access', result: 'denied', target_id: 'x', actor_id: '' } },
    ]
    const s = await summary({}, '24h', 24 * H * 1000, now)
    expect(s.total).toBe(1)
    expect(s.byCategory).toEqual({ authz: 1 })
    expect(s.prev).toMatchObject({ total: 1, denied: 1 })
    expect(s.series.length).toBe(25)
  })
})
