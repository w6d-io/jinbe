import { env } from '../../config/env.js'
import { auditEventV1Schema, type AuditEventV1 } from '../v1/schema.js'
import { GENESIS, verifyChain } from '../v1/chain.js'
import { auditQuery, countBy, type AuditFilter } from './logql.js'
import { lokiClient, msToNs, MAX_ENTRIES, LokiUnavailableError } from './loki.js'
import { DAY_MS, encodeCursor, type Cursor } from './params.js'

/**
 * The read side of the audit trail over Loki (AUD-9). Every query comes from logql.ts; every entry
 * Loki returns is parsed back into an audit/v1 event and checked again against the same filter in
 * JS — the scope is enforced by the query AND by what is let through, so a query that matched too
 * much (or a store that ignored a filter) still cannot hand a caller a foreign event.
 */

const BODY_KEYS = Object.keys(auditEventV1Schema.innerType().shape)
const EVENT_KEYS = new Set([...BODY_KEYS, 'chain_id', 'seq', 'prev_hash', 'hash'])

/** The audit/v1 event inside a pino line — the logger's own fields (level, pid, hostname…) dropped. */
export function parseLine(line: string): AuditEventV1 | null {
  let raw: Record<string, unknown>
  try {
    raw = JSON.parse(line) as Record<string, unknown>
  } catch {
    return null
  }
  if (raw.log_type !== 'audit' || raw.schema !== 'audit/v1' || typeof raw.event_id !== 'string') return null
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(raw)) if (EVENT_KEYS.has(k)) out[k] = v
  return out as unknown as AuditEventV1
}

/** The filter, again, in JS: the second of the two locks on scope. */
export function matches(e: AuditEventV1, f: AuditFilter, line: string): boolean {
  if (f.orgs && !f.orgs.includes(e.org_id ?? '')) return false
  if (f.subject && e.actor?.id !== f.subject && e.target?.id !== f.subject) return false
  if (f.actor && e.actor?.id !== f.actor) return false
  if (f.actorTypes?.length && !f.actorTypes.includes(e.actor?.type)) return false
  if (f.target && e.target?.id !== f.target) return false
  if (f.site && e.site !== f.site) return false
  if (f.events?.length && !f.events.some((k) => (k.endsWith('.*') ? e.event.startsWith(k.slice(0, -1)) : e.event === k))) return false
  if (f.category && e.category !== f.category) return false
  if (f.result && e.result !== f.result) return false
  if (f.severity && e.severity !== f.severity) return false
  if (f.traceId && e.trace_id !== f.traceId) return false
  if (f.eventId && e.event_id !== f.eventId) return false
  if (f.q && !line.includes(f.q)) return false
  return true
}

export interface Page {
  events: AuditEventV1[]
  nextCursor: string | null
  truncated: boolean
}

/**
 * One page, newest first. The cursor is the Loki timestamp of the last entry handed out plus the
 * ids already handed out AT that timestamp — two events may share a nanosecond, and neither may be
 * repeated or skipped.
 */
export async function readPage(f: AuditFilter, fromMs: number, toMs: number, limit: number, cursor: Cursor | null): Promise<Page> {
  const skip = new Set(cursor?.ids ?? [])
  const want = Math.min(limit + 1 + skip.size, MAX_ENTRIES)
  const endNs = cursor ? (BigInt(cursor.t) + 1n).toString() : msToNs(toMs + 1)
  const entries = await lokiClient().queryRange({ query: auditQuery(f, env.LOKI_NAMESPACE), startNs: msToNs(fromMs), endNs, limit: want, direction: 'backward' })

  const events: AuditEventV1[] = []
  let lastTs: string | null = null
  let idsAtLast: string[] = []
  let more = false
  for (const entry of entries) {
    if (cursor && BigInt(entry.ts) > BigInt(cursor.t)) continue
    const e = parseLine(entry.line)
    if (!e) continue
    if (cursor && entry.ts === cursor.t && skip.has(e.event_id)) continue
    if (!matches(e, f, entry.line)) continue
    if (events.length === limit) { more = true; break }
    events.push(e)
    if (entry.ts !== lastTs) { lastTs = entry.ts; idsAtLast = [] }
    idsAtLast.push(e.event_id)
  }

  // Loki gave everything it was asked for: there may be more behind what was filtered out.
  if (!more && entries.length >= want && entries.length > 0) {
    const last = entries[entries.length - 1]
    const ids = entries.filter((x) => x.ts === last.ts).map((x) => parseLine(x.line)?.event_id).filter((x): x is string => !!x)
    return { events, nextCursor: encodeCursor({ t: last.ts, ids }), truncated: false }
  }
  if (!more || !lastTs) return { events, nextCursor: null, truncated: false }
  const carried = cursor && cursor.t === lastTs ? cursor.ids : []
  return { events, nextCursor: encodeCursor({ t: lastTs, ids: [...carried, ...idsAtLast] }), truncated: false }
}

// ─── Facets and summary ─────────────────────────────────────────────────────

export type Count = { key: string; count: number }
export type Bucket = { t: string; total: number; failed: number; denied: number }

const FACETS = { event: 'event', category: 'category', result: 'result', site: 'site', actor_type: 'actor_type', actor: 'actor_id' } as const
type FacetName = keyof typeof FACETS
// Every facet but the actor id comes out of ONE grouped query: each is a function of few values, so
// the combinations stay far under Loki's series limit. The actor id is the one open-ended field.
const GROUPED = ['event', 'category', 'result', 'site', 'actor_type'] as const
const TOP = 20

function label(metric: Record<string, string>, field: string): string {
  return metric[field] ?? metric[`${field}_extracted`] ?? ''
}

function counts(samples: Array<{ metric: Record<string, string>; value: number }>, field: string): Count[] {
  const by = new Map<string, number>()
  for (const s of samples) {
    const key = label(s.metric, field)
    if (key !== '') by.set(key, (by.get(key) ?? 0) + s.value)
  }
  return [...by.entries()].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count)
}

/** Histogram widths, smallest first: the first that draws the range in at most 60 bars is used. */
const STEPS_S = [60, 300, 900, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86_400]
/** The widest step a count is ASKED at; wider bars are sums of hourly points (see countsOver). */
const QUERY_STEP_MAX_S = 3600

export function histogramStep(rangeS: number): number {
  return STEPS_S.find((s) => rangeS / s <= 60) ?? STEPS_S[STEPS_S.length - 1]
}

type Sample = { metric: Record<string, string>; value: number }
/** Counts per group over the window, and the same counts per step (keyed by the step's END, in s). */
interface Windowed { total: Sample[]; points: Map<number, Sample[]>; stepS: number }

const metricKey = (m: Record<string, string>) => JSON.stringify(Object.entries(m).sort(([a], [b]) => a.localeCompare(b)))

function add(into: Map<string, Sample>, metric: Record<string, string>, value: number) {
  const k = metricKey(metric)
  const cur = into.get(k)
  if (cur) cur.value += value
  else into.set(k, { metric, value })
}

/**
 * `sum by (<by>) (count_over_time(<query>))` over (from, to], whole and per step, asked the way
 * Loki's results cache can keep it.
 *
 * An instant query over seven days re-reads seven days of lines every time (the cache does not keep
 * those), and the audit selector has to read every jinbe line to find the few audit ones. A RANGE
 * query at a fixed step is cached per interval: a reload re-reads only the newest step. So the window
 * is cut in three: the whole steps in the middle as one range query (start and end on step boundaries,
 * which is also what Loki aligns to), and the two partial steps at the edges as instant queries over
 * less than a step each — cheap, and exact, so the totals match an instant query over the window.
 */
export async function countsOver(query: string, by: string, fromMs: number, toMs: number, displayStepS: number): Promise<Windowed> {
  const stepS = Math.min(displayStepS, QUERY_STEP_MAX_S)
  const fromS = Math.floor(fromMs / 1000)
  const toS = Math.ceil(toMs / 1000)
  const a = Math.ceil(fromS / stepS) * stepS
  const b = Math.floor(toS / stepS) * stepS
  const expr = (rangeS: number) => `sum by (${by}) (count_over_time(${query} [${Math.max(1, rangeS)}s]))`
  const client = lokiClient()
  const points = new Map<number, Sample[]>()
  const total = new Map<string, Sample>()
  const put = (t: number, samples: Sample[]) => {
    points.set(t, [...(points.get(t) ?? []), ...samples])
    for (const x of samples) add(total, x.metric, x.value)
  }
  if (b <= a) {
    // Inside one step: nothing whole to cache.
    put(Math.ceil(toS / stepS) * stepS, await client.instant(expr(toS - fromS), toS))
  } else {
    const [middle, head, tail] = await Promise.all([
      client.range(expr(stepS), a + stepS, b, stepS),
      a > fromS ? client.instant(expr(a - fromS), a) : Promise.resolve([]),
      toS > b ? client.instant(expr(toS - b), toS) : Promise.resolve([]),
    ])
    put(a, head)
    for (const series of middle) for (const [t, v] of series.values) put(t, [{ metric: series.metric, value: v }])
    put(b + stepS, tail)
  }
  return { total: [...total.values()], points, stepS }
}

/** Buckets of `displayStepS` over the window from per-step result counts; `t` is a bucket's START. */
export function toBuckets(w: Windowed, fromMs: number, toMs: number, displayStepS: number): Bucket[] {
  const first = Math.floor(fromMs / 1000 / displayStepS) * displayStepS
  const last = Math.ceil(toMs / 1000 / displayStepS) * displayStepS
  const buckets = new Map<number, Bucket>()
  for (let t = first; t < last; t += displayStepS) buckets.set(t, { t: new Date(t * 1000).toISOString(), total: 0, failed: 0, denied: 0 })
  for (const [end, samples] of w.points) {
    // A point counts (end - step, end]: it belongs to the bucket its last second falls in.
    const start = Math.floor((end - 1) / displayStepS) * displayStepS
    const bucket = buckets.get(start)
    if (!bucket) continue
    for (const x of samples) {
      const result = label(x.metric, 'result')
      bucket.total += x.value
      if (result !== 'success') bucket.failed += x.value
      if (result === 'denied') bucket.denied += x.value
    }
  }
  return [...buckets.values()]
}

/** Loki refused the grouped query (too many series): the facets are asked one by one instead. */
const tooWide = (err: unknown) => err instanceof LokiUnavailableError && err.status === 400

type GroupedName = (typeof GROUPED)[number]

async function perFacet(query: string, rangeS: number, atS: number): Promise<Record<GroupedName, Count[]>> {
  const client = lokiClient()
  const each = await Promise.all(GROUPED.map((g) => client.instant(countBy(query, g, rangeS, TOP + 1), atS)))
  return Object.fromEntries(GROUPED.map((g, i) => [g, counts(each[i], g)])) as Record<GroupedName, Count[]>
}

/**
 * Facet counts, the total and the histogram for the whole range. The page used to ask twelve
 * instant queries for this (six facets, six for the summary it drew the histogram from), each
 * re-reading the whole window; Loki's five-way querier ran them mostly one after the other.
 * Now: the five small facets and the histogram from ONE grouped count, the actor ids from another,
 * both cacheable (countsOver).
 */
export async function facets(f: AuditFilter, fromMs: number, toMs: number): Promise<{ facets: Record<FacetName, Count[]>; total: number; truncated: boolean; series: Bucket[] }> {
  const query = auditQuery(f, env.LOKI_NAMESPACE)
  const rangeS = (toMs - fromMs) / 1000
  const display = histogramStep(rangeS)
  const [grouped, actors] = await Promise.all([
    countsOver(query, GROUPED.join(', '), fromMs, toMs, display).catch((err) => (tooWide(err) ? null : Promise.reject(err))),
    countsOver(query, FACETS.actor, fromMs, toMs, display).catch((err) => (tooWide(err) ? null : Promise.reject(err))),
  ])
  const all = {} as Record<FacetName, Count[]>
  if (grouped) for (const g of GROUPED) all[g] = counts(grouped.total, g)
  else Object.assign(all, await perFacet(query, rangeS, toMs / 1000))
  all.actor = counts(actors ? actors.total : await lokiClient().instant(countBy(query, FACETS.actor, rangeS, TOP + 1), toMs / 1000), FACETS.actor)
  let truncated = false
  const out = {} as Record<FacetName, Count[]>
  for (const n of Object.keys(FACETS) as FacetName[]) {
    if (all[n].length > TOP) truncated = true
    out[n] = all[n].slice(0, TOP)
  }
  const series = grouped ? toBuckets(grouped, fromMs, toMs, display) : await histogram(query, fromMs, toMs)
  return { facets: out, total: all.result.reduce((a, c) => a + c.count, 0), truncated, series }
}

/** Events per bucket over [from, to], split by result. */
export async function histogram(query: string, fromMs: number, toMs: number): Promise<Bucket[]> {
  const display = histogramStep((toMs - fromMs) / 1000)
  return toBuckets(await countsOver(query, 'result', fromMs, toMs, display), fromMs, toMs, display)
}

const sumBy = (list: Count[]) => Object.fromEntries(list.map((c) => [c.key, c.count]))
const failedOf = (byResult: Record<string, number>) => Object.entries(byResult).filter(([k]) => k !== 'success').reduce((a, [, v]) => a + v, 0)

/** The top `n` of one field over the window: cached like the rest, an instant top-k if it has too many values. */
async function topOver(query: string, field: string, fromMs: number, toMs: number, display: number, n: number): Promise<Count[]> {
  try {
    return counts((await countsOver(query, field, fromMs, toMs, display)).total, field).slice(0, n)
  } catch (err) {
    if (!tooWide(err)) throw err
    return counts(await lokiClient().instant(countBy(query, field, (toMs - fromMs) / 1000, n), toMs / 1000), field).slice(0, n)
  }
}

export async function summary(f: AuditFilter, window: string, wMs: number, now = Date.now()) {
  const query = auditQuery(f, env.LOKI_NAMESPACE)
  const denied = auditQuery({ ...f, result: 'denied' }, env.LOKI_NAMESPACE)
  const display = histogramStep(wMs / 1000)
  const from = now - wMs
  const [both, prev, topDenied, topActors] = await Promise.all([
    countsOver(query, 'category, result', from, now, display),
    // The previous window is all past: once asked, Loki serves it from its cache.
    countsOver(query, 'result', from - wMs, from, display),
    topOver(denied, 'target_id', from, now, display, 10),
    topOver(query, 'actor_id', from, now, display, 10),
  ])
  const results = sumBy(counts(both.total, 'result'))
  const prevResults = sumBy(counts(prev.total, 'result'))
  const total = Object.values(results).reduce((a, v) => a + v, 0)
  return {
    window,
    total,
    prev: { total: Object.values(prevResults).reduce((a, v) => a + v, 0), failed: failedOf(prevResults), denied: prevResults.denied ?? 0 },
    byCategory: sumBy(counts(both.total, 'category')),
    byResult: results,
    series: toBuckets(both, from, now, display).map(({ t, total: n, failed }) => ({ t, total: n, failed })),
    topDenied,
    topActors: topActors.map((c) => ({ actorId: c.key, count: c.count })),
  }
}

// ─── One event, with its place in the chain ─────────────────────────────────

export type ChainStatus = 'verified' | 'unverified' | 'broken'

/** Recomputes the event's own hash, and the link to the event before it in the same chain. */
export function chainStatus(e: AuditEventV1, prev: AuditEventV1 | undefined): ChainStatus {
  if (typeof e.hash !== 'string' || typeof e.seq !== 'number') return 'unverified' // a legacy import
  if (!verifyChain([e]).ok) return 'broken'
  if (e.seq === 1) return e.prev_hash === GENESIS ? 'verified' : 'broken'
  if (!prev) return 'unverified'
  return verifyChain([prev, e]).ok ? 'verified' : 'broken'
}

export async function eventById(f: AuditFilter, eventId: string, atMs: number | null, now = Date.now()): Promise<{ event: AuditEventV1; chain: ChainStatus } | null> {
  const [fromMs, toMs] = atMs ? [atMs - 3_600_000, Math.min(atMs + 3_600_000, now)] : [now - 30 * DAY_MS, now]
  const client = lokiClient()
  const scoped = { ...f, eventId }
  const hits = await client.queryRange({ query: auditQuery(scoped, env.LOKI_NAMESPACE), startNs: msToNs(fromMs), endNs: msToNs(toMs + 1), limit: 5, direction: 'backward' })
  const hit = hits.map((h) => ({ h, e: parseLine(h.line) })).find((x) => x.e && matches(x.e, scoped, x.h.line))
  if (!hit?.e) return null
  const e = hit.e
  if (typeof e.seq !== 'number' || e.seq <= 1 || !e.chain_id) return { event: e, chain: chainStatus(e, undefined) }

  // The neighbour may belong to any org: it is read to verify, never returned.
  const eMs = Date.parse(e.ts)
  const neighbours = await client.queryRange({
    query: auditQuery({ chain: { id: e.chain_id, from: e.seq - 1, to: e.seq - 1 } }, env.LOKI_NAMESPACE),
    startNs: msToNs(eMs - 30 * DAY_MS), endNs: msToNs(eMs + 1), limit: 5, direction: 'backward',
  })
  const prev = neighbours.map((n) => parseLine(n.line)).find((n) => n && n.chain_id === e.chain_id && n.seq === e.seq - 1) ?? undefined
  return { event: e, chain: chainStatus(e, prev) }
}
