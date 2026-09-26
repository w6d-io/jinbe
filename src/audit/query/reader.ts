import { env } from '../../config/env.js'
import { auditEventV1Schema, type AuditEventV1 } from '../v1/schema.js'
import { GENESIS, verifyChain } from '../v1/chain.js'
import { auditQuery, countBy, type AuditFilter } from './logql.js'
import { lokiClient, msToNs, MAX_ENTRIES } from './loki.js'
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

const FACETS = { event: 'event', category: 'category', result: 'result', site: 'site', actor: 'actor_id' } as const
const TOP = 20

function label(metric: Record<string, string>, field: string): string {
  return metric[field] ?? metric[`${field}_extracted`] ?? ''
}

function counts(samples: Array<{ metric: Record<string, string>; value: number }>, field: string): Count[] {
  return samples
    .map((s) => ({ key: label(s.metric, field), count: s.value }))
    .filter((c) => c.key !== '')
    .sort((a, b) => b.count - a.count)
}

export async function facets(f: AuditFilter, fromMs: number, toMs: number): Promise<{ facets: Record<keyof typeof FACETS, Count[]>; total: number; truncated: boolean }> {
  const query = auditQuery(f, env.LOKI_NAMESPACE)
  const rangeS = (toMs - fromMs) / 1000
  const client = lokiClient()
  const names = Object.keys(FACETS) as Array<keyof typeof FACETS>
  const [totalSamples, ...perFacet] = await Promise.all([
    client.instant(countBy(query, null, rangeS), toMs / 1000),
    // One more than shown: that is how "there were more" is known without a second query.
    ...names.map((n) => client.instant(countBy(query, FACETS[n], rangeS, TOP + 1), toMs / 1000)),
  ])
  let truncated = false
  const out = {} as Record<keyof typeof FACETS, Count[]>
  names.forEach((n, i) => {
    const list = counts(perFacet[i], FACETS[n])
    if (list.length > TOP) truncated = true
    out[n] = list.slice(0, TOP)
  })
  return { facets: out, total: totalSamples.reduce((a, s) => a + s.value, 0), truncated }
}

const sumBy = (list: Count[]) => Object.fromEntries(list.map((c) => [c.key, c.count]))
const failedOf = (byResult: Record<string, number>) => Object.entries(byResult).filter(([k]) => k !== 'success').reduce((a, [, v]) => a + v, 0)

export async function summary(f: AuditFilter, window: string, wMs: number, now = Date.now()) {
  const query = auditQuery(f, env.LOKI_NAMESPACE)
  const denied = auditQuery({ ...f, result: 'denied' }, env.LOKI_NAMESPACE)
  const client = lokiClient()
  const wS = wMs / 1000
  const nowS = now / 1000
  const stepS = Math.max(60, Math.floor(wS / 24))
  const [byCategory, byResult, prevByResult, series, topDenied, topActors] = await Promise.all([
    client.instant(countBy(query, 'category', wS), nowS),
    client.instant(countBy(query, 'result', wS), nowS),
    client.instant(countBy(query, 'result', wS), nowS - wS),
    client.range(`sum by (result) (count_over_time(${query} [${stepS}s]))`, nowS - wS, nowS, stepS),
    client.instant(countBy(denied, 'target_id', wS, 10), nowS),
    client.instant(countBy(query, 'actor_id', wS, 10), nowS),
  ])
  const results = sumBy(counts(byResult, 'result'))
  const prevResults = sumBy(counts(prevByResult, 'result'))
  const buckets = new Map<number, { total: number; failed: number }>()
  for (const s of series) {
    const failed = label(s.metric, 'result') !== 'success'
    for (const [t, v] of s.values) {
      const b = buckets.get(t) ?? { total: 0, failed: 0 }
      b.total += v
      if (failed) b.failed += v
      buckets.set(t, b)
    }
  }
  const total = Object.values(results).reduce((a, v) => a + v, 0)
  return {
    window,
    total,
    prev: { total: Object.values(prevResults).reduce((a, v) => a + v, 0), failed: failedOf(prevResults), denied: prevResults.denied ?? 0 },
    byCategory: sumBy(counts(byCategory, 'category')),
    byResult: results,
    series: [...buckets.entries()].sort(([a], [b]) => a - b).map(([t, b]) => ({ t: new Date(t * 1000).toISOString(), ...b })),
    topDenied: counts(topDenied, 'target_id').slice(0, 10),
    topActors: counts(topActors, 'actor_id').slice(0, 10).map((c) => ({ actorId: c.key, count: c.count })),
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
