import type { Redis } from 'ioredis'
import { foldCategory, type AuditActor, type AuditCategory, type AuditChanges, type AuditKind, type AuditResult, type AuditSeverity } from './audit-event.service.js'

/**
 * Read side of the legacy Redis audit stream: the paged event list and the windowed summary.
 *
 * Retired with the stream itself (AUD-14); the v1 reads come from Loki (AUD-9).
 */

export interface AuditQueryOptions {
  limit?:    number
  since?:    string
  until?:    string
  category?: AuditCategory
  actor?:    string
  service?:  string
  target?:   string
  result?:   AuditResult
  verb?:     string
  kind?:     AuditKind
  from?:     number   // ms epoch lower bound
  to?:       number   // ms epoch upper bound
  q?:        string   // free-text substring over target/who/reason
  risk?:     'high'
  cursor?:   string   // exclusive upper-bound stream ID for pagination
}

const BATCH = 500
const SCAN_BUDGET = 20_000

/** `user:<email>` / `user:<id>` (what the console sends) and a bare value read the same trail key. */
export function targetTrailKey(target: string): string {
  return `auth:audit:target:${target.startsWith('user:') ? target.slice('user:'.length) : target}`
}

/**
 * One page of events, newest first, read from the most specific fan-out key when an entity filter
 * is given (so a per-service/actor/target trail is not bounded by the global window).
 *
 * Filters are applied while scanning backwards in batches until the page is full, the window is
 * exhausted or the scan budget is spent — so a sparse filter finds its rows whatever `limit` is.
 * `nextCursor` is null only when the window holds nothing more: the scan looks for one match past
 * the page, and when the budget runs out first it returns where it stopped.
 */
export async function queryPage(
  redis: Redis,
  streamKey: string,
  options: AuditQueryOptions = {},
): Promise<{ events: FrontendAuditEvent[]; nextCursor: string | null }> {
  const { limit = 50, category, actor, service, target, result, verb, kind, from, to, q, risk, cursor } = options

  let sourceKey = streamKey
  if (actor)        sourceKey = `auth:audit:actor:${actor}`
  else if (service) sourceKey = `auth:audit:svc:${service}`
  else if (target)  sourceKey = targetTrailKey(target)

  // Window → stream IDs. `from`/`to` are ms epochs; stream IDs are `<ms>-<seq>`.
  // `cursor` (a prior page's last id) becomes an EXCLUSIVE upper bound.
  const since = from != null ? `${from}-0` : (options.since ?? '-')
  let until = cursor ? `(${cursor}` : (to != null ? `${to}-9999` : (options.until ?? '+'))

  const budget = Math.max(SCAN_BUDGET, limit + 1)
  const events: FrontendAuditEvent[] = []
  let scanned = 0
  let lastScanned: string | null = null
  let exhausted = false
  let more = false

  while (!more) {
    const count = Math.min(BATCH, budget - scanned)
    if (count <= 0) break
    const rows = await redis.xrevrange(sourceKey, until, since, 'COUNT', String(count))
    for (const [id, fields] of rows) {
      lastScanned = id
      const ev = toFrontend(id, fields, { category, result, verb, kind, risk, q })
      if (!ev) continue
      if (events.length === limit) { more = true; break }
      events.push(ev)
    }
    scanned += rows.length
    if (rows.length < count) { exhausted = true; break }
    if (lastScanned) until = `(${lastScanned}`
  }

  const nextCursor = more
    ? events[events.length - 1]?.id ?? null
    : exhausted ? null : (events.length === limit ? events[events.length - 1]?.id ?? null : lastScanned)
  return { events, nextCursor }
}

type RowFilter = Pick<AuditQueryOptions, 'category' | 'result' | 'verb' | 'kind' | 'risk' | 'q'>

/** A stored row as the console reads it, or null when a filter excludes it. */
function toFrontend(id: string, fields: string[], f: RowFilter): FrontendAuditEvent | null {
  const raw: Record<string, string> = {}
  for (let i = 0; i < fields.length; i += 2) raw[fields[i]] = fields[i + 1]

  const cat = foldCategory(raw.category || 'system')
  if (f.category && cat !== f.category) return null
  if (f.result && raw.result !== f.result) return null
  if (f.verb && raw.verb !== f.verb) return null
  if (f.kind && (raw.kind || 'change') !== f.kind) return null
  if (f.risk === 'high' && (raw.severity || 'info') !== 'high') return null

  let actorObj: AuditActor = { email: null }
  try { actorObj = JSON.parse(raw.actor || '{}') } catch { /* ignore */ }

  const who = actorObj.email || 'anon'
  if (f.q) {
    const hay = `${raw.target || ''} ${who} ${raw.reason || ''}`.toLowerCase()
    if (!hay.includes(f.q.toLowerCase())) return null
  }

  let changes: AuditChanges | undefined
  if (raw.changes) { try { changes = JSON.parse(raw.changes) } catch { /* ignore */ } }
  let details: Record<string, unknown> | undefined
  if (raw.details) { try { details = JSON.parse(raw.details) } catch { /* ignore */ } }

  return {
    id,
    ts:            raw.timestamp,
    when:          timeAgo(raw.timestamp),
    category:      cat,
    kind:          (raw.kind as AuditKind) || 'change',
    verb:          raw.verb || '?',
    target:        raw.target || '—',
    result:        (raw.result || 'ok') as AuditResult,
    severity:      (raw.severity as AuditSeverity) || 'info',
    who,
    actorName:     actorObj.name  || undefined,
    ip:            actorObj.ip   || undefined,
    ua:            actorObj.ua   ? shortUa(actorObj.ua) : undefined,
    sessionId:     actorObj.sessionId || undefined,
    service:       raw.service || undefined,
    reason:        raw.reason  || undefined,
    method:        raw.method  || undefined,
    path:          raw.path    || undefined,
    statusCode:    raw.statusCode ? Number(raw.statusCode) : undefined,
    responseTimeMs: raw.responseTimeMs ? Number(raw.responseTimeMs) : undefined,
    requestId:     raw.requestId || undefined,
    targetId:      raw.targetId || undefined,
    targetType:    raw.targetType || undefined,
    mfa:           raw.mfa || undefined,
    changes,
    details,
  }
}

/**
 * Windowed summary derived from the SHARED Redis stream (P1-2) — not
 * Prometheus (per-replica + resets on redeploy). Scans bounded by the window,
 * computing the start ID from `windowMs`.
 */
export async function summarizeStream(redis: Redis, streamKey: string, windowMs: number): Promise<AuditSummary> {
  const now = Date.now()
  const prevStartId = `${now - 2 * windowMs}-0`
  // Scan the window (bounded by time, not the global cap).
  const rows = await redis.xrevrange(streamKey, '+', prevStartId, 'COUNT', '20000')

  const byKind: Record<string, number> = {}
  const byCategory: Record<string, { total: number; failed: number }> = {}
  const byResult: Record<string, number> = {}
  const topDeniedMap: Record<string, number> = {}
  const topActorsMap: Record<string, number> = {}
  const activeActors = new Set<string>()
  const seriesBuckets = new Map<number, number>()
  const bucketMs = Math.max(Math.floor(windowMs / 24), 60_000)

  let total = 0
  let prevTotal = 0
  let failed = 0

  for (const [id, fields] of rows) {
    const ms = Number(id.split('-')[0])
    const inCurrent = ms >= now - windowMs
    if (!inCurrent) { prevTotal++; continue }
    total++

    const raw: Record<string, string> = {}
    for (let i = 0; i < fields.length; i += 2) raw[fields[i]] = fields[i + 1]

    const cat  = foldCategory(raw.category || 'system')
    // Derive kind from category when absent (legacy/access-log events have no
    // `kind`) — defaulting to 'change' misclassified every admin-GET access.allow
    // as a config mutation, inflating "changes" and contradicting the client.
    const kind = raw.kind || (cat === 'access' ? 'access' : cat === 'auth' ? 'auth' : cat === 'system' ? 'system' : 'change')
    const result = raw.result || 'ok'
    const isFail = result === 'denied' || result === 'error' || result === 'failed'

    byKind[kind] = (byKind[kind] ?? 0) + 1
    byResult[result] = (byResult[result] ?? 0) + 1
    if (!byCategory[cat]) byCategory[cat] = { total: 0, failed: 0 }
    byCategory[cat].total++
    if (isFail) { byCategory[cat].failed++; failed++ }

    if (result === 'denied') {
      const key = raw.target || '—'
      topDeniedMap[key] = (topDeniedMap[key] ?? 0) + 1
    }

    try {
      const a = JSON.parse(raw.actor || '{}') as AuditActor
      if (a.email) {
        activeActors.add(a.email)
        // Top actors = who is making real changes (not the UI's own reads).
        if ((kind === 'change' || kind === 'auth') && a.email !== 'system') {
          topActorsMap[a.email] = (topActorsMap[a.email] ?? 0) + 1
        }
      }
    } catch { /* ignore */ }

    const bucket = Math.floor(ms / bucketMs) * bucketMs
    seriesBuckets.set(bucket, (seriesBuckets.get(bucket) ?? 0) + 1)
  }

  const series = [...seriesBuckets.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([t, count]) => ({ t: new Date(t).toISOString(), count }))
  const topDenied = Object.entries(topDeniedMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([target, count]) => ({ target, count }))
  const topActors = Object.entries(topActorsMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([actor, count]) => ({ actor, count }))

  return {
    total,
    prevTotal,
    byKind,
    byCategory,
    byResult,
    failureRate: total > 0 ? failed / total : 0,
    activeActors: activeActors.size,
    series,
    topDenied,
    topActors,
  }
}

// ─── Frontend event shape ─────────────────────────────────────────────────────

export interface FrontendAuditEvent {
  id:             string
  ts:             string
  when:           string
  category:       AuditCategory
  kind:           AuditKind
  verb:           string
  target:         string
  result:         AuditResult
  severity:       AuditSeverity
  who:            string       // email | "anon" | "system"
  actorName?:     string
  ip?:            string
  ua?:            string
  sessionId?:     string
  service?:       string
  reason?:        string
  method?:        string
  path?:          string
  statusCode?:    number
  responseTimeMs?: number
  requestId?:     string
  targetId?:      string
  targetType?:    string
  mfa?:           string
  changes?:       AuditChanges
  details?:       Record<string, unknown>
}

export interface AuditSummary {
  total:        number
  prevTotal:    number
  byKind:       Record<string, number>
  byCategory:   Record<string, { total: number; failed: number }>
  byResult:     Record<string, number>
  failureRate:  number
  activeActors: number
  series:       Array<{ t: string; count: number }>
  topDenied:    Array<{ target: string; count: number }>
  topActors:    Array<{ actor: string; count: number }>
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60)   return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60)   return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24)   return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function shortUa(ua: string): string {
  // Return browser name only
  if (ua.includes('Firefox'))  return 'Firefox'
  if (ua.includes('Edg'))      return 'Edge'
  if (ua.includes('Chrome'))   return 'Chrome'
  if (ua.includes('Safari'))   return 'Safari'
  if (ua.includes('curl'))     return 'curl'
  return ua.slice(0, 32)
}
