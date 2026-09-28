import * as sources from '../sources.js'
import { ensureLabels, person } from '../labels.js'
import { auditQuery, countBy, regexAlternation, type AuditFilter } from '../../audit/query/logql.js'
import { foldCategory } from '../../services/audit-types.js'
import type { LokiSample, LokiSeries } from '../../audit/query/loki.js'
import type { Activity, HomeWindow } from '../types.js'
import type { ModuleResult } from '../cache.js'
import type { HomeView } from '../scope.js'
import { CONNECT, iso, ok, src, unavailable, windowMs, type ModuleDef } from './common.js'

/**
 * Sign-ins and the audit pulse (home-data §3.5 activity, J9). Tier C: Loki is never on a request's
 * path — a background refresh writes the result, a request reads it.
 *
 * Source: audit/v1 in Loki when LOKI_URL is set and the v1 sink is on; otherwise the legacy Redis
 * stream, platform only (it is not org-scoped) and without top actors (it is keyed by address).
 * Org admins are filtered INSIDE the query (auditPipeline's org_id stage), never after the fact.
 */

const BUCKETS = 24
const SPIKE_FACTOR = 3
const SPIKE_FLOOR = 20
const LOGIN_EVENTS = ['auth.login.succeeded', 'auth.login.failed']
export const CHANGE_CATEGORIES = ['authz', 'config', 'directory', 'secret']
const LEGACY_SCAN = 20_000

type Series = Activity['series']

function emptySeries(startMs: number, stepMs: number): Series {
  return Array.from({ length: BUCKETS }, (_, i) => ({ t: iso(startMs + i * stepMs), succeeded: 0, failed: 0, changes: 0 }))
}

/** A count ending at `tMs` (Loki's count_over_time window, or an event time) → its bucket. */
const bucketOf = (tMs: number, startMs: number, stepMs: number) => Math.min(BUCKETS - 1, Math.max(0, Math.floor((tMs - startMs - 1) / stepMs)))

const byLabel = (samples: LokiSample[], label: string) => {
  const out: Record<string, number> = {}
  for (const s of samples) out[s.metric[label] ?? ''] = (out[s.metric[label] ?? ''] ?? 0) + s.value
  return out
}
const total = (samples: LokiSample[]) => samples.reduce((a, s) => a + s.value, 0)

/** No address may leave in an aggregate key; older legacy rows still carry raw paths (pre-J8). */
const safeRoute = (route: string) => !route.includes('@') && route !== '—'

/**
 * `failedFactor` (§10): the failures of the last hour against the median of the same hour-of-day over
 * the previous 7 days; null below 3× or below 20 failures.
 */
export function failedFactor(hourly: number[]): number | null {
  return failedSpike(hourly)?.factor ?? null
}

export function failedSpike(hourly: number[]): { factor: number; current: number; baseline: number } | null {
  if (hourly.length < 2) return null
  const current = hourly[hourly.length - 1]
  const sameHour = hourly.slice(0, -1).filter((_, i, arr) => (arr.length - i) % 24 === 0)
  if (sameHour.length === 0) return null
  const sorted = [...sameHour].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  const median = sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
  const factor = Math.round((current / Math.max(median, 1)) * 10) / 10
  return factor >= SPIKE_FACTOR && current >= SPIKE_FLOOR ? { factor, current, baseline: median } : null
}

async function fromLoki(view: HomeView, window: HomeWindow, now: number): Promise<Activity> {
  const client = sources.loki()
  const ns = sources.lokiNamespace()
  const orgs = view.kind === 'orgs' ? view.orgs : undefined
  const q = (f: AuditFilter) => auditQuery({ ...f, ...(orgs ? { orgs } : {}) }, ns)
  const wMs = windowMs(window)
  const wS = wMs / 1000
  const nowS = now / 1000
  const stepS = wS / BUCKETS
  const logins = q({ events: LOGIN_EVENTS })
  const denied = q({ events: ['access.denied'] })
  const changes = `${q({ result: 'success' })} | category=~${regexAlternation(CHANGE_CATEGORIES)}`
  const failed = q({ events: ['auth.login.failed'] })

  const [signNow, signPrev, distinct, loginSeries, changeSeries, byCategory, deniedNow, deniedPrev, topDenied, topActors, hourly] = await Promise.all([
    client.instant(countBy(logins, 'event', wS), nowS),
    client.instant(countBy(logins, 'event', wS), nowS - wS),
    client.instant(`count(${countBy(q({ events: ['auth.login.succeeded'] }), 'actor_id', wS)})`, nowS),
    client.range(`sum by (event) (count_over_time(${logins} [${stepS}s]))`, nowS - wS + stepS, nowS, stepS),
    client.range(`sum(count_over_time(${changes} [${stepS}s]))`, nowS - wS + stepS, nowS, stepS),
    client.instant(countBy(q({}), 'category', wS), nowS),
    client.instant(countBy(denied, null, wS), nowS),
    client.instant(countBy(denied, null, wS), nowS - wS),
    client.instant(countBy(denied, 'target_id', wS, 10), nowS),
    orgs ? Promise.resolve([] as LokiSample[]) : client.instant(countBy(q({}), 'actor_id', wS, 10), nowS),
    client.range(`sum(count_over_time(${failed} [3600s]))`, nowS - 7 * 86_400, nowS, 3600),
  ])

  const startMs = now - wMs
  const stepMs = wMs / BUCKETS
  const series = emptySeries(startMs, stepMs)
  const fill = (list: LokiSeries[], pick: (s: LokiSeries) => 'succeeded' | 'failed' | 'changes' | null) => {
    for (const s of list) {
      const field = pick(s)
      if (!field) continue
      for (const [t, v] of s.values) series[bucketOf(t * 1000, startMs, stepMs)][field] += v
    }
  }
  fill(loginSeries, (s) => (s.metric.event === 'auth.login.succeeded' ? 'succeeded' : s.metric.event === 'auth.login.failed' ? 'failed' : null))
  fill(changeSeries, () => 'changes')

  await ensureLabels().catch(() => {})
  const now_ = byLabel(signNow, 'event')
  const prev = byLabel(signPrev, 'event')
  const hourlyValues = hourly[0]?.values.map(([, v]) => v) ?? []
  return {
    window,
    signIns: {
      succeeded: now_['auth.login.succeeded'] ?? 0,
      failed: now_['auth.login.failed'] ?? 0,
      prevSucceeded: prev['auth.login.succeeded'] ?? 0,
      prevFailed: prev['auth.login.failed'] ?? 0,
      distinctUsers: total(distinct),
      failedFactor: failedFactor(hourlyValues),
      failedSpike: failedSpike(hourlyValues),
    },
    series,
    byCategory: byLabel(byCategory, 'category'),
    denied: { total: total(deniedNow), prev: total(deniedPrev) },
    topDeniedRoutes: topDenied.map((s) => ({ route: s.metric.target_id ?? '', count: s.value })).filter((r) => r.route && safeRoute(r.route)),
    ...(orgs ? {} : { topActors: topActors.filter((s) => s.metric.actor_id).map((s) => ({ actorId: s.metric.actor_id, label: person(s.metric.actor_id).label, count: s.value })) }),
    source: 'loki',
    truncated: false,
  }
}

async function fromLegacy(window: HomeWindow, now: number): Promise<Activity> {
  const wMs = windowMs(window)
  const rows = await sources.legacyRows(now - 2 * wMs, LEGACY_SCAN)
  const startMs = now - wMs
  const stepMs = wMs / BUCKETS
  const series = emptySeries(startMs, stepMs)
  const sign = { succeeded: 0, failed: 0, prevSucceeded: 0, prevFailed: 0 }
  const denied = { total: 0, prev: 0 }
  const byCategory: Record<string, number> = {}
  const deniedRoutes: Record<string, number> = {}
  const users = new Set<string>()

  for (const [id, fields] of rows) {
    const ms = Number(id.split('-')[0])
    const f: Record<string, string> = {}
    for (let i = 0; i < fields.length; i += 2) f[fields[i]] = fields[i + 1]
    const current = ms >= startMs
    const result = f.result || 'ok'
    const failedResult = result === 'denied' || result === 'failed' || result === 'error'
    const login = f.category === 'auth' && f.verb === 'login'
    if (login) {
      if (failedResult) current ? sign.failed++ : sign.prevFailed++
      else current ? sign.succeeded++ : sign.prevSucceeded++
    }
    if (result === 'denied' && f.category !== 'auth') current ? denied.total++ : denied.prev++
    if (!current) continue
    const cat = foldCategory(f.category || 'system')
    byCategory[cat] = (byCategory[cat] ?? 0) + 1
    const b = series[bucketOf(ms + 1, startMs, stepMs)]
    if (login) failedResult ? b.failed++ : b.succeeded++
    if (f.kind === 'change') b.changes++
    if (login && !failedResult) {
      try {
        const actor = JSON.parse(f.actor || '{}') as { id?: string; email?: string }
        const key = actor.id || actor.email
        if (key) users.add(key) // counted, never returned
      } catch { /* ignore */ }
    }
    if (result === 'denied' && f.category === 'access' && f.target && safeRoute(f.target)) deniedRoutes[f.target] = (deniedRoutes[f.target] ?? 0) + 1
  }

  return {
    window,
    // TODO(HOME-later): the spike from the legacy stream needs a 7-day scan; audit/v1 carries it.
    signIns: { ...sign, distinctUsers: users.size, failedFactor: null, failedSpike: null },
    series,
    byCategory,
    denied,
    topDeniedRoutes: Object.entries(deniedRoutes).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([route, count]) => ({ route, count })),
    source: 'redis-legacy',
    truncated: rows.length >= LEGACY_SCAN,
  }
}

/** Which audit store answers for this view, or why none can. Shared with `changes`. */
export function auditSourceFor(view: HomeView): 'loki' | 'redis-legacy' | ModuleResult<never> {
  const sink = sources.auditSink()
  if (sources.lokiConfigured() && sink !== 'legacy') return 'loki'
  if (view.kind === 'platform' && sink !== 'v1') return 'redis-legacy'
  if (!sources.lokiConfigured()) {
    return unavailable(view.kind === 'platform' ? 'not_configured' : 'not_deployed', { loki: src('not_configured', CONNECT.loki) }, CONNECT.loki)
  }
  return unavailable('not_deployed', { loki: src('ok'), audit_v1: src('not_deployed', CONNECT.auditV1) }, CONNECT.auditV1)
}

export const activityModule: ModuleDef<Activity> = {
  name: 'activity',
  tier: 'background',
  freshMs: 60_000,
  timeoutMs: 150,
  windowed: true,
  async compute(ctx) {
    const which = auditSourceFor(ctx.view)
    if (typeof which !== 'string') return which
    if (which === 'loki') return ok(await fromLoki(ctx.view, ctx.window, ctx.now), { loki: src('ok') })
    return ok(await fromLegacy(ctx.window, ctx.now), { audit_legacy: src('ok'), loki: sources.lokiConfigured() ? src('ok') : src('not_configured', CONNECT.loki) })
  },
}

