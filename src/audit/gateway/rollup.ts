import type { FastifyBaseLogger } from 'fastify'
import { env } from '../../config/env.js'
import { getRedisClient } from '../../services/redis-client.service.js'
import { lokiClient } from '../query/loki.js'
import { auditLog } from '../v1/index.js'
import type { AuditV1Input } from '../v1/emitter.js'
import { gatewayQuery, isUnauthenticated, subjectKind } from './decisions.js'

/**
 * `access.summary`: what the gateway allowed and refused, into the audit trail, one event per
 * subject and host per hour — never one per request.
 *
 * The gateway's own log is kept as long as any log; the audit trail 400 days. So the counts are
 * copied into the trail hourly, a few minutes after the hour closes (Loki ingests with a lag). One
 * replica writes each hour (a Redis key per hour, set NX); a failed hour gives its key back and is
 * tried again on the next tick, for up to BACKFILL_H hours.
 *
 * Bounded: at most MAX_EVENTS per hour, the busiest first; the rest are folded into one event per
 * kind of actor. Unauthenticated traffic (scanners, expired sessions) is one event per host with
 * an anonymous actor, which the console hides by default.
 */

const HOUR_S = 3600
const LAG_S = 5 * 60
const BACKFILL_H = 3
const MAX_EVENTS = 200
const TICK_MS = 5 * 60_000

type Row = { subject: string; host: string; allowed: number; denied: number }

const hourLabel = (endS: number) => {
  const iso = (s: number) => new Date(s * 1000).toISOString().slice(11, 16)
  return `${new Date((endS - HOUR_S) * 1000).toISOString().slice(0, 10)} ${iso(endS - HOUR_S)}–${iso(endS)} UTC`
}

function actorOf(subject: string): AuditV1Input['actor'] {
  const kind = subjectKind(subject)
  if (kind === 'anonymous') return { type: 'anonymous' }
  // An id with an address in it would be refused by the schema: kept as an HMAC instead.
  return subject.includes('@') ? { type: kind, email: subject } : { type: kind, id: subject }
}

function eventOf(row: Row, endS: number, label?: string): AuditV1Input {
  const who = isUnauthenticated(row.subject) ? 'unauthenticated requests' : 'requests'
  return {
    event: 'access.summary',
    result: row.allowed > 0 ? 'success' : 'denied',
    actor: actorOf(row.subject),
    target: row.host ? { type: 'host', id: row.host } : null,
    changes: {
      resource: 'host',
      ...(row.host ? { id: row.host } : {}),
      summary: `${label ?? (row.host || 'gateway')}: ${row.allowed} ${who} allowed, ${row.denied} denied, ${hourLabel(endS)}`,
    },
    flags: ['rollup'],
    source: 'gateway',
  }
}

/** The events for the hour ending at `endS` (seconds, on the hour), without writing them. */
export async function hourEvents(endS: number): Promise<AuditV1Input[]> {
  const samples = await lokiClient().instant(`sum by (granted, subject, host) (count_over_time(${gatewayQuery()} [${HOUR_S}s]))`, endS)
  const rows = new Map<string, Row>()
  for (const { metric, value } of samples) {
    const subject = isUnauthenticated(metric.subject ?? '') ? '' : (metric.subject ?? '')
    const host = metric.host ?? ''
    const key = `${subject}\n${host}`
    const row = rows.get(key) ?? { subject, host, allowed: 0, denied: 0 }
    if (metric.granted === 'true') row.allowed += value
    else row.denied += value
    rows.set(key, row)
  }
  const sorted = [...rows.values()].filter((r) => r.allowed + r.denied > 0).sort((a, b) => b.allowed + b.denied - (a.allowed + a.denied))
  const kept = sorted.slice(0, MAX_EVENTS)
  const events = kept.map((r) => eventOf(r, endS))
  // The long tail: one event per kind, so the hour's totals still add up.
  const rest = new Map<string, Row & { n: number }>()
  for (const r of sorted.slice(MAX_EVENTS)) {
    const kind = subjectKind(r.subject)
    const agg = rest.get(kind) ?? { subject: kind === 'anonymous' ? '' : kind, host: '', allowed: 0, denied: 0, n: 0 }
    agg.allowed += r.allowed
    agg.denied += r.denied
    agg.n++
    rest.set(kind, agg)
  }
  for (const [kind, agg] of rest) {
    events.push({
      ...eventOf(agg, endS, `${agg.n} more ${kind === 'anonymous' ? 'hosts' : `${kind}/host pairs`}`),
      actor: { type: kind as 'user' | 'service' | 'anonymous' },
    })
  }
  return events
}

const doneKey = (endS: number) => `auth:audit:access_rollup:${endS}`

/** Writes every closed hour not yet written (the last BACKFILL_H). Returns the hours written. */
export async function rollupTick(now = Date.now()): Promise<number[]> {
  const lastEnd = Math.floor((now / 1000 - LAG_S) / HOUR_S) * HOUR_S
  const written: number[] = []
  for (let endS = lastEnd - (BACKFILL_H - 1) * HOUR_S; endS <= lastEnd; endS += HOUR_S) {
    const redis = getRedisClient()
    if ((await redis.set(doneKey(endS), '1', 'EX', 3 * 86_400, 'NX')) !== 'OK') continue
    try {
      for (const event of await hourEvents(endS)) await auditLog.emit(event)
      written.push(endS)
    } catch {
      // Loki unreachable: give the hour back, the next tick tries again.
      await redis.del(doneKey(endS)).catch(() => {})
    }
  }
  return written
}

let timer: NodeJS.Timeout | null = null

export function startAccessRollup(log: FastifyBaseLogger): void {
  if (timer || env.ACCESS_ROLLUP === 'off' || !env.LOKI_URL || env.AUDIT_SINK === 'legacy') return
  const tick = () => void rollupTick().then((hours) => {
    if (hours.length) log.info({ hours: hours.map((h) => new Date(h * 1000).toISOString()) }, '[audit] gateway access summarised')
  }).catch((err) => log.warn({ err }, '[audit] gateway access summary failed'))
  timer = setInterval(tick, TICK_MS)
  timer.unref()
  tick()
}

/** Test seam. */
export function stopAccessRollup(): void {
  if (timer) clearInterval(timer)
  timer = null
}
