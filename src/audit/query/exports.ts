import { createHash, randomUUID } from 'crypto'
import { env } from '../../config/env.js'
import { getRedisClient } from '../../services/redis-client.service.js'
import { auditEventService, type AuditActorInput } from '../../services/audit-event.service.js'
import type { AuditEventV1 } from '../v1/schema.js'
import type { AuditFilter } from './logql.js'
import { LokiUnavailableError, MAX_ENTRIES } from './loki.js'
import { MAX_SPAN_MS, decodeCursor, type Filters } from './params.js'
import { readPage } from './reader.js'

/**
 * Audit exports (CONTROL C4, AU-13): an async job, one at a time per user, bounded in rows, audited.
 *
 * Outbox-style: the request writes the job record and appends its id to a Redis stream; a worker
 * takes each queued id, streams the range out of Loki in ≤30-day windows, stores the file, and only
 * THEN removes the id from the queue. A replica dying mid-job leaves the id queued for the next
 * drain. The file is kept one hour behind an owner-checked download route (no bucket in this pass).
 */

const QUEUE = 'auth:audit:exports'
const JOB = (id: string) => `auth:audit:export:${id}`
const DATA = (id: string) => `auth:audit:export:${id}:data`
const LOCK = (id: string) => `auth:audit:export:${id}:lock`
const ACTIVE = (owner: string) => `auth:audit:export:active:${owner}`
const TTL_S = 3600

export interface ExportJob {
  id: string
  owner: string
  status: 'queued' | 'running' | 'done' | 'failed'
  format: 'csv' | 'ndjson'
  fromMs: number
  toMs: number
  filters: Filters
  query: AuditFilter
  actor: AuditActorInput
  createdAt: string
  rows?: number
  sha256?: string
  truncated?: boolean
  error?: string
  expiresAt?: string
}

async function save(job: ExportJob): Promise<void> {
  await getRedisClient().set(JOB(job.id), JSON.stringify(job), 'EX', 24 * TTL_S)
}

export async function getJob(id: string): Promise<ExportJob | null> {
  const raw = await getRedisClient().get(JOB(id))
  return raw ? (JSON.parse(raw) as ExportJob) : null
}

export async function getJobData(id: string): Promise<string | null> {
  return getRedisClient().get(DATA(id))
}

/** Queues a job, or returns null when this user already has one running. */
export async function enqueueExport(input: Omit<ExportJob, 'id' | 'status' | 'createdAt'>): Promise<ExportJob | null> {
  const redis = getRedisClient()
  const id = randomUUID()
  if ((await redis.set(ACTIVE(input.owner), id, 'EX', TTL_S, 'NX')) !== 'OK') return null
  const job: ExportJob = { ...input, id, status: 'queued', createdAt: new Date().toISOString() }
  await save(job)
  await redis.xadd(QUEUE, '*', 'id', id)
  return job
}

// ─── Formats ────────────────────────────────────────────────────────────────

const CSV_COLS = ['ts', 'event_id', 'event', 'category', 'action', 'result', 'reason', 'severity', 'actor_type', 'actor_id', 'target_type', 'target_id', 'org_id', 'site', 'request_id', 'trace_id', 'chain_id', 'seq', 'hash'] as const

function csvRow(e: AuditEventV1): string {
  const v: Record<(typeof CSV_COLS)[number], unknown> = {
    ts: e.ts, event_id: e.event_id, event: e.event, category: e.category, action: e.action, result: e.result,
    reason: e.reason, severity: e.severity, actor_type: e.actor?.type, actor_id: e.actor?.id, target_type: e.target?.type,
    target_id: e.target?.id, org_id: e.org_id, site: e.site, request_id: e.request_id, trace_id: e.trace_id,
    chain_id: e.chain_id, seq: e.seq, hash: e.hash,
  }
  return CSV_COLS.map((c) => {
    const s = v[c] == null ? '' : String(v[c])
    // A leading = + - @ would run as a formula in a spreadsheet.
    const safe = /^[=+\-@]/.test(s) ? `'${s}` : s
    return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
  }).join(',')
}

// ─── Worker ─────────────────────────────────────────────────────────────────

async function collect(job: ExportJob): Promise<{ events: AuditEventV1[]; truncated: boolean }> {
  const events: AuditEventV1[] = []
  const max = env.AUDIT_EXPORT_MAX_ROWS
  // Newest window first, each ≤30 days (Loki max_query_length), paged within.
  for (let end = job.toMs; end > job.fromMs; end -= MAX_SPAN_MS) {
    const start = Math.max(job.fromMs, end - MAX_SPAN_MS)
    let cursor = null
    for (;;) {
      const page = await readPage(job.query, start, end, Math.min(MAX_ENTRIES - 250, max - events.length + 1), cursor)
      events.push(...page.events)
      if (events.length > max) return { events: events.slice(0, max), truncated: true }
      if (!page.nextCursor) break
      cursor = decodeCursor(page.nextCursor)
    }
  }
  return { events, truncated: false }
}

async function run(job: ExportJob): Promise<void> {
  const redis = getRedisClient()
  await save({ ...job, status: 'running' })
  try {
    const { events, truncated } = await collect(job)
    const body = job.format === 'csv'
      ? [CSV_COLS.join(','), ...events.map(csvRow)].join('\n')
      : events.map((e) => JSON.stringify(e)).join('\n')
    const sha256 = createHash('sha256').update(body).digest('hex')
    await redis.set(DATA(job.id), body, 'EX', TTL_S)
    await save({ ...job, status: 'done', rows: events.length, sha256, truncated, expiresAt: new Date(Date.now() + TTL_S * 1000).toISOString() })
    // The export is an exfiltration path: it is itself an event (audit.exported), once, when done.
    auditEventService.emit({
      category: 'system', kind: 'change', verb: 'export', target: `audit_export:${job.id}`,
      targetType: 'audit_export', targetId: job.id, result: 'applied',
      actor: { id: job.actor.id ?? null, email: job.actor.email ?? null, ip: job.actor.ip ?? null, ua: job.actor.ua ?? null, sessionId: job.actor.sessionId ?? null },
      requestId: job.actor.requestId ?? null,
      details: {
        format: job.format, rows: events.length, sha256, truncated,
        from: new Date(job.fromMs).toISOString(), to: new Date(job.toMs).toISOString(),
        ...(job.query.orgs?.length === 1 ? { organizationId: job.query.orgs[0] } : {}),
      },
      source: 'jinbe-api',
      v1Event: 'audit.exported',
    }).catch(() => {})
  } catch (err) {
    const error = err instanceof LokiUnavailableError ? 'audit_store_unavailable' : 'export_failed'
    await save({ ...job, status: 'failed', error })
  }
}

/** `autoDrain`: the request that queues a job kicks a drain. Tests turn it off to drive the worker. */
export const exportsConfig = { autoDrain: true }

let draining: Promise<void> | null = null

/** Runs every queued job this replica can claim. Safe to call often; one drain at a time. */
export function drainExports(): Promise<void> {
  draining ??= (async () => {
    const redis = getRedisClient()
    try {
      for (const [entryId, fields] of await redis.xrange(QUEUE, '-', '+', 'COUNT', 50)) {
        const id = fields[fields.indexOf('id') + 1]
        if ((await redis.set(LOCK(id), '1', 'EX', 600, 'NX')) !== 'OK') continue
        const job = await getJob(id)
        if (job && job.status === 'queued') await run(job)
        // Acked only after the job reached a final state (or vanished): the outbox rule.
        await redis.xdel(QUEUE, entryId)
        await redis.del(LOCK(id))
        if (job) await redis.del(ACTIVE(job.owner))
      }
    } finally {
      draining = null
    }
  })()
  return draining
}
