import { Counter } from 'prom-client'
import pino from 'pino'
import { getRedisClient } from './redis-client.service.js'
import { env } from '../config/env.js'
import { foldCategory, type AuditCategory, type AuditChanges, type AuditEvent, type AuditKind, type AuditResult, type AuditSeverity, type LegacyAuditEvent } from './audit-types.js'
import { queryPage, summarizeStream, type AuditQueryOptions, type AuditSummary, type FrontendAuditEvent } from './audit-query.js'
import { auditLog as auditV1 } from '../audit/v1/index.js'
import { legacyToV1 } from '../audit/v1/legacy-map.js'

/**
 * Audit Event Service
 *
 * Publishes structured audit events to Redis Streams and, per AUDIT_SINK, to the audit/v1 line +
 * outbox (audit/v1). `legacy` = Redis only, `dual` (default) = both, `v1` = audit/v1 only.
 * Also increments Prometheus counters (served by telemetry/metrics-server.ts).
 *
 * Stream: auth:audit:events (configurable via REDIS_AUDIT_STREAM, capped by
 * REDIS_AUDIT_MAXLEN). On emit we ALSO fan out to bounded per-entity keys
 * (per-service, per-actor, per-target, per-source-IP) so per-entity trails
 * aren't limited to the global window. Every write is redacted (no secrets/PII).
 *
 * Retention is bounded by the caps; there is NO tamper-evidence in this pass
 * (documented Redis-only limit — Mongo/WORM is an upgrade path).
 */

// ─── Rich event schema (audit-types.ts) ─────────────────────────────────────

export * from './audit-types.js'
export type { AuditQueryOptions, AuditSummary, FrontendAuditEvent } from './audit-query.js'

// ─── Prometheus metrics ──────────────────────────────────────────────────────

export const auditEventsCounter = new Counter({
  name: 'jinbe_audit_events_total',
  help: 'Total audit events emitted, by category/verb/result',
  labelNames: ['category', 'verb', 'result'] as const,
})

// [P1-1] Fail-loud: incremented whenever the primary audit write fails, so a
// silent audit outage is observable in metrics + logs.
export const auditEmitFailuresCounter = new Counter({
  name: 'jinbe_audit_emit_failures_total',
  help: 'Total audit events that failed to persist to the primary stream',
  labelNames: ['category', 'verb'] as const,
})

// HTTP RED series live with the other process metrics; re-exported for existing importers.
export { httpRequestsCounter, httpDurationHistogram } from '../telemetry/metrics.js'

// Structured logger for fail-loud audit lines (no request context here).
// Fall back to 'info' when LOG_LEVEL is absent (e.g. a partially-mocked env).
const auditLog = pino({ name: 'audit', level: env.LOG_LEVEL || 'info' })

// ─── Redaction (P0-3) ─────────────────────────────────────────────────────────

// Field-name deny pattern. Any object key (or a bare identifier such as a
// metadata changedKey) matching this is redacted — its VALUE never serializes.
export const AUDIT_DENY_PATTERN =
  /pass(word)?|secret|token|api[-_]?key|client_secret|credential|authoriz|cookie|recover|otp|totp|lookup|code|link|jwks|private[-_]?key/i

const REDACTED = '[redacted]'

/**
 * Deep-redact a free-form object by KEY (values are dropped for sensitive
 * keys, never inspected for content — so structural strings like paths are
 * preserved). Used for legacy `details` blobs and webhook payloads.
 */
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[truncated]'
  if (value === null || value === undefined) return value
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1))
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = AUDIT_DENY_PATTERN.test(k) ? REDACTED : redact(v, depth + 1)
    }
    return out
  }
  return value
}

/** Redact a list of field-NAMES (e.g. metadata changedKeys) in place. */
export function redactFieldNames(names: string[] | undefined): string[] | undefined {
  if (!names) return names
  return names.map((n) => (AUDIT_DENY_PATTERN.test(n) ? REDACTED : n))
}

/** Sanitize a changes envelope: never let a sensitive field-name leak. */
function sanitizeChanges(c: AuditChanges | undefined): AuditChanges | undefined {
  if (!c) return c
  return { ...c, changedKeys: redactFieldNames(c.changedKeys) }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Maps legacy event type suffixes to clean verbs
const VERB_MAP: Record<string, string> = {
  'created': 'create', 'updated': 'update', 'deleted': 'delete',
  'group_created': 'create', 'group_updated': 'update', 'group_deleted': 'delete',
  'service_created': 'create', 'service_deleted': 'delete',
  'service_routes_updated': 'update', 'service_roles_updated': 'update',
  'unauthorized': 'deny', 'denied': 'deny',
  'client_error': 'error', 'server_error': 'error',
  'login': 'login', 'logout': 'logout', 'mfa': 'mfa',
  'groups_changed': 'assign', 'import': 'import',
}

/** Coarse kind derived from category/result when a caller doesn't set one. */
function deriveKind(ev: { category: AuditCategory; result: AuditResult }): AuditKind {
  if (ev.category === 'access') return 'access'
  if (ev.category === 'auth') return 'auth'
  if (ev.category === 'system') return 'system'
  return 'change'
}

/** Server-authoritative severity from flags/result when a caller doesn't set one. */
function deriveSeverity(ev: {
  result: AuditResult
  changes?: AuditChanges
}): AuditSeverity {
  const flags = ev.changes?.flags ?? []
  if (flags.length > 0) return 'high'
  if (ev.result === 'denied' || ev.result === 'error' || ev.result === 'failed') return 'warn'
  return 'info'
}

function upgradeLegacy(ev: LegacyAuditEvent): AuditEvent {
  const parts = ev.type.split('.')
  const cat   = foldCategory(parts[0] || 'system')
  const suffix = parts.slice(1).join('.')
  const verb  = VERB_MAP[suffix] || suffix || cat
  const d     = ev.details || {}

  const result: AuditResult =
    ev.type.includes('unauthorized') ? 'denied' :
    ev.type.includes('denied')       ? 'denied' :
    ev.type.includes('error')        ? 'error'  : 'applied'

  // Build human-readable target
  const tgt = ev.target
  const targetStr = tgt
    ? tgt.type && tgt.id ? `${tgt.type}:${tgt.id}` : (tgt.id || tgt.service || '—')
    : String(d.path || d.id || '—')

  // Map details → changes. A group mutation carries oldGroups/newGroups, which
  // becomes an added/removed envelope; anything else keeps its (redacted)
  // details and records the changed field-names.
  let changes = ev.changes
  if (!changes) {
    const oldGroups = Array.isArray(d.oldGroups) ? (d.oldGroups as string[]) : undefined
    const newGroups = Array.isArray(d.newGroups) ? (d.newGroups as string[]) : undefined
    if (oldGroups || newGroups) {
      const before = new Set(oldGroups ?? [])
      const after  = new Set(newGroups ?? [])
      changes = {
        resource: 'user_groups',
        id: tgt?.id,
        added:   [...after].filter((g) => !before.has(g)),
        removed: [...before].filter((g) => !after.has(g)),
      }
    }
  }

  return {
    category:  cat,
    verb,
    target:    targetStr,
    result,
    actor: {
      id:        ev.actor?.id ?? null,
      email:     ev.actor?.email ?? null,
      name:      ev.actor?.name ?? null,
      ip:        ev.actor?.ip ?? (d.ip as string | undefined) ?? null,
      ua:        ev.actor?.ua ?? null,
      sessionId: ev.actor?.sessionId ?? null,
    },
    service:     ev.target?.service,
    reason:      d.reason as string | undefined,
    method:      d.method as string | undefined,
    path:        d.path   as string | undefined,
    statusCode:  d.statusCode as number | undefined,
    responseTimeMs: d.responseTimeMs as number | undefined,
    source:      ev.source || 'jinbe-api',
    // requestId may arrive top-level or inside the actor (auditActor() carries
    // it there) — accept either so cascade child-events correlate.
    requestId:   ev.requestId ?? ev.actor?.requestId ?? null,
    changes,
    details:     ev.details,
    targetId:    tgt?.id,
    targetType:  tgt?.type,
    severity:    ev.severity,
    v1Event:     ev.v1Event,
  }
}

/** Normalize + redact a rich event before it is written anywhere. */
function normalize(rich: AuditEvent): AuditEvent {
  const category = foldCategory(rich.category)
  const changes  = sanitizeChanges(rich.changes)
  const details  = rich.details ? (redact(rich.details) as Record<string, unknown>) : undefined
  const kind     = rich.kind ?? deriveKind({ category, result: rich.result })
  const severity = rich.severity ?? deriveSeverity({ result: rich.result, changes })
  return { ...rich, category, kind, changes, details, severity }
}

function redisFields(ev: AuditEvent): string[] {
  const fields: string[] = [
    'category',  ev.category,
    'kind',      ev.kind || 'change',
    'verb',      ev.verb,
    'target',    ev.target,
    'result',    ev.result,
    'severity',  ev.severity || 'info',
    'actor',     JSON.stringify(ev.actor),
    'timestamp', new Date().toISOString(),
    'source',    ev.source || 'jinbe-api',
  ]
  if (ev.service)       fields.push('service',       ev.service)
  if (ev.reason)        fields.push('reason',        ev.reason)
  if (ev.method)        fields.push('method',        ev.method)
  if (ev.path)          fields.push('path',          ev.path)
  if (ev.statusCode != null) fields.push('statusCode', String(ev.statusCode))
  if (ev.responseTimeMs != null) fields.push('responseTimeMs', String(ev.responseTimeMs))
  if (ev.requestId)     fields.push('requestId',     ev.requestId)
  if (ev.targetId)      fields.push('targetId',      ev.targetId)
  if (ev.targetType)    fields.push('targetType',    ev.targetType)
  if (ev.mfa)           fields.push('mfa',           ev.mfa)
  if (ev.changes)       fields.push('changes',       JSON.stringify(ev.changes))
  if (ev.details)       fields.push('details',       JSON.stringify(ev.details))
  return fields
}

// ─── Fan-out keys (P0-2) ───────────────────────────────────────────────────────

const FANOUT_MAXLEN = 500
const FANOUT_TTL_S  = 90 * 24 * 60 * 60 // 90 days

/** A Kratos-directory (verified) actor — the ONLY actors that get an actor: key. */
function directoryEmail(email: string | null | undefined): string | null {
  if (!email) return null
  if (email === 'system' || email === 'anon' || email === 'anonymous') return null
  return email.includes('@') ? email : null
}

/** Parse a `user:<email>` target into its email (for the done-to trail). */
function targetEmailOf(ev: AuditEvent): string | null {
  if (ev.targetType === 'user') {
    const direct = directoryEmail((ev.details?.targetEmail as string | undefined) ?? null)
    if (direct) return direct
  }
  if (ev.target.startsWith('user:')) {
    return directoryEmail(ev.target.slice('user:'.length))
  }
  return null
}

/**
 * Decide whether this event fans out to per-entity keys. Fan out ONLY for
 * change/auth/security kinds OR applied/denied/error results — NEVER a plain
 * access.allow (every admin GET), which would evict the change records.
 */
function shouldFanOut(ev: AuditEvent): boolean {
  const kind = ev.kind || 'change'
  if (kind === 'change' || kind === 'auth' || kind === 'security') return true
  return ev.result === 'applied' || ev.result === 'denied' || ev.result === 'error'
}

// ─── Service ─────────────────────────────────────────────────────────────────

class AuditEventService {
  private get streamKey() { return env.REDIS_AUDIT_STREAM }
  private get redis() { return getRedisClient() }

  /**
   * Emit a rich audit event. Fire-and-forget at call sites; fail-loud here.
   * Returns the Redis stream id (or, with AUDIT_SINK=v1, the audit/v1 event_id); null on failure.
   */
  async emit(event: AuditEvent | LegacyAuditEvent): Promise<string | null> {
    const legacyType = 'category' in event ? undefined : (event as LegacyAuditEvent).type
    const rich: AuditEvent = normalize('category' in event ? (event as AuditEvent) : upgradeLegacy(event as LegacyAuditEvent))
    const sink = env.AUDIT_SINK ?? 'dual'

    let v1Id: string | null = null
    if (sink !== 'legacy') {
      // Never throws: its own failures are counted and reported by the emitter.
      v1Id = (await auditV1.emit(legacyToV1(rich, legacyType)))?.event_id ?? null
    }
    if (sink === 'v1') return v1Id

    let id: string | null = null
    try {
      auditEventsCounter.labels(rich.category, rich.verb, rich.result).inc()
      const fields = redisFields(rich)
      id = await this.redis.xadd(this.streamKey, 'MAXLEN', '~', String(env.REDIS_AUDIT_MAXLEN), '*', ...fields)
    } catch (err) {
      // [P1-1] Fail-loud — never a silent catch for a security event.
      auditEmitFailuresCounter.labels(rich.category, rich.verb).inc()
      auditLog.error(
        { err: (err as Error).message, category: rich.category, verb: rich.verb, result: rich.result, targetType: rich.targetType, actorId: rich.actor?.id ?? null },
        'audit emit failed (primary stream)',
      )
      return null
    }

    // Secondary fan-out is best-effort — a fan-out failure must not fail the
    // primary emit that already succeeded, but it is still logged loudly.
    try {
      if (shouldFanOut(rich)) await this.fanOut(rich)
    } catch (err) {
      auditLog.warn({ err: (err as Error).message, targetType: rich.targetType }, 'audit fan-out failed (primary stream intact)')
    }
    return id
  }

  /** Write bounded per-entity copies + provenance index. */
  private async fanOut(ev: AuditEvent): Promise<void> {
    const fields = redisFields(ev)
    const keys: string[] = []

    if (ev.service) keys.push(`auth:audit:svc:${ev.service}`)

    const actorEmail = directoryEmail(ev.actor?.email)
    if (actorEmail) {
      keys.push(`auth:audit:actor:${actorEmail}`)
    } else if (ev.actor?.ip) {
      // Unverified/attacker actor: a SINGLE bounded per-IP key only — never an
      // attacker-chosen actor:<email> key (memory-DoS + log-poisoning guard).
      keys.push(`auth:audit:ip:${ev.actor.ip}`)
    }

    // The "done to them" trail, under the address (what the console has) AND the immutable id, so
    // the trail survives an address change. Read back by audit-query `targetTrailKey`.
    const targetEmail = targetEmailOf(ev)
    if (targetEmail && targetEmail !== actorEmail) keys.push(`auth:audit:target:${targetEmail}`)
    if (ev.targetType === 'user' && ev.targetId && !ev.targetId.includes('@') && ev.targetId !== ev.actor?.id) {
      keys.push(`auth:audit:target:${ev.targetId}`)
    }

    for (const key of keys) {
      await this.redis.xadd(key, 'MAXLEN', '~', String(FANOUT_MAXLEN), '*', ...fields)
      await this.redis.expire(key, FANOUT_TTL_S)
    }

    // Provenance index — last activity per directory actor (dormant-admin signal).
    if (actorEmail) {
      const now = new Date().toISOString()
      await this.redis.hset('auth:audit:last_seen', actorEmail, now)
      if (ev.kind === 'change' || ev.severity === 'high') {
        await this.redis.hset('auth:audit:last_privileged_action', actorEmail, now)
      }
    }
  }

  /** One page of events plus an honest cursor (audit-query `queryPage`). */
  async queryPage(options: AuditQueryOptions = {}): Promise<{ events: FrontendAuditEvent[]; nextCursor: string | null }> {
    return queryPage(this.redis, this.streamKey, options)
  }

  /** Events only, newest first — for exports and trails that do not page. */
  async query(options: AuditQueryOptions = {}): Promise<FrontendAuditEvent[]> {
    return (await this.queryPage(options)).events
  }

  async summary(windowMs: number): Promise<AuditSummary> {
    return summarizeStream(this.redis, this.streamKey, windowMs)
  }

  // ── SWR cache for /summary (mirrors getDirectoryStats: fresh-ms + single-
  // flight). Per-replica in-memory cache is safe because the summary is derived
  // from the SHARED stream, so every replica computes the same value; the cache
  // only avoids recomputing the window scan on every request. ──
  private summaryCache = new Map<number, { computedAt: number; data: AuditSummary }>()
  private summaryFlight = new Map<number, Promise<AuditSummary>>()
  private readonly SUMMARY_FRESH_MS = 15_000

  /** SWR-cached windowed summary — returns fresh-or-stale at once, refreshes in bg. */
  async summaryCached(windowMs: number): Promise<AuditSummary & { computedAt: string; window: number }> {
    const cached = this.summaryCache.get(windowMs)
    if (cached) {
      if (Date.now() - cached.computedAt >= this.SUMMARY_FRESH_MS) {
        void this.refreshSummary(windowMs).catch(() => {})
      }
      return { ...cached.data, computedAt: new Date(cached.computedAt).toISOString(), window: windowMs }
    }
    const data = await this.refreshSummary(windowMs)
    return { ...data, computedAt: new Date().toISOString(), window: windowMs }
  }

  private refreshSummary(windowMs: number): Promise<AuditSummary> {
    const inflight = this.summaryFlight.get(windowMs)
    if (inflight) return inflight
    const p = (async () => {
      const data = await this.summary(windowMs)
      this.summaryCache.set(windowMs, { computedAt: Date.now(), data })
      return data
    })().finally(() => this.summaryFlight.delete(windowMs))
    this.summaryFlight.set(windowMs, p)
    return p
  }

  async count(): Promise<number> {
    return this.redis.xlen(this.streamKey)
  }
}

export const auditEventService = new AuditEventService()
