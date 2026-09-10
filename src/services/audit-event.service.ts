import { Counter, Histogram, register } from 'prom-client'
import pino from 'pino'
import { getRedisClient } from './redis-client.service.js'
import { env } from '../config/env.js'

/**
 * Audit Event Service
 *
 * Publishes structured audit events to Redis Streams.
 * Also increments Prometheus counters for metrics scraping at GET /metrics.
 *
 * Stream: auth:audit:events (configurable via REDIS_AUDIT_STREAM, capped by
 * REDIS_AUDIT_MAXLEN). On emit we ALSO fan out to bounded per-entity keys
 * (per-service, per-actor, per-target, per-source-IP) so per-entity trails
 * aren't limited to the global window. Every write is redacted (no secrets/PII).
 *
 * Retention is bounded by the caps; there is NO tamper-evidence in this pass
 * (documented Redis-only limit — Mongo/WORM is an upgrade path).
 */

// ─── Rich event schema ───────────────────────────────────────────────────────

export type AuditCategory = 'auth' | 'access' | 'rbac' | 'policy' | 'service' | 'route' | 'secret' | 'system'
export type AuditResult   = 'ok' | 'applied' | 'denied' | 'failed' | 'error'
// Coarse grouping used for fan-out gating + UI facets. `security` is reserved
// for explicitly security-flagged emits (kept in the fan-out predicate even
// though it is not a default derived value).
export type AuditKind     = 'change' | 'access' | 'auth' | 'system' | 'security'
// Server-authoritative severity. Maps to UI semantic tokens (info/warn/err);
// `high` is the security-critical tier surfaced via ?risk=high.
export type AuditSeverity = 'info' | 'warn' | 'high'
export type AuditFlag     = 'opened_to_public' | 'auth_disabled' | 'grants_super_admin' | 'wildcard_permission'

export interface AuditActor {
  id?:       string | null    // the immutable identity; an address changes hands, this does not
  email:     string | null    // email, "system", or null (unauthenticated)
  name?:     string | null
  ip?:       string | null
  ua?:       string | null    // User-Agent (truncated)
  sessionId?: string | null
}

/**
 * Loosely-typed actor as threaded from a request through service mutations
 * (A4/P2-5). Superset of the old `{email, ip}` builder — carries name/ua/
 * sessionId for the audit trail and `requestId` for cross-event correlation.
 */
export interface AuditActorInput {
  id?:        string | null
  email?:     string | null
  name?:      string | null
  ip?:        string | null
  ua?:        string | null
  sessionId?: string | null
  requestId?: string | null
}

/**
 * Compact before→after diff envelope. Structural only — values are never
 * serialized here: `added`/`removed` are allow-listed identifiers (service:role,
 * method:path, group names …); `changedKeys` are field names (secret-looking
 * names are redacted); `flags` are computed posture signals; `summary` is
 * plain-language.
 */
export interface AuditChanges {
  resource:     string
  id?:          string
  added?:       string[]
  removed?:     string[]
  changedKeys?: string[]
  flags?:       AuditFlag[]
  summary?:     string
}

export interface AuditEvent {
  category:  AuditCategory
  kind?:     AuditKind
  verb:      string           // allow, deny, login, logout, create, update, delete, assign, sync, expire, mfa, commit
  target:    string           // human-readable: "GET /api/clusters", "group:finance", "user:alice@example.com"
  result:    AuditResult
  actor:     AuditActor
  service?:  string           // RBAC service name if applicable
  reason?:   string           // denial/error reason
  method?:   string           // HTTP method (access events)
  path?:     string           // HTTP path (access events)
  statusCode?: number
  responseTimeMs?: number
  source?:   string           // 'jinbe-api' | 'kratos-webhook' | 'opal' | 'bootstrap'
  // ── Enrichment (A1) ──
  requestId?:  string | null
  changes?:    AuditChanges   // before→after diff (redacted at write time)
  details?:    Record<string, unknown>  // free-form (redacted by key at write time)
  targetId?:   string         // structured target id (e.g. Kratos uuid) for filtering
  targetType?: string         // 'user' | 'group' | 'service' | 'access_rule' | …
  mfa?:        string         // second-factor method/state (auth events)
  severity?:   AuditSeverity  // computed at emit if omitted
}

// ─── Legacy compat type (callers still using old schema get auto-upgraded) ──

export interface LegacyAuditEvent {
  type: string
  actor?: { email?: string | null; ip?: string | null; name?: string | null; ua?: string | null; sessionId?: string | null; requestId?: string | null }
  target?: { type?: string; id?: string; service?: string; services?: string[] }
  details?: Record<string, unknown>
  changes?: AuditChanges
  requestId?: string | null
  source?: string
  severity?: AuditSeverity
}

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

export const httpRequestsCounter = new Counter({
  name: 'jinbe_http_requests_total',
  help: 'Total HTTP requests, by method/route/status_class',
  labelNames: ['method', 'route', 'status_class'] as const,
})

export const httpDurationHistogram = new Histogram({
  name: 'jinbe_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route'] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
})

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

// [P2-1] Fold out-of-enum legacy categories into the canonical taxonomy so
// they are filterable + iconed rather than 400ing the route schema.
const CATEGORY_FOLD: Record<string, AuditCategory> = {
  roles: 'rbac',
  api_key: 'secret',
  user: 'access',
  organization_user: 'access',
}

function foldCategory(cat: string): AuditCategory {
  return (CATEGORY_FOLD[cat] ?? cat) as AuditCategory
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

  /** Emit a rich audit event. Fire-and-forget at call sites; fail-loud here. */
  async emit(event: AuditEvent | LegacyAuditEvent): Promise<string | null> {
    const rich: AuditEvent = normalize('category' in event ? (event as AuditEvent) : upgradeLegacy(event as LegacyAuditEvent))
    let id: string | null = null
    try {
      auditEventsCounter.labels(rich.category, rich.verb, rich.result).inc()
      const fields = redisFields(rich)
      id = await this.redis.xadd(this.streamKey, 'MAXLEN', '~', String(env.REDIS_AUDIT_MAXLEN), '*', ...fields)
    } catch (err) {
      // [P1-1] Fail-loud — never a silent catch for a security event.
      auditEmitFailuresCounter.labels(rich.category, rich.verb).inc()
      auditLog.error(
        { err: (err as Error).message, category: rich.category, verb: rich.verb, result: rich.result, target: rich.target, actor: rich.actor?.email ?? null },
        'audit emit failed (primary stream)',
      )
      return null
    }

    // Secondary fan-out is best-effort — a fan-out failure must not fail the
    // primary emit that already succeeded, but it is still logged loudly.
    try {
      if (shouldFanOut(rich)) await this.fanOut(rich)
    } catch (err) {
      auditLog.warn({ err: (err as Error).message, target: rich.target }, 'audit fan-out failed (primary stream intact)')
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

    const targetEmail = targetEmailOf(ev)
    if (targetEmail && targetEmail !== actorEmail) keys.push(`auth:audit:target:${targetEmail}`)

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

  /**
   * Query audit events — returns frontend-ready objects (newest first).
   * Reads the most specific fan-out key when an entity filter is given, so a
   * per-service/per-actor/per-target trail is not bounded by the global window.
   */
  async query(options: {
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
  } = {}): Promise<Array<FrontendAuditEvent>> {
    const { limit = 50, category, actor, service, target, result, verb, kind, from, to, q, risk, cursor } = options

    // Pick the source stream: most specific entity key wins.
    let sourceKey = this.streamKey
    if (actor)        sourceKey = `auth:audit:actor:${actor}`
    else if (service) sourceKey = `auth:audit:svc:${service}`
    else if (target)  sourceKey = `auth:audit:target:${target}`

    // Window → stream IDs. `from`/`to` are ms epochs; stream IDs are `<ms>-<seq>`.
    // `cursor` (a prior page's last id) becomes an EXCLUSIVE upper bound.
    const since = from != null ? `${from}-0` : (options.since ?? '-')
    const until = cursor ? `(${cursor}` : (to != null ? `${to}-9999` : (options.until ?? '+'))

    // Over-fetch when filtering in-memory so post-filter still yields `limit`.
    const filtering = !!(category || result || verb || kind || q || risk)
    const fetchLimit = filtering ? Math.min(limit * 8, 2000) : limit
    const results = await this.redis.xrevrange(sourceKey, until, since, 'COUNT', String(fetchLimit))

    const events: FrontendAuditEvent[] = []
    for (const [id, fields] of results) {
      const raw: Record<string, string> = {}
      for (let i = 0; i < fields.length; i += 2) raw[fields[i]] = fields[i + 1]

      const cat = foldCategory(raw.category || 'system')
      if (category && cat !== category) continue
      if (result && raw.result !== result) continue
      if (verb && raw.verb !== verb) continue
      if (kind && (raw.kind || 'change') !== kind) continue
      if (risk === 'high' && (raw.severity || 'info') !== 'high') continue

      let actorObj: AuditActor = { email: null }
      try { actorObj = JSON.parse(raw.actor || '{}') } catch { /* ignore */ }

      const who = actorObj.email || 'anon'
      if (q) {
        const hay = `${raw.target || ''} ${who} ${raw.reason || ''}`.toLowerCase()
        if (!hay.includes(q.toLowerCase())) continue
      }

      let changes: AuditChanges | undefined
      if (raw.changes) { try { changes = JSON.parse(raw.changes) } catch { /* ignore */ } }
      let details: Record<string, unknown> | undefined
      if (raw.details) { try { details = JSON.parse(raw.details) } catch { /* ignore */ } }

      events.push({
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
      })

      if (events.length >= limit) break
    }

    return events
  }

  /**
   * Windowed summary derived from the SHARED Redis stream (P1-2) — not
   * Prometheus (per-replica + resets on redeploy). Scans bounded by the window,
   * computing the start ID from `windowMs`.
   */
  async summary(windowMs: number): Promise<AuditSummary> {
    const now = Date.now()
    const prevStartId = `${now - 2 * windowMs}-0`
    // Scan the window (bounded by time, not the global cap).
    const rows = await this.redis.xrevrange(this.streamKey, '+', prevStartId, 'COUNT', '20000')

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

  async getPrometheusMetrics(): Promise<string> {
    return register.metrics()
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

export const auditEventService = new AuditEventService()
