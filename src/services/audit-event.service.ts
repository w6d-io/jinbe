import { Counter, Histogram, register } from 'prom-client'
import { getRedisClient } from './redis-client.service.js'
import { env } from '../config/env.js'

/**
 * Audit Event Service
 *
 * Publishes structured audit events to Redis Streams.
 * Also increments Prometheus counters for metrics scraping at GET /metrics.
 *
 * Stream: auth:audit:events (configurable via REDIS_AUDIT_STREAM)
 *
 * Rich event schema — maps directly to the frontend AuditEvent shape.
 */

// ─── Rich event schema ───────────────────────────────────────────────────────

export type AuditCategory = 'auth' | 'access' | 'rbac' | 'policy' | 'service' | 'route' | 'secret' | 'system'
export type AuditResult   = 'ok' | 'applied' | 'denied' | 'failed' | 'error'

export interface AuditActor {
  email:     string | null    // email, "system", or "anon"
  name?:     string | null
  ip?:       string | null
  ua?:       string | null    // User-Agent (truncated)
  sessionId?: string | null
}

export interface AuditEvent {
  category:  AuditCategory
  verb:      string           // allow, deny, login, logout, create, update, delete, assign, sync, expire, mfa, commit
  target:    string           // human-readable: "GET /api/clusters", "group:finance", "user:omar@w6d.io"
  result:    AuditResult
  actor:     AuditActor
  service?:  string           // RBAC service name if applicable
  reason?:   string           // denial/error reason
  method?:   string           // HTTP method (access events)
  path?:     string           // HTTP path (access events)
  statusCode?: number
  responseTimeMs?: number
  source?:   string           // 'jinbe-api' | 'kratos-webhook' | 'opal'
}

// ─── Legacy compat type (callers still using old schema get auto-upgraded) ──

export interface LegacyAuditEvent {
  type: string
  actor?: { email?: string; ip?: string }
  target?: { type?: string; id?: string; service?: string }
  details?: Record<string, unknown>
  source?: string
}

// ─── Prometheus metrics ──────────────────────────────────────────────────────

export const auditEventsCounter = new Counter({
  name: 'jinbe_audit_events_total',
  help: 'Total audit events emitted, by category/verb/result',
  labelNames: ['category', 'verb', 'result'] as const,
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
  'groups_changed': 'assign',
}

function upgradeLegacy(ev: LegacyAuditEvent): AuditEvent {
  const parts = ev.type.split('.')
  const cat   = parts[0] as AuditCategory
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

  return {
    category:  cat || 'system',
    verb,
    target:    targetStr,
    result,
    actor: {
      email: ev.actor?.email || null,
      ip:    ev.actor?.ip    || (d.ip as string | undefined) || null,
    },
    service:     ev.target?.service,
    reason:      d.reason as string | undefined,
    method:      d.method as string | undefined,
    path:        d.path   as string | undefined,
    statusCode:  d.statusCode as number | undefined,
    responseTimeMs: d.responseTimeMs as number | undefined,
    source:      ev.source || 'jinbe-api',
  }
}

function redisFields(ev: AuditEvent): string[] {
  const fields: string[] = [
    'category',  ev.category,
    'verb',      ev.verb,
    'target',    ev.target,
    'result',    ev.result,
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
  return fields
}

// ─── Service ─────────────────────────────────────────────────────────────────

class AuditEventService {
  private get streamKey() { return env.REDIS_AUDIT_STREAM }
  private get redis() { return getRedisClient() }

  /** Emit a rich audit event */
  async emit(event: AuditEvent | LegacyAuditEvent): Promise<string | null> {
    const rich: AuditEvent = 'category' in event ? event : upgradeLegacy(event as LegacyAuditEvent)
    try {
      auditEventsCounter.labels(rich.category, rich.verb, rich.result).inc()
      const fields = redisFields(rich)
      const id = await this.redis.xadd(this.streamKey, 'MAXLEN', '~', '100000', '*', ...fields)
      return id
    } catch (err) {
      console.error('[audit] Failed to emit event:', err)
      return null
    }
  }

  /**
   * Query audit events — returns frontend-ready objects (newest first)
   */
  async query(options: {
    limit?:    number
    since?:    string
    until?:    string
    category?: AuditCategory
  } = {}): Promise<Array<FrontendAuditEvent>> {
    const { limit = 50, since = '-', until = '+', category } = options

    const fetchLimit = category ? Math.min(limit * 5, 500) : limit
    const results = await this.redis.xrevrange(this.streamKey, until, since, 'COUNT', String(fetchLimit))

    const events: FrontendAuditEvent[] = []
    for (const [id, fields] of results) {
      const raw: Record<string, string> = {}
      for (let i = 0; i < fields.length; i += 2) raw[fields[i]] = fields[i + 1]

      const cat = (raw.category || 'system') as AuditCategory
      if (category && cat !== category) continue

      let actor: AuditActor = { email: null }
      try { actor = JSON.parse(raw.actor || '{}') } catch { /* ignore */ }

      events.push({
        id,
        ts:            raw.timestamp,
        when:          timeAgo(raw.timestamp),
        category:      cat,
        verb:          raw.verb || '?',
        target:        raw.target || '—',
        result:        (raw.result || 'ok') as AuditResult,
        who:           actor.email || 'anon',
        actorName:     actor.name  || undefined,
        ip:            actor.ip   || undefined,
        ua:            actor.ua   ? raw.actor && shortUa(actor.ua) : undefined,
        service:       raw.service || undefined,
        reason:        raw.reason  || undefined,
        method:        raw.method  || undefined,
        path:          raw.path    || undefined,
        statusCode:    raw.statusCode ? Number(raw.statusCode) : undefined,
        responseTimeMs: raw.responseTimeMs ? Number(raw.responseTimeMs) : undefined,
      })

      if (events.length >= limit) break
    }

    return events
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
  verb:           string
  target:         string
  result:         AuditResult
  who:            string       // email | "anon" | "system"
  actorName?:     string
  ip?:            string
  ua?:            string
  service?:       string
  reason?:        string
  method?:        string
  path?:          string
  statusCode?:    number
  responseTimeMs?: number
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
