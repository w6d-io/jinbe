import type { FastifyInstance } from 'fastify'
import { auditEventService } from '../services/audit-event.service.js'
import { requireAdmin } from '../middleware/require-admin.js'
import { auditActor } from '../utils/audit-actor.js'
import { unauthorizedResponseSchema, forbiddenResponseSchema } from '../schemas/response-schemas.js'
import type { AuditCategory, AuditKind, AuditResult, FrontendAuditEvent } from '../services/audit-event.service.js'
import { guardAll } from '../policy/declared-routes.js'
import { isPublicRoute } from '../middleware/require-auth.js'

/**
 * Audit Events endpoint — admin only
 *
 * GET /audit/events   → paginated rich audit log (newest first, filterable)
 * GET /audit/summary  → windowed stats derived from the Redis stream (P1-2)
 * GET /audit/export   → server-side NDJSON/CSV of a filtered range (audits itself)
 * GET /audit/metrics  → Prometheus text format (no auth — scraper access)
 */

// Canonical categories only (out-of-enum legacy categories are folded server-side).
const CATEGORY_ENUM = ['auth', 'access', 'rbac', 'policy', 'service', 'route', 'secret', 'system']
const KIND_ENUM = ['change', 'access', 'auth', 'system', 'security']
const RESULT_ENUM = ['ok', 'applied', 'denied', 'failed', 'error']

// Parse a window shorthand ('24h','7d','90m','3600000') → ms. Default 24h.
function parseWindowMs(raw: string | undefined): number {
  if (!raw) return 24 * 60 * 60 * 1000
  const m = /^(\d+)\s*(ms|s|m|h|d)?$/.exec(raw.trim())
  if (!m) return 24 * 60 * 60 * 1000
  const n = Number(m[1])
  switch (m[2]) {
    case 'd': return n * 86_400_000
    case 'h': return n * 3_600_000
    case 'm': return n * 60_000
    case 's': return n * 1_000
    case 'ms': return n
    default:  return n // bare number = ms
  }
}

interface EventsQuery {
  limit?: number; since?: string; until?: string; cursor?: string
  category?: AuditCategory; actor?: string; service?: string; target?: string
  result?: AuditResult; verb?: string; kind?: AuditKind
  from?: number; to?: number; q?: string; risk?: 'high'
}

export async function auditRoutes(fastify: FastifyInstance) {
  // Prometheus scrape endpoint — no auth (IP-level protection at ingress)
  fastify.get('/metrics', {
    schema: {
      description: 'Prometheus metrics for audit events and HTTP requests',
      tags: ['audit'],
      response: { 200: { type: 'string' } },
    },
  }, async (_req, reply) => {
    const metrics = await auditEventService.getPrometheusMetrics()
    reply.header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
    return reply.send(metrics)
  })

  // All remaining routes require admin
  guardAll(fastify, requireAdmin, isPublicRoute)

  fastify.get('/events', {
    schema: {
      description: 'Query audit events (newest first). Rich schema — maps directly to UI.',
      tags: ['audit'],
      querystring: {
        type: 'object',
        properties: {
          limit:    { type: 'integer', minimum: 1, maximum: 500, default: 50 },
          since:    { type: 'string', description: 'Stream ID lower bound ("-" = oldest)' },
          until:    { type: 'string', description: 'Stream ID upper bound ("+" = newest)' },
          cursor:   { type: 'string', description: 'Exclusive upper-bound stream ID for pagination' },
          category: { type: 'string', enum: CATEGORY_ENUM },
          actor:    { type: 'string', description: 'Actor email — reads the per-actor trail' },
          service:  { type: 'string', description: 'Service name — reads the per-service trail' },
          target:   { type: 'string', description: 'Target email — reads the "done-to" trail' },
          result:   { type: 'string', enum: RESULT_ENUM },
          verb:     { type: 'string' },
          kind:     { type: 'string', enum: KIND_ENUM },
          from:     { type: 'integer', description: 'ms epoch lower bound' },
          to:       { type: 'integer', description: 'ms epoch upper bound' },
          q:        { type: 'string', description: 'free-text substring over target/actor/reason' },
          risk:     { type: 'string', enum: ['high'] },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            events:     { type: 'array', items: { type: 'object', additionalProperties: true } },
            total:      { type: 'number' },
            nextCursor: { type: 'string', nullable: true },
          },
        },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, async (request, reply) => {
    const query = request.query as EventsQuery
    const [events, total] = await Promise.all([
      auditEventService.query(query),
      auditEventService.count(),
    ])
    const nextCursor = events.length === (query.limit ?? 50) ? events[events.length - 1]?.id ?? null : null
    return reply.send({ events, total, nextCursor })
  })

  fastify.get('/summary', {
    schema: {
      description: 'Windowed audit summary derived from the shared Redis stream (not Prometheus).',
      tags: ['audit'],
      querystring: {
        type: 'object',
        properties: {
          window: { type: 'string', description: "e.g. '24h', '7d', '1h' (default 24h)" },
        },
      },
      response: {
        200: { type: 'object', additionalProperties: true },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, async (request, reply) => {
    const windowMs = parseWindowMs((request.query as { window?: string }).window)
    const summary = await auditEventService.summaryCached(windowMs)
    return reply.send(summary)
  })

  fastify.get('/export', {
    schema: {
      description: 'Export a filtered audit range as NDJSON (default) or CSV. The export itself is audited.',
      tags: ['audit'],
      querystring: {
        type: 'object',
        properties: {
          format:   { type: 'string', enum: ['ndjson', 'csv'], default: 'ndjson' },
          limit:    { type: 'integer', minimum: 1, maximum: 50000, default: 10000 },
          category: { type: 'string', enum: CATEGORY_ENUM },
          actor:    { type: 'string' },
          service:  { type: 'string' },
          target:   { type: 'string' },
          result:   { type: 'string', enum: RESULT_ENUM },
          verb:     { type: 'string' },
          kind:     { type: 'string', enum: KIND_ENUM },
          from:     { type: 'integer' },
          to:       { type: 'integer' },
          q:        { type: 'string' },
          risk:     { type: 'string', enum: ['high'] },
        },
      },
      response: {
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, async (request, reply) => {
    const q = request.query as EventsQuery & { format?: 'ndjson' | 'csv'; limit?: number }
    const format = q.format ?? 'ndjson'
    const limit = Math.min(q.limit ?? 10000, 50000)
    const events = await auditEventService.query({ ...q, limit })

    // The export is an exfil path — audit it (actor always resolvable here).
    const a = auditActor(request)
    await auditEventService.emit({
      category: 'system',
      kind: 'change',
      verb: 'export',
      target: 'audit:export',
      result: 'applied',
      actor: { email: a.email ?? null, name: a.name, ip: a.ip, ua: a.ua, sessionId: a.sessionId },
      requestId: a.requestId,
      details: { format, count: events.length, filters: { category: q.category, actor: q.actor, service: q.service, target: q.target, result: q.result, verb: q.verb, kind: q.kind, risk: q.risk } },
    })

    const stamp = new Date().toISOString().slice(0, 10)
    if (format === 'csv') {
      reply.header('Content-Type', 'text/csv; charset=utf-8')
      reply.header('Content-Disposition', `attachment; filename="audit-${stamp}.csv"`)
      return reply.send(toCsv(events))
    }
    reply.header('Content-Type', 'application/x-ndjson; charset=utf-8')
    reply.header('Content-Disposition', `attachment; filename="audit-${stamp}.ndjson"`)
    return reply.send(events.map((e) => JSON.stringify(e)).join('\n'))
  })
}

const CSV_COLS: Array<keyof FrontendAuditEvent> = [
  'ts', 'category', 'kind', 'verb', 'target', 'result', 'severity', 'who', 'ip', 'service', 'reason', 'requestId',
]

function toCsv(events: FrontendAuditEvent[]): string {
  const esc = (v: unknown) => {
    const s = v == null ? '' : String(v)
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const header = CSV_COLS.join(',')
  const rows = events.map((e) => CSV_COLS.map((c) => esc(e[c])).join(','))
  return [header, ...rows].join('\n')
}
