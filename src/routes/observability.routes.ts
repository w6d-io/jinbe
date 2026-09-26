import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { env } from '../config/env.js'
import { requireAdmin } from '../middleware/require-admin.js'
import { guardAll } from '../policy/declared-routes.js'
import { isPublicRoute } from '../middleware/require-auth.js'
import { opsLogsQuery } from '../audit/query/logql.js'
import { lokiClient, msToNs } from '../audit/query/loki.js'
import { orUnavailable, parse } from '../audit/query/http.js'
import { scrubEmails } from '../audit/v1/pseudonym.js'

/**
 * /api/admin/observability/* (OBS-4.1, obs-flow.md §5): narrow, fixed lookups for in-app panels.
 * Exploration belongs in Grafana; these answer "the logs / trace of THIS request".
 *
 *   - logs:  operational logs of this environment's namespace only (Loki is single tenant, so the
 *            pinned namespace is the boundary), never the audit stream, ≤24 h, ≤1000 lines,
 *            re-redacted before they leave.
 *   - trace: a span summary from Tempo — names, durations, status; no attributes (headers live there).
 *   - links: Grafana explore URLs built from ids only. No email ever goes into a URL.
 */

const HOUR = 3_600_000
const HEX32 = /^[0-9a-f]{32}$/
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/
const SERVICES = ['jinbe', 'oathkeeper', 'kratos', 'opa-authz-proxy', 'opal-*'] as const

const logsQuery = z.object({
  request_id: z.string().regex(REQUEST_ID).optional(),
  trace_id: z.string().regex(HEX32).optional(),
  subject: z.string().uuid().optional(),
  service: z.enum(SERVICES).optional(),
  log_type: z.enum(['app', 'request']).optional(),
  since: z.string().datetime({ offset: true }).optional(),
  until: z.string().datetime({ offset: true }).optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(200),
}).strict()

const linksQuery = z.object({
  request_id: z.string().regex(REQUEST_ID).optional(),
  trace_id: z.string().regex(HEX32).optional(),
}).strict()

/** Tokens and addresses a line may still carry, whatever the upstream redaction missed. */
const TOKENS = /\b(ory_(st|at|ht|rt|ac)_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|Bearer\s+[A-Za-z0-9._~+/=-]+)/g
export const redactLine = (line: string): string => scrubEmails(line.replace(TOKENS, '[redacted]'))

type OtlpAttr = { key: string; value?: { stringValue?: string } }
type OtlpSpan = { name?: string; spanId?: string; startTimeUnixNano?: string; endTimeUnixNano?: string; status?: { code?: number | string } }
type OtlpBatch = { resource?: { attributes?: OtlpAttr[] }; scopeSpans?: Array<{ spans?: OtlpSpan[] }>; instrumentationLibrarySpans?: Array<{ spans?: OtlpSpan[] }> }

function spansOf(body: { batches?: OtlpBatch[]; resourceSpans?: OtlpBatch[] }) {
  const out: Array<{ service: string; name: string; spanId: string; durationMs: number; status: 'ok' | 'error' | 'unset' }> = []
  for (const batch of body.batches ?? body.resourceSpans ?? []) {
    const service = batch.resource?.attributes?.find((a) => a.key === 'service.name')?.value?.stringValue ?? 'unknown'
    for (const scope of batch.scopeSpans ?? batch.instrumentationLibrarySpans ?? []) {
      for (const s of scope.spans ?? []) {
        const code = s.status?.code
        out.push({
          service, name: s.name ?? '', spanId: s.spanId ?? '',
          durationMs: Number((BigInt(s.endTimeUnixNano ?? '0') - BigInt(s.startTimeUnixNano ?? '0')) / 1000n) / 1000,
          status: code === 2 || code === 'STATUS_CODE_ERROR' ? 'error' : code === 1 || code === 'STATUS_CODE_OK' ? 'ok' : 'unset',
        })
      }
    }
  }
  return out
}

function explore(datasource: string, query: Record<string, unknown>): string {
  const left = { datasource, queries: [{ refId: 'A', datasource: { uid: datasource }, ...query }], range: { from: 'now-7d', to: 'now' } }
  return `${env.GRAFANA_URL!.replace(/\/$/, '')}/explore?schemaVersion=1&orgId=1&panes=${encodeURIComponent(JSON.stringify({ a: left }))}`
}

export async function observabilityRoutes(fastify: FastifyInstance) {
  guardAll(fastify, requireAdmin, isPublicRoute)

  fastify.get('/logs', { config: { rateLimit: { max: 10, timeWindow: 1000 } } }, async (request, reply) => {
    const q = parse(logsQuery, request.query, reply)
    if (!q) return
    const namespace = env.LOKI_NAMESPACE ?? env.SERVICE_DEFAULT_NAMESPACE
    const until = q.until ? Math.min(Date.parse(q.until), Date.now()) : Date.now()
    const since = q.since ? Date.parse(q.since) : until - HOUR
    if (!(since < until)) return reply.status(400).send({ error: 'invalid_range', message: '`since` must be before `until`.' })
    if (until - since > 24 * HOUR) return reply.status(400).send({ error: 'range_too_large', message: 'Pick 24 hours or fewer.' })
    const query = opsLogsQuery({ namespace, container: q.service, requestId: q.request_id, traceId: q.trace_id, subject: q.subject, logType: q.log_type })
    return orUnavailable(reply, async () => {
      const entries = await lokiClient().queryRange({ query, startNs: msToNs(since), endNs: msToNs(until), limit: q.limit, direction: 'backward' })
      return reply.send({
        lines: entries.map((e) => ({ ts: new Date(Number(BigInt(e.ts) / 1_000_000n)).toISOString(), container: e.labels.container ?? null, line: redactLine(e.line) })),
        namespace, range: { since: new Date(since).toISOString(), until: new Date(until).toISOString() },
        truncated: entries.length >= q.limit, source: 'loki',
      })
    })
  })

  fastify.get('/trace/:traceId', async (request, reply) => {
    if (!env.TEMPO_URL) return reply.status(404).send({ error: 'not_configured', message: 'Tracing is not configured here.' })
    const traceId = (request.params as { traceId: string }).traceId
    if (!HEX32.test(traceId)) return reply.status(400).send({ error: 'invalid_request', message: 'traceId: 32 lowercase hex characters' })
    let res: Response
    try {
      res = await fetch(`${env.TEMPO_URL.replace(/\/$/, '')}/api/traces/${traceId}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10_000) })
    } catch {
      return reply.status(503).send({ error: 'trace_store_unavailable' })
    }
    // Tempo keeps 7 days: an unknown id is usually an expired one.
    if (res.status === 404) return reply.status(404).send({ error: 'not_found', message: 'Trace not found (kept 7 days).' })
    if (!res.ok) return reply.status(503).send({ error: 'trace_store_unavailable' })
    return reply.send({ traceId, spans: spansOf(await res.json() as Parameters<typeof spansOf>[0]) })
  })

  fastify.get('/links', async (request, reply) => {
    const q = parse(linksQuery, request.query, reply)
    if (!q) return
    if (!env.GRAFANA_URL) return reply.status(404).send({ error: 'not_configured', message: 'Grafana is not configured here.' })
    const namespace = env.LOKI_NAMESPACE ?? env.SERVICE_DEFAULT_NAMESPACE
    const needle = q.request_id ?? q.trace_id
    return reply.send({
      links: {
        logs: needle ? explore(env.GRAFANA_LOKI_DATASOURCE_UID, { expr: opsLogsQuery({ namespace, requestId: q.request_id, traceId: q.request_id ? undefined : q.trace_id }) }) : null,
        trace: q.trace_id ? explore(env.GRAFANA_TEMPO_DATASOURCE_UID, { queryType: 'traceql', query: q.trace_id }) : null,
      },
    })
  })
}
