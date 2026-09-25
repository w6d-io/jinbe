import { FastifyRequest, FastifyReply } from 'fastify'
import { httpRequestsCounter, httpDurationHistogram } from '../services/audit-event.service.js'

/**
 * Request logger — runs after the response is sent (onResponse hook).
 *
 * One `log_type:"request"` line per request, and the HTTP RED counters. This is an operations log,
 * not the audit trail: business events are emitted by the code that performs them (audit/v1), and
 * an admin GET is no longer recorded as an "access.allow" audit row.
 *
 * The line names the caller by subject id (the Kratos identity), never by email or name, and names
 * the route by its pattern, never by the raw path with ids and query string.
 */

// Probes answer every few seconds and say nothing when they succeed.
const SILENT = new Set(['/api/health'])
// Oathkeeper's rules poll (every 5 s per replica): kept, but only for someone debugging it.
const DEBUG_ONLY = new Set(['GET /api/oathkeeper/rules'])

export async function requestLogger(request: FastifyRequest, reply: FastifyReply) {
  const method = request.method
  const route = request.routeOptions?.url || request.url.split('?')[0]
  const status = reply.statusCode
  const elapsed = reply.elapsedTime

  const statusClass = status >= 500 ? '5xx' : status >= 400 ? '4xx' : status >= 300 ? '3xx' : '2xx'
  httpRequestsCounter.labels(method, route, statusClass).inc()
  httpDurationHistogram.labels(method, route).observe(elapsed / 1000)

  if (SILENT.has(route) && status < 500) return

  const uc = request.userContext
  const entry = {
    log_type: 'request',
    method,
    route,
    status,
    latency_ms: Math.round(elapsed * 100) / 100,
    subject: uc?.id && uc.id !== 'unknown' ? uc.id : undefined,
  }
  if (status >= 500) request.log.error(entry, 'request')
  else if (status >= 400) request.log.warn(entry, 'request')
  else if (DEBUG_ONLY.has(`${method} ${route}`)) request.log.debug(entry, 'request')
  else request.log.info(entry, 'request')
}
