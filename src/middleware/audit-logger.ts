import { FastifyRequest, FastifyReply } from 'fastify'
import { auditEventService, httpRequestsCounter, httpDurationHistogram } from '../services/audit-event.service.js'

/**
 * Audit logger middleware — runs after response is sent (onResponse hook).
 *
 * - Logs structured JSON to Pino (all requests)
 * - Emits rich audit events to Redis for:
 *   - access.allow  → successful requests to /admin/* routes  (status < 400)
 *   - access.deny   → 401/403 (also emitted by require-auth/require-admin)
 *   - request.error → 4xx/5xx not covered by middleware
 * - Increments Prometheus counters for /metrics scraping
 */
export async function auditLogger(request: FastifyRequest, reply: FastifyReply) {
  const responseTime = reply.getResponseTime()
  const uc = request.userContext || { email: 'anonymous', id: 'unknown', name: 'anonymous' }

  const method      = request.method
  const routePath   = request.routeOptions?.url || request.url.split('?')[0]  // pattern for Prometheus
  const actualPath  = request.url.split('?')[0]                               // real path for audit log
  const path        = routePath
  const statusCode = reply.statusCode
  const rtMs       = Math.round(responseTime * 100) / 100
  const ua         = (request.headers['user-agent'] || '') as string
  const ip         = request.ip

  // ── Pino structured log ────────────────────────────────────────────────────
  const entry = {
    timestamp: new Date().toISOString(),
    service: 'jinbe',
    method, path, statusCode,
    responseTimeMs: rtMs,
    userEmail: uc.email, userId: uc.id, userName: uc.name,
    requestId: request.id, ip, userAgent: ua,
  }
  if (statusCode >= 500)      request.log.error(entry, 'audit')
  else if (statusCode >= 400) request.log.warn(entry,  'audit')
  else                        request.log.info(entry,  'audit')

  // ── Prometheus ─────────────────────────────────────────────────────────────
  const statusClass = statusCode >= 500 ? '5xx' : statusCode >= 400 ? '4xx' : statusCode >= 300 ? '3xx' : '2xx'
  httpRequestsCounter.labels(method, path, statusClass).inc()
  httpDurationHistogram.labels(method, path).observe(responseTime / 1000)

  // ── Redis audit events ─────────────────────────────────────────────────────
  // Only emit for /admin/* — avoids flooding with health/oathkeeper/opal calls
  if (!path.startsWith('/api/admin') && !path.startsWith('/api/auth')) return

  const actor = {
    email:     uc.email === 'anonymous' ? null : uc.email,
    name:      uc.name  === 'anonymous' ? null : uc.name,
    ip,
    ua:        ua || null,
    sessionId: request.validatedSession?.sessionId || null,
  }

  if (statusCode < 400) {
    auditEventService.emit({
      category: 'access',
      verb:     'allow',
      target:   `${method} ${actualPath}`,
      result:   'ok',
      actor,
      method, path: actualPath, statusCode, responseTimeMs: rtMs,
    }).catch(() => {})
  } else if (statusCode >= 500) {
    auditEventService.emit({
      category: 'system',
      verb:     'error',
      target:   `${method} ${actualPath}`,
      result:   'error',
      actor,
      method, path: actualPath, statusCode, responseTimeMs: rtMs,
      reason:   `HTTP ${statusCode}`,
    }).catch(() => {})
  }
  // 401/403 already handled by require-auth / require-admin with richer context
}
