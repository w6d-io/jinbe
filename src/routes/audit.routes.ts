import type { FastifyInstance } from 'fastify'
import { auditEventService } from '../services/audit-event.service.js'
import { requireAdmin } from '../middleware/require-admin.js'
import { unauthorizedResponseSchema, forbiddenResponseSchema } from '../schemas/response-schemas.js'
import type { AuditCategory } from '../services/audit-event.service.js'

/**
 * Audit Events endpoint — admin only
 *
 * GET /audit/events  → paginated rich audit log (newest first)
 * GET /audit/metrics → Prometheus text format (no auth — scraper access)
 */
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
  fastify.addHook('preHandler', requireAdmin)

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
          category: { type: 'string', enum: ['auth','access','rbac','policy','service','route','secret','system'] },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            events: { type: 'array', items: { type: 'object', additionalProperties: true } },
            total:  { type: 'number' },
          },
        },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
      },
    },
  }, async (request, reply) => {
    const { limit, since, until, category } = request.query as {
      limit?:    number
      since?:    string
      until?:    string
      category?: AuditCategory
    }

    const [events, total] = await Promise.all([
      auditEventService.query({ limit, since, until, category }),
      auditEventService.count(),
    ])

    return reply.send({ events, total })
  })
}
