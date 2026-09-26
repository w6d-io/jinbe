import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { z } from 'zod'
import { recordRoute } from '../../policy/declared-routes.js'
import { isPublicRoute } from '../../middleware/require-auth.js'
import { LokiUnavailableError } from './loki.js'
import { zodMessage } from './params.js'
import type { AuditScope } from './scope.js'

/** Shared plumbing of the /api/audit and /api/admin/observability plugins. */

/** 10 requests per second per user (§4.4), when the rate-limit plugin is registered. */
export const perUserRate = {
  rateLimit: { max: 10, timeWindow: 1000, keyGenerator: (r: FastifyRequest) => r.userContext?.id ?? r.ip },
}

/** Records every route of the plugin with its per-route guards, so the table sees them standalone too. */
export function recordPluginRoutes(fastify: FastifyInstance): void {
  fastify.addHook('onRoute', (route) => recordRoute(route.method, route.url, [route.preHandler], isPublicRoute))
}

export function parse<T extends z.ZodTypeAny>(schema: T, value: unknown, reply: FastifyReply): z.infer<T> | null {
  const parsed = schema.safeParse(value ?? {})
  if (parsed.success) return parsed.data
  reply.status(400).send({ error: 'invalid_request', message: zodMessage(parsed.error) })
  return null
}

/** Loki unreachable is an outage, never an empty answer (CONTROL AU-11). */
export async function orUnavailable(reply: FastifyReply, fn: () => Promise<unknown>): Promise<unknown> {
  try {
    return await fn()
  } catch (err) {
    if (err instanceof LokiUnavailableError) {
      reply.log.warn({ status: err.status }, '[audit] the log store did not answer')
      return reply.status(503).send({ error: 'audit_store_unavailable' })
    }
    throw err
  }
}

export const scopeOf = (request: FastifyRequest): AuditScope => request.auditScope as AuditScope

export const outOfScope = (reply: FastifyReply) =>
  reply.status(403).send({ error: 'org_out_of_scope', message: 'You can only see audit events for organisations you administer.' })
