import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { requireAuditScope } from '../query/scope.js'
import { checkRange } from '../query/params.js'
import { orUnavailable, parse, perUserRate, scopeOf } from '../query/http.js'
import { gatewayAccess } from './decisions.js'

/**
 * GET /api/audit/access — what the gateway allowed and refused over a window, by person and host
 * (audit/gateway/decisions.ts). Platform readers only: the gateway's lines name no organisation, so
 * there is nothing to cut an org admin's view to.
 */

const time = z.string().datetime({ offset: true })
export const accessQuerySchema = z.object({
  from: time,
  to: time,
  subject: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/).optional(),
  host: z.string().regex(/^[a-z0-9.-]{1,253}(:\d{1,5})?$/).optional(),
}).strict()

export async function gatewayAccessRoute(fastify: FastifyInstance) {
  fastify.get('/access', { preHandler: requireAuditScope('audit:read'), config: perUserRate }, async (request, reply) => {
    const q = parse(accessQuerySchema, request.query, reply)
    if (!q) return
    const range = checkRange(q.from, q.to)
    if (!range.ok) return reply.status(400).send({ error: range.error, message: range.message })
    const scope = scopeOf(request)
    if (!scope.platform) {
      return reply.status(403).send({ error: 'platform_only', message: 'Gateway access covers every site and names no organisation; only platform readers can see it.' })
    }
    return orUnavailable(reply, async () => {
      const started = Date.now()
      const result = await gatewayAccess({ subject: q.subject, host: q.host }, range.fromMs, range.toMs)
      return reply.send({
        ...result, scope, range: { from: new Date(range.fromMs).toISOString(), to: new Date(range.toMs).toISOString() },
        source: 'gateway-log', queryMs: Date.now() - started,
      })
    })
  })
}
