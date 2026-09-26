import type { FastifyInstance } from 'fastify'
import { env } from '../../config/env.js'
import { getRedisClient } from '../../services/redis-client.service.js'
import { requireAuditScope, orgsFor } from './scope.js'
import { auditQuery } from './logql.js'
import { lokiClient, msToNs, LokiUnavailableError } from './loki.js'
import { filtersSchema, toFilter } from './params.js'
import { matches, parseLine } from './reader.js'
import { outOfScope, parse, scopeOf } from './http.js'

/**
 * GET /api/audit/tail — live events as Server-Sent Events, with the same scope as /events (§4.4).
 *
 * Polls Loki's query_range every couple of seconds from the last timestamp seen rather than holding
 * a websocket to /tail: the same builder, the same scoping, the same JS re-check, nothing new to
 * trust. One stream per user (a Redis lock, across replicas), stopped after 15 minutes.
 */

export const tailConfig = { maxMs: 15 * 60_000, pollMs: 2000 }

export async function auditTailRoute(fastify: FastifyInstance) {
  fastify.get('/tail', { preHandler: requireAuditScope('audit:read') }, async (request, reply) => {
    const q = parse(filtersSchema, request.query, reply)
    if (!q) return
    const orgs = orgsFor(scopeOf(request), q.org)
    if (orgs === null) return outOfScope(reply)
    const filter = toFilter(q, orgs)
    const query = auditQuery(filter, env.LOKI_NAMESPACE)
    const subject = request.userContext!.id
    const lock = `auth:audit:tail:${subject}`

    // Fail before the stream opens: a store that is down is a 503, not an empty live view.
    let since = BigInt(msToNs(Date.now()))
    try {
      await lokiClient().queryRange({ query, startNs: (since - 1_000_000_000n).toString(), endNs: since.toString(), limit: 1, direction: 'backward' })
    } catch (err) {
      if (err instanceof LokiUnavailableError) return reply.status(503).send({ error: 'audit_store_unavailable' })
      throw err
    }
    if ((await getRedisClient().set(lock, '1', 'PX', tailConfig.maxMs, 'NX')) !== 'OK') {
      return reply.status(429).send({ error: 'tail_in_progress', message: 'One live view at a time.' })
    }

    reply.hijack()
    const raw = reply.raw
    raw.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' })
    const started = Date.now()
    let open = true
    request.raw.on('close', () => { open = false })

    const send = (event: string, data: unknown) => raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
    try {
      while (open && Date.now() - started < tailConfig.maxMs) {
        const now = BigInt(msToNs(Date.now()))
        const entries = await lokiClient().queryRange({ query, startNs: (since + 1n).toString(), endNs: (now + 1n).toString(), limit: 500, direction: 'forward' })
        for (const entry of entries) {
          const e = parseLine(entry.line)
          if (e && matches(e, filter, entry.line)) send('audit', e)
          if (BigInt(entry.ts) > since) since = BigInt(entry.ts)
        }
        if (!open) break
        await new Promise((r) => setTimeout(r, tailConfig.pollMs))
      }
      if (open) send('end', { reason: 'max_duration', maxMinutes: Math.round(tailConfig.maxMs / 60_000) })
    } catch (err) {
      send('error', { error: err instanceof LokiUnavailableError ? 'audit_store_unavailable' : 'tail_failed' })
    } finally {
      await getRedisClient().del(lock).catch(() => 0)
      raw.end()
    }
  })
}
