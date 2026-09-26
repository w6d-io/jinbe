import type { FastifyInstance } from 'fastify'
import { organisationsForSubject } from '../services/organisation-store.js'
import { requireAuditScope, orgsFor } from '../audit/query/scope.js'
import { readPage, facets, summary, eventById } from '../audit/query/reader.js'
import {
  checkRange, decodeCursor, toFilter, windowMs, DAY_MS, MAX_SPAN_MS,
  eventsQuerySchema, facetsQuerySchema, summaryQuerySchema, timelineQuerySchema, myLoginsQuerySchema,
  eventByIdQuerySchema, eventIdSchema, userIdSchema, type Cursor,
} from '../audit/query/params.js'
import { orUnavailable, outOfScope, parse, perUserRate, recordPluginRoutes, scopeOf } from '../audit/query/http.js'
import { auditWorkflowRoutes } from './audit-workflow.routes.js'
import { auditTailRoute } from '../audit/query/tail.js'

/**
 * /api/audit/* — the audit trail read from Loki (audit-tab.md §4.4, AUD-9).
 *
 * jinbe builds every query (audit/query/logql.ts); the client sends allow-listed facets only. The
 * caller's scope is resolved by the guard and injected server-side: platform readers see everything,
 * an org admin the orgs they administer (asking for another is 403). Every read is bounded — 30 days
 * per page, 400 days back, ≤200 rows, ≤5000 Loki entries — and says `scope` and `truncated`, so the
 * UI never implies completeness. Loki unreachable → 503 `audit_store_unavailable`, never `[]`.
 *
 * Replaces /api/admin/audit/* (Redis) once AUDIT_READ switches; both live side by side until AUD-14.
 */
export async function auditApiRoutes(fastify: FastifyInstance) {
  recordPluginRoutes(fastify)
  const read = requireAuditScope('audit:read')
  const opts = { preHandler: read, config: perUserRate }

  fastify.get('/events', opts, async (request, reply) => {
    const q = parse(eventsQuerySchema, request.query, reply)
    if (!q) return
    const range = checkRange(q.from, q.to)
    if (!range.ok) return reply.status(400).send({ error: range.error, message: range.message })
    const scope = scopeOf(request)
    const orgs = orgsFor(scope, q.org)
    if (orgs === null) return outOfScope(reply)
    let cursor: Cursor | null = null
    if (q.cursor) {
      cursor = decodeCursor(q.cursor)
      if (!cursor) return reply.status(400).send({ error: 'invalid_request', message: 'cursor: not a cursor this API issued' })
    }
    return orUnavailable(reply, async () => {
      const started = Date.now()
      const page = await readPage(toFilter(q, orgs), range.fromMs, range.toMs, q.limit, cursor)
      return reply.send({
        events: page.events, nextCursor: page.nextCursor, scope,
        range: { from: new Date(range.fromMs).toISOString(), to: new Date(range.toMs).toISOString() },
        truncated: page.truncated, source: 'loki', queryMs: Date.now() - started,
      })
    })
  })

  fastify.get('/facets', opts, async (request, reply) => {
    const q = parse(facetsQuerySchema, request.query, reply)
    if (!q) return
    const range = checkRange(q.from, q.to)
    if (!range.ok) return reply.status(400).send({ error: range.error, message: range.message })
    const scope = scopeOf(request)
    const orgs = orgsFor(scope, q.org)
    if (orgs === null) return outOfScope(reply)
    return orUnavailable(reply, async () => {
      const started = Date.now()
      const result = await facets(toFilter(q, orgs), range.fromMs, range.toMs)
      return reply.send({
        ...result, scope, range: { from: new Date(range.fromMs).toISOString(), to: new Date(range.toMs).toISOString() },
        source: 'loki', queryMs: Date.now() - started,
      })
    })
  })

  fastify.get('/summary', opts, async (request, reply) => {
    const q = parse(summaryQuerySchema, request.query, reply)
    if (!q) return
    const wMs = windowMs(q.window)
    if (wMs <= 0 || wMs > MAX_SPAN_MS) return reply.status(400).send({ error: 'range_too_large', message: 'Pick 30 days or fewer.' })
    const scope = scopeOf(request)
    const orgs = orgsFor(scope, q.org)
    if (orgs === null) return outOfScope(reply)
    return orUnavailable(reply, async () => {
      const started = Date.now()
      const result = await summary({ orgs }, q.window, wMs)
      return reply.send({ ...result, scope, truncated: false, source: 'loki', queryMs: Date.now() - started })
    })
  })

  fastify.get('/events/:eventId', opts, async (request, reply) => {
    const id = eventIdSchema.safeParse((request.params as { eventId: string }).eventId)
    if (!id.success) return reply.status(400).send({ error: 'invalid_request', message: 'eventId: not an event id' })
    const q = parse(eventByIdQuerySchema, request.query, reply)
    if (!q) return
    const orgs = orgsFor(scopeOf(request))
    return orUnavailable(reply, async () => {
      const found = await eventById({ orgs: orgs ?? undefined }, id.data, q.ts ? Date.parse(q.ts) : null)
      // Out of scope and absent read the same: whether it exists is itself information.
      if (!found) return reply.status(404).send({ error: 'not_found', message: 'No such event in your scope.' })
      return reply.send({ ...found, scope: scopeOf(request), source: 'loki' })
    })
  })

  fastify.get('/users/:id/timeline', opts, async (request, reply) => {
    const id = userIdSchema.safeParse((request.params as { id: string }).id)
    if (!id.success) return reply.status(400).send({ error: 'invalid_request', message: 'id: not an identity id' })
    const q = parse(timelineQuerySchema, request.query, reply)
    if (!q) return
    const range = checkRange(q.from, q.to)
    if (!range.ok) return reply.status(400).send({ error: range.error, message: range.message })
    const scope = scopeOf(request)
    let orgs: string[] | undefined
    if (!scope.platform) {
      // An org admin reads the timeline of a member of their org — and only its events in their org.
      let theirs: string[]
      try {
        theirs = await organisationsForSubject(id.data)
      } catch {
        return reply.status(503).send({ error: 'Service Unavailable', message: 'Unable to verify organisation membership.' })
      }
      orgs = scope.orgs.filter((o) => theirs.includes(o))
      if (orgs.length === 0) return outOfScope(reply)
    }
    const cursor = q.cursor ? decodeCursor(q.cursor) : null
    if (q.cursor && !cursor) return reply.status(400).send({ error: 'invalid_request', message: 'cursor: not a cursor this API issued' })
    return orUnavailable(reply, async () => {
      const page = await readPage({ orgs, subject: id.data }, range.fromMs, range.toMs, q.limit, cursor)
      return reply.send({ ...page, scope, range: { from: new Date(range.fromMs).toISOString(), to: new Date(range.toMs).toISOString() }, source: 'loki' })
    })
  })

  // Any authenticated user, about themselves (GDPR access right): no scope guard, no org filter.
  fastify.get('/me/logins', { config: perUserRate }, async (request, reply) => {
    const subject = request.userContext?.id
    if (!subject || subject === 'unknown') return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    const q = parse(myLoginsQuerySchema, request.query, reply)
    if (!q) return
    const to = q.to ?? new Date().toISOString()
    const range = checkRange(q.from ?? new Date(Date.parse(to) - 30 * DAY_MS).toISOString(), to)
    if (!range.ok) return reply.status(400).send({ error: range.error, message: range.message })
    const cursor = q.cursor ? decodeCursor(q.cursor) : null
    if (q.cursor && !cursor) return reply.status(400).send({ error: 'invalid_request', message: 'cursor: not a cursor this API issued' })
    return orUnavailable(reply, async () => {
      const page = await readPage({ subject, events: ['auth.*'] }, range.fromMs, range.toMs, q.limit, cursor)
      return reply.send({ ...page, range: { from: new Date(range.fromMs).toISOString(), to: new Date(range.toMs).toISOString() }, source: 'loki' })
    })
  })

  await fastify.register(auditTailRoute)
  await fastify.register(auditWorkflowRoutes)
}
