import type { FastifyInstance } from 'fastify'
import { requireAuditScope, orgsFor } from '../audit/query/scope.js'
import { checkRange, exportBodySchema, savedQueryBodySchema, toFilter, MAX_EXPORT_SPAN_MS } from '../audit/query/params.js'
import { outOfScope, parse, perUserRate, scopeOf } from '../audit/query/http.js'
import { enqueueExport, drainExports, exportsConfig, getJob, getJobData } from '../audit/query/exports.js'
import { createSaved, deleteSaved, listSaved } from '../audit/query/saved-queries.js'
import { auditActor } from '../utils/audit-actor.js'

/**
 * /api/audit/exports and /api/audit/saved-queries (§4.4). Registered by auditApiRoutes, under its
 * prefix and its route recorder.
 */
export async function auditWorkflowRoutes(fastify: FastifyInstance) {
  const exporter = { preHandler: requireAuditScope('audit:export'), config: perUserRate }
  const reader = { preHandler: requireAuditScope('audit:read'), config: perUserRate }

  fastify.post('/exports', exporter, async (request, reply) => {
    const body = parse(exportBodySchema, request.body, reply)
    if (!body) return
    // Longer than a page (up to the 400-day retention): the job walks it in 30-day windows.
    const range = checkRange(body.from, body.to, MAX_EXPORT_SPAN_MS)
    if (!range.ok) return reply.status(400).send({ error: range.error, message: range.message })
    const orgs = orgsFor(scopeOf(request), body.filters.org)
    if (orgs === null) return outOfScope(reply)
    const actor = auditActor(request)
    const job = await enqueueExport({
      owner: request.userContext!.id, format: body.format, fromMs: range.fromMs, toMs: range.toMs,
      filters: body.filters, query: toFilter(body.filters, orgs),
      actor: { id: actor.id, ip: actor.ip, ua: actor.ua, sessionId: actor.sessionId, requestId: actor.requestId },
    })
    if (!job) return reply.status(429).send({ error: 'export_in_progress', message: 'One export at a time — wait for the running one to finish.' })
    if (exportsConfig.autoDrain) setImmediate(() => { drainExports().catch((err) => request.log.warn({ err }, '[audit] export drain failed')) })
    return reply.status(202).send({ id: job.id, status: job.status })
  })

  fastify.get('/exports/:id', exporter, async (request, reply) => {
    const job = await getJob((request.params as { id: string }).id)
    // Somebody else's export reads as absent.
    if (!job || job.owner !== request.userContext?.id) return reply.status(404).send({ error: 'not_found' })
    return reply.send({
      id: job.id, status: job.status, format: job.format,
      rows: job.rows ?? null, sha256: job.sha256 ?? null, truncated: job.truncated ?? false,
      url: job.status === 'done' ? `/api/audit/exports/${job.id}/download` : null,
      expiresAt: job.expiresAt ?? null, ...(job.error ? { error: job.error } : {}),
    })
  })

  fastify.get('/exports/:id/download', exporter, async (request, reply) => {
    const job = await getJob((request.params as { id: string }).id)
    if (!job || job.owner !== request.userContext?.id || job.status !== 'done') return reply.status(404).send({ error: 'not_found' })
    const data = await getJobData(job.id)
    if (data === null) return reply.status(410).send({ error: 'expired', message: 'This export has expired; run it again.' })
    const stamp = new Date(job.createdAt).toISOString().slice(0, 10)
    reply.header('Content-Type', job.format === 'csv' ? 'text/csv; charset=utf-8' : 'application/x-ndjson; charset=utf-8')
    reply.header('Content-Disposition', `attachment; filename="audit-${stamp}-${job.id.slice(0, 8)}.${job.format}"`)
    reply.header('X-Content-SHA256', job.sha256 ?? '')
    return reply.send(data)
  })

  fastify.get('/saved-queries', reader, async (request, reply) => {
    return reply.send({ queries: await listSaved(request.userContext!.id, scopeOf(request)) })
  })

  fastify.post('/saved-queries', reader, async (request, reply) => {
    const body = parse(savedQueryBodySchema, request.body, reply)
    if (!body) return
    const scope = scopeOf(request)
    if (body.shared) {
      if (!body.orgId) return reply.status(400).send({ error: 'invalid_request', message: 'orgId: a shared query belongs to one organisation' })
      if (orgsFor(scope, body.orgId) === null) return outOfScope(reply)
    }
    return reply.status(201).send(await createSaved(request.userContext!.id, body))
  })

  fastify.delete('/saved-queries/:id', reader, async (request, reply) => {
    const deleted = await deleteSaved(request.userContext!.id, (request.params as { id: string }).id)
    if (!deleted) return reply.status(404).send({ error: 'not_found' })
    return reply.status(204).send()
  })
}
