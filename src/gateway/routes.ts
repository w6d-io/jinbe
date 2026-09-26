import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { ZodError, type ZodSchema } from 'zod'
import { zodToJsonSchema } from 'zod-to-json-schema'
import { requireRecentMfa, requireSitesApply, requireSuperAdmin } from '../middleware/require-admin.js'
import type { Actor } from './audit.js'
import { proposalBodySchema, rollbackBodySchema } from './schemas.js'
import * as gateway from './service.js'

/**
 * /api/admin/gateway — the Oathkeeper handlers every site builds on (GW-2).
 *
 * Registered inside the admin plugin, so reading needs `admin:read`. A preview needs `admin:write`;
 * writing the Gateway CR restarts every gateway pod, so it needs `sites:apply` (super_admin) and a
 * second factor proven in the last 15 minutes.
 */

const TAGS = ['gateway']
const write = { preHandler: [requireSuperAdmin] }
const apply = { preHandler: [requireSitesApply, requireRecentMfa] }
const doc = (description: string, body?: ZodSchema) => ({
  schema: { description, tags: TAGS, ...(body ? { body: zodToJsonSchema(body, { target: 'openApi3' }) } : {}) },
})

function actorOf(request: FastifyRequest): Actor {
  return {
    id: request.userContext?.id ?? null,
    email: request.userContext?.email ?? null,
    ip: request.ip,
    ua: (request.headers['user-agent'] as string | undefined)?.slice(0, 200) ?? null,
    sessionId: request.userContext?.sessionId ?? null,
    requestId: (request.headers['x-request-id'] as string | undefined) ?? null,
  }
}

/** One error shape: `{error: <code>, message, issues?}`. */
function fail(reply: FastifyReply, request: FastifyRequest, err: unknown) {
  if (err instanceof ZodError) {
    return reply.status(400).send({ error: 'invalid_request', message: 'The request is not valid', issues: err.issues })
  }
  const e = err as { statusCode?: number; code?: string; message?: string; issues?: unknown }
  const status = typeof e.statusCode === 'number' && e.statusCode >= 400 && e.statusCode < 600 ? e.statusCode : 500
  if (status >= 500 && status !== 503) request.log.error({ err }, '[gateway] request failed')
  return reply.status(status).send({
    error: e.code ?? (status === 500 ? 'internal_error' : 'error'),
    message: status === 500 ? 'Internal error' : e.message,
    ...(e.issues ? { issues: e.issues } : {}),
  })
}

type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
const handle = (fn: Handler): Handler => async (request, reply) => {
  try {
    return await fn(request, reply)
  } catch (err) {
    return fail(reply, request, err)
  }
}

let pollMs = 2000
let maxStreamMs = 10 * 60_000
/** Test seam. */
export function setRolloutPolling(poll: number, max: number): void {
  pollMs = poll
  maxStreamMs = max
}

/**
 * SSE: one `rollout` event whenever the CR status changes, closed once the rollout has settled or
 * after ten minutes. A read error ends the stream with an `error` event; the client reconnects.
 */
async function streamRollout(request: FastifyRequest, reply: FastifyReply) {
  reply.hijack()
  const raw = reply.raw
  raw.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' })
  let closed = false
  request.raw.on('close', () => { closed = true })
  const started = Date.now()
  let last = ''
  while (!closed && Date.now() - started < maxStreamMs) {
    try {
      const state = await gateway.rollout()
      const json = JSON.stringify(state)
      if (json !== last) {
        raw.write(`event: rollout\ndata: ${json}\n\n`)
        last = json
      } else {
        raw.write(': keep-alive\n\n')
      }
      if (state.settled) break
    } catch (err) {
      raw.write(`event: error\ndata: ${JSON.stringify({ message: (err as Error).message })}\n\n`)
      break
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs))
  }
  raw.end()
}

export async function gatewayRoutes(fastify: FastifyInstance) {
  // Documentation-only body schemas: zod is the validator.
  fastify.setValidatorCompiler(() => (data) => ({ value: data }))

  fastify.get('', doc('Every Oathkeeper handler: enabled, global config (secrets masked), defaults, the sites using it, form fields; plus rollout status. managed=false when no Gateway resource exists yet (live config, read-only)'),
    handle(async (_request, reply) => {
      const out = await gateway.view()
      reply.header('etag', `"${out.etag}"`)
      return out
    }))

  fastify.post('/preview', { ...write, ...doc('Validate a proposed gateway configuration: handler schemas, in-use handlers, fallback, risk flags. Writes nothing', proposalBodySchema) },
    handle(async (request) => gateway.preview(proposalBodySchema.parse(request.body))))

  fastify.put('', { ...apply, ...doc('Write the Gateway resource (If-Match: the etag you edited). The site-operator rolls the gateway pods', proposalBodySchema) },
    handle(async (request, reply) => {
      const out = await gateway.put(proposalBodySchema.parse(request.body), request.headers['if-match'] as string | undefined, actorOf(request))
      reply.header('etag', `"${out.etag}"`)
      return out
    }))

  fastify.get('/rollout', doc('Rollout progress of the last gateway change (from the Gateway status)'), handle(async () => gateway.rollout()))

  fastify.get('/rollout/events', doc('Rollout progress as Server-Sent Events, until it settles'), streamRollout)

  fastify.post('/rollback', { ...apply, ...doc('Restore the configuration before the last change, re-checked against the sites using each handler', rollbackBodySchema) },
    handle(async (request, reply) => {
      const body = rollbackBodySchema.parse(request.body ?? {})
      const out = await gateway.rollback(request.headers['if-match'] as string | undefined, actorOf(request), body.note)
      reply.header('etag', `"${out.etag}"`)
      return out
    }))
}
