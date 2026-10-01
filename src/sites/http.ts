import type { FastifyReply, FastifyRequest } from 'fastify'
import { ZodError, type z, type ZodTypeAny } from 'zod'
import { nameParamsSchema } from './schemas.js'
import type { Actor } from './audit.js'
import { clientIp } from '../utils/client-ip.js'
import { validationFailed, zodDetails } from '../utils/validation-error.js'

/** Request plumbing shared by every Sites route file: actor, zod parsing, one error shape. */

export function actorOf(request: FastifyRequest): Actor {
  return {
    id: request.userContext?.id ?? null,
    email: request.userContext?.email ?? null,
    ip: clientIp(request),
    ua: (request.headers['user-agent'] as string | undefined)?.slice(0, 200) ?? null,
    sessionId: request.userContext?.sessionId ?? null,
    requestId: (request.headers['x-request-id'] as string | undefined) ?? null,
    // A user acting through a client (an MCP key): the trail names the client beside the user.
    ...(request.userContext?.authVia === 'delegated' && request.userContext.delegation
      ? { act: { client_id: request.userContext.delegation.clientId, via: request.userContext.delegation.via, kind: request.userContext.delegation.kind } }
      : {}),
  }
}

export const parse = <S extends ZodTypeAny>(schema: S, value: unknown): z.output<S> => schema.parse(value)
export const nameOf = (request: FastifyRequest) => parse(nameParamsSchema, request.params).name

/** One error shape for the whole module: `{error: <code>, message, checks?, findings?, details?, issues?, sites?, current?}`. */
export function fail(reply: FastifyReply, request: FastifyRequest, err: unknown) {
  if (err instanceof ZodError) {
    // `details[]` (field + message) like every other 400 of the API; `issues` is zod's own, kept.
    const { message, details } = validationFailed(zodDetails(err))
    return reply.status(400).send({ error: 'invalid_request', message: `The request is not valid: ${message}`, details, issues: err.issues })
  }
  const e = err as { statusCode?: number; code?: string; message?: string; checks?: unknown; findings?: unknown; ties?: unknown; sites?: unknown; retryAfterSec?: number; etag?: string; current?: unknown }
  const status = typeof e.statusCode === 'number' && e.statusCode >= 400 && e.statusCode < 600 ? e.statusCode : 500
  if (status >= 500 && status !== 503) request.log.error({ err }, '[sites] request failed')
  // A throttled upstream (KubeThrottled): the client may retry, and when.
  if (typeof e.retryAfterSec === 'number') reply.header('retry-after', String(e.retryAfterSec))
  // A precondition refused (412): the etag of what is there now.
  if (typeof e.etag === 'string') reply.header('etag', `"${e.etag}"`)
  return reply.status(status).send({
    error: e.code ?? (status === 409 ? 'conflict' : status === 500 ? 'internal_error' : 'error'),
    message: status === 500 ? 'Internal error' : e.message,
    ...(e.checks ? { checks: e.checks } : {}),
    ...(e.findings ? { findings: e.findings } : {}),
    ...(e.ties ? { ties: e.ties } : {}),
    ...(e.sites ? { sites: e.sites } : {}),
    ...(e.current ? { current: e.current } : {}),
  })
}

export type Handler = (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
export const handle = (fn: Handler): Handler => async (request, reply) => {
  try {
    return await fn(request, reply)
  } catch (err) {
    return fail(reply, request, err)
  }
}
