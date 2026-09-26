import type { FastifyReply, FastifyRequest } from 'fastify'
import { ZodError, type z, type ZodTypeAny } from 'zod'
import { nameParamsSchema } from './schemas.js'
import type { Actor } from './audit.js'

/** Request plumbing shared by every Sites route file: actor, zod parsing, one error shape. */

export function actorOf(request: FastifyRequest): Actor {
  return {
    id: request.userContext?.id ?? null,
    email: request.userContext?.email ?? null,
    ip: request.ip,
    ua: (request.headers['user-agent'] as string | undefined)?.slice(0, 200) ?? null,
    sessionId: request.userContext?.sessionId ?? null,
    requestId: (request.headers['x-request-id'] as string | undefined) ?? null,
  }
}

export const parse = <S extends ZodTypeAny>(schema: S, value: unknown): z.output<S> => schema.parse(value)
export const nameOf = (request: FastifyRequest) => parse(nameParamsSchema, request.params).name

/** One error shape for the whole module: `{error: <code>, message, checks?, issues?}`. */
export function fail(reply: FastifyReply, request: FastifyRequest, err: unknown) {
  if (err instanceof ZodError) {
    return reply.status(400).send({ error: 'invalid_request', message: 'The request is not valid', issues: err.issues })
  }
  const e = err as { statusCode?: number; code?: string; message?: string; checks?: unknown; ties?: unknown }
  const status = typeof e.statusCode === 'number' && e.statusCode >= 400 && e.statusCode < 600 ? e.statusCode : 500
  if (status >= 500 && status !== 503) request.log.error({ err }, '[sites] request failed')
  return reply.status(status).send({
    error: e.code ?? (status === 409 ? 'conflict' : status === 500 ? 'internal_error' : 'error'),
    message: status === 500 ? 'Internal error' : e.message,
    ...(e.checks ? { checks: e.checks } : {}),
    ...(e.ties ? { ties: e.ties } : {}),
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
