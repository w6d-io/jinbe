import { createHash } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { getRedisClient } from '../services/redis-client.service.js'

/**
 * `Idempotency-Key` on POST / PUT / PATCH: the same key sent again replays the first answer instead
 * of doing the work twice — what an MCP client needs when a call timed out and it cannot tell whether
 * the write happened (MCP §3.8).
 *
 *   - optional: a request without the header is untouched;
 *   - scoped to WHO asked and WHAT for: (subject, client, method, URL, key). One person's key never
 *     replays somebody else's answer, and the same key on another route is another request;
 *   - the same key with a different body is a mistake, never a replay: 422 idempotency_key_reused;
 *   - while the first request runs, a second one answers 409 idempotency_in_progress;
 *   - kept 24 h. A 5xx is not kept (the write may not have happened: retrying must be possible), nor
 *     is an answer that is not a plain body (a stream).
 *
 * Runs as a global preHandler, after the delegation gate and before the route's own guards: a replay
 * returns what that same principal was already answered, and does nothing new.
 */

export const IDEMPOTENCY_HEADER = 'idempotency-key'
export const IDEMPOTENCY_TTL_S = 24 * 3600
/** How long a claim may stay "in progress" when the process dies mid-request. */
const PENDING_TTL_S = 120
const KEY_FORMAT = /^[A-Za-z0-9_-]{8,64}$/
const METHODS = new Set(['POST', 'PUT', 'PATCH'])

type Stored =
  | { state: 'pending'; bodyHash: string }
  | { state: 'done'; bodyHash: string; status: number; contentType?: string; body: string }

declare module 'fastify' {
  interface FastifyRequest {
    idempotencySlot?: { redisKey: string; bodyHash: string }
  }
}

function canonical(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(canonical)
  if (Buffer.isBuffer(value)) return value.toString('base64')
  return Object.fromEntries(Object.keys(value as object).sort().map((k) => [k, canonical((value as Record<string, unknown>)[k])]))
}

export function bodyHashOf(body: unknown): string {
  return createHash('sha256').update(JSON.stringify(canonical(body ?? null))).digest('hex')
}

function slotKey(request: FastifyRequest, key: string): string {
  const uc = request.userContext
  const scope = [uc?.id ?? '', uc?.delegation?.clientId ?? '', request.method.toUpperCase(), request.url, key].join('\n')
  return `jinbe:idem:${createHash('sha256').update(scope).digest('hex')}`
}

export async function idempotencyPreHandler(request: FastifyRequest, reply: FastifyReply) {
  const raw = request.headers[IDEMPOTENCY_HEADER]
  if (raw === undefined || !METHODS.has(request.method.toUpperCase())) return
  const key = Array.isArray(raw) ? raw[0] : raw
  if (!KEY_FORMAT.test(key)) {
    return reply.status(400).send({ error: 'invalid_idempotency_key', message: 'Idempotency-Key must be 8-64 characters: letters, digits, - and _.' })
  }
  // Only for somebody the service knows: an anonymous caller has nothing to scope the key to.
  if (!request.userContext?.id || request.userContext.id === 'unknown') return

  const redisKey = slotKey(request, key)
  const bodyHash = bodyHashOf(request.body)
  const redis = getRedisClient()
  const pending: Stored = { state: 'pending', bodyHash }
  const claimed = await redis.set(redisKey, JSON.stringify(pending), 'EX', PENDING_TTL_S, 'NX')
  if (claimed === 'OK') {
    request.idempotencySlot = { redisKey, bodyHash }
    return
  }

  const raw2 = await redis.get(redisKey)
  if (!raw2) {
    // Expired between the two calls: nothing to replay, and the claim is free again.
    return reply.status(409).send({ error: 'idempotency_in_progress', message: 'Retry in a moment.' })
  }
  const stored = JSON.parse(raw2) as Stored
  if (stored.bodyHash !== bodyHash) {
    return reply.status(422).send({
      error: 'idempotency_key_reused',
      message: 'This Idempotency-Key was already used for a different request. Use a new key for a new request.',
    })
  }
  if (stored.state === 'pending') {
    return reply.status(409).send({ error: 'idempotency_in_progress', message: 'The first request with this key is still running. Retry in a moment.' })
  }
  reply.header('idempotent-replayed', 'true')
  if (stored.contentType) reply.header('content-type', stored.contentType)
  return reply.status(stored.status).send(stored.body)
}

export async function idempotencyOnSend(request: FastifyRequest, reply: FastifyReply, payload: unknown) {
  const slot = request.idempotencySlot
  if (!slot) return payload
  request.idempotencySlot = undefined
  const redis = getRedisClient()
  const body = typeof payload === 'string' ? payload : Buffer.isBuffer(payload) ? payload.toString('utf8') : null
  try {
    if (reply.statusCode >= 500 || body === null) {
      await redis.del(slot.redisKey)
    } else {
      const contentType = reply.getHeader('content-type')
      const done: Stored = {
        state: 'done',
        bodyHash: slot.bodyHash,
        status: reply.statusCode,
        ...(typeof contentType === 'string' ? { contentType } : {}),
        body,
      }
      await redis.set(slot.redisKey, JSON.stringify(done), 'EX', IDEMPOTENCY_TTL_S)
    }
  } catch (err) {
    // The answer itself is not lost; only its replay is. The pending claim expires on its own.
    request.log.warn({ err: (err as Error).message }, '[idempotency] could not record the answer')
  }
  return payload
}

/** Both hooks, on the instance whose routes they cover (server.ts: the root, so every route). */
export function registerIdempotency(fastify: {
  addHook(name: 'preHandler', fn: typeof idempotencyPreHandler): unknown
  addHook(name: 'onSend', fn: typeof idempotencyOnSend): unknown
}): void {
  fastify.addHook('preHandler', idempotencyPreHandler)
  fastify.addHook('onSend', idempotencyOnSend)
}
