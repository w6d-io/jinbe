import { FastifyRequest, FastifyReply } from 'fastify'

/**
 * Request ID middleware
 *
 * `request.id` is the caller's `x-request-id` when it is a plausible id, or a fresh UUID
 * (telemetry/logger.ts `genReqId`). It is written back to the header so everything that reads the
 * header (audit actor, outgoing calls) agrees with what the log lines carry, and echoed on the reply.
 */
export async function requestIdMiddleware(
  request: FastifyRequest,
  reply: FastifyReply
) {
  request.headers['x-request-id'] = request.id
  reply.header('X-Request-ID', request.id)
}
