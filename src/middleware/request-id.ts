import { FastifyRequest, FastifyReply } from 'fastify'
import { randomUUID } from 'crypto'

/**
 * Request ID middleware
 * Adds a unique identifier to each request for tracing and logging
 */
export async function requestIdMiddleware(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const requestId = request.headers['x-request-id'] || randomUUID()
  request.headers['x-request-id'] = requestId as string
  reply.header('X-Request-ID', requestId)
}
