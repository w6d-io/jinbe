import type { FastifyRequest, FastifyReply } from 'fastify'

/**
 * Remap a URL param to a different name for the controller.
 * Eliminates the ugly `req.params.X = req.params.id` + `as any` pattern.
 */
export function remapParam(
  paramFrom: string,
  paramTo: string,
  handler: (request: FastifyRequest<any>, reply: FastifyReply) => Promise<unknown>
) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const params = request.params as Record<string, string>
    params[paramTo] = params[paramFrom]
    return handler(request as any, reply)
  }
}
