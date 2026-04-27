import type { FastifyInstance } from 'fastify'
import { opaBundleService } from '../services/opa-bundle.service.js'

/**
 * OPA Bundle endpoint — polled by OPA replicas
 *
 * GET /api/opa/bundle → tar.gz containing rbac.rego + data.json
 * Supports ETag for efficient polling (304 Not Modified)
 * Public — no auth required (internal cluster only)
 */
export async function opaBundleRoutes(fastify: FastifyInstance) {
  fastify.get('/bundle', {
    schema: {
      description: 'Get OPA policy bundle (tar.gz). Polled by OPA replicas.',
      tags: ['opa'],
    },
  }, async (request, reply) => {
    const ifNoneMatch = request.headers['if-none-match'] as string | undefined

    const result = await opaBundleService.getBundle(ifNoneMatch)

    if (!result) {
      return reply.status(304).send()
    }

    return reply
      .header('Content-Type', 'application/gzip')
      .header('ETag', result.etag)
      .header('Cache-Control', 'no-cache')
      .send(result.buffer)
  })
}
