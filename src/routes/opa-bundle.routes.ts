import type { FastifyInstance } from 'fastify'
import { opaBundleService } from '../services/opa-bundle.service.js'
import { requireInternalCaller } from '../middleware/require-internal-caller.js'

/**
 * OPA Bundle endpoint — polled by OPA replicas
 *
 * GET /api/opa/bundle → tar.gz containing rbac.rego + data.json
 * Supports ETag for efficient polling (304 Not Modified)
 * Internal callers only (a ServiceAccount listed in INTERNAL_API_ALLOWED_SUBJECTS): the bundle's
 * data.json maps every email to its groups. No consumer today (OPA is fed by OPAL).
 */
export async function opaBundleRoutes(fastify: FastifyInstance) {
  fastify.get('/bundle', {
    preHandler: requireInternalCaller,
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
