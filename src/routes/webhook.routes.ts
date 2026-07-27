import type { FastifyInstance } from 'fastify'
import { webhookController } from '../controllers/webhook.controller.js'

/**
 * Kratos after-hook webhook (A5). Public at the gateway (Kratos has no jinbe
 * session) but SELF-AUTHENTICATED in the handler — see webhook.controller.
 *
 * A raw-body content-type parser is registered on this encapsulated instance so
 * the handler can verify an `Ory-Signature` HMAC over the exact bytes Kratos
 * sent, in addition to the api_key header path.
 */
export async function webhookRoutes(fastify: FastifyInstance) {
  fastify.addContentTypeParser(
    'application/json',
    { parseAs: 'string' },
    (req, body, done) => {
      ;(req as typeof req & { rawBody?: string }).rawBody = body as string
      try {
        done(null, body ? JSON.parse(body as string) : {})
      } catch (err) {
        done(err as Error, undefined)
      }
    },
  )

  fastify.post(
    '/kratos',
    {
      schema: {
        description: 'Kratos after-hook receiver (login / MFA / settings / registration). Self-authenticated via shared secret.',
        tags: ['webhooks'],
        body: { type: 'object', additionalProperties: true },
        response: {
          200: { type: 'object', properties: { ok: { type: 'boolean' } } },
          401: { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } },
        },
      },
    },
    (request, reply) => webhookController.kratos(request, reply),
  )
}
