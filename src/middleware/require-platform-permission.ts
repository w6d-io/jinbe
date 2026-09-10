import { FastifyRequest, FastifyReply } from 'fastify'
import { holdsPlatformPermission } from '../services/authorization-model.service.js'

/**
 * Requires a permission ACROSS the platform, from the model the engine decides against.
 *
 * For the surfaces that are not about one organisation: listing every organisation, reading the
 * audit trail, handing out a group. Whether the caller may is decided by the same documents and the
 * same coverage rule a route of any other API is decided by — so `admin:read` admits
 * `admin.organisation:read` here exactly as it would there.
 *
 * Keyed on the immutable identity, never an address. And it refuses rather than narrowing: a screen
 * that asked for everything and received less would have no way to tell a short answer from a
 * complete one.
 */
export function requirePlatformPermission(required: string) {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const subject = request.userContext?.id
    if (!subject || subject === 'unknown') {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    }

    let permitted: boolean
    try {
      permitted = await holdsPlatformPermission(subject, required)
    } catch (err) {
      // "Does not hold it" and "I could not tell" are opposite facts. A 403 here would read as a
      // missing right rather than as a model nobody could load.
      request.log.warn({ subject, required, err }, '[platform] the authorization model could not be read')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    }

    if (!permitted) {
      return reply.status(403).send({
        error: 'Forbidden',
        message: `This needs ${required}.`,
      })
    }
  }
}
