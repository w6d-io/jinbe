import { FastifyInstance, FastifyRequest } from 'fastify'
import { opaService } from '../services/opa.service.js'
import { env } from '../config/env.js'

/**
 * Self-service ("me") routes — scoped to the authenticated caller.
 *
 * GET /me/organizations
 *   The organisations the caller may administer (delegation
 *   `manageable_orgs`, resolved by OPA from OPAL data by email). Powers the
 *   org-admin UI: which orgs to offer, and which to gate the scoped
 *   user-management views behind. Requires a valid session (401 otherwise).
 *   FAIL-CLOSED: OPA error → empty list (the UI then offers nothing).
 */
export async function meRoutes(fastify: FastifyInstance) {
  fastify.get(
    '/organizations',
    {
      schema: {
        description: 'List the organizations the current user may administer',
        tags: ['me'],
        response: {
          200: {
            type: 'object',
            properties: {
              organizations: { type: 'array', items: { type: 'string' } },
            },
          },
          401: {
            type: 'object',
            properties: { error: { type: 'string' }, message: { type: 'string' } },
          },
        },
      },
    },
    async (request: FastifyRequest, reply) => {
      // DEV MODE: mirror the whoami/requireServiceAdmin bypass — no OPA.
      if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
        return reply.send({ organizations: [] })
      }

      const email =
        request.validatedSession?.email ||
        (request.userContext?.email && request.userContext.email !== 'unknown'
          ? request.userContext.email
          : null)

      if (!email) {
        return reply.status(401).send({
          error: 'Unauthorized',
          message: 'Authentication required',
        })
      }

      const organizations = await opaService.manageableOrgs(email)
      return reply.send({ organizations })
    }
  )
}
