import { FastifyInstance, FastifyRequest } from 'fastify'
import { opaService } from '../services/opa.service.js'
import { rbacService } from '../services/rbac.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { env } from '../config/env.js'

/**
 * Self-service ("me") routes — scoped to the authenticated caller.
 *
 * GET /me/organizations
 *   The organisations the caller may administer, with a `scope`:
 *     - global super_admin → `scope: "all"` + EVERY mapped org (org_service_map
 *       keys). Super admins already pass the gateway + guard for any org via
 *       their global "*", so the list must reflect that (they aren't members of
 *       every org, so manageable_orgs would wrongly return few/none).
 *     - delegated org admin → `scope: "delegated"` + `manageable_orgs` (orgs
 *       they are a member of AND administer), resolved by OPA from email.
 *   Requires a valid session (401 otherwise). FAIL-CLOSED: OPA error → empty
 *   list (the UI then offers nothing).
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
              scope: { type: 'string', enum: ['all', 'delegated'] },
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
        return reply.send({ organizations: [], scope: 'delegated' })
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

      // A global super_admin manages EVERY org — return all mapped orgs, not just
      // the ones they happen to be a member of (manageable_orgs). The enforcement
      // layers already admit them to any org via their global "*".
      if (await rbacService.isSuperAdmin({ email })) {
        const organizations = Object.keys(await redisRbacRepository.getOrgServiceMap())
        return reply.send({ organizations, scope: 'all' })
      }

      const organizations = await opaService.manageableOrgs(email)
      return reply.send({ organizations, scope: 'delegated' })
    }
  )
}
