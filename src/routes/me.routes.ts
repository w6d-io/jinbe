import { FastifyInstance, FastifyRequest } from 'fastify'
import { opaService } from '../services/opa.service.js'
import { rbacService } from '../services/rbac.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { kratosService } from '../services/kratos.service.js'
import { env } from '../config/env.js'

/**
 * The full org universe a global super_admin administers. Organizations are
 * NOT a first-class entity — they are implied by two independent sources:
 *   1. org_service_map keys (orgs that have a service mapping), and
 *   2. the org ids identities carry (native organization_id + any
 *      metadata_admin.organizations).
 * A super_admin can reach ANY org (their global "*" passes every gateway +
 * guard), so discovery must reflect the union of both — listing only mapped
 * orgs hid every org that has members but no service mapping yet.
 * FAIL-SOFT: if the Kratos scan fails we still return the mapped orgs rather
 * than erroring the whole endpoint.
 */
async function allOrganizations(): Promise<string[]> {
  const orgs = new Set<string>(
    Object.keys(await redisRbacRepository.getOrgServiceMap()),
  )
  try {
    const bindings = await kratosService.getAllIdentitiesWithBindings()
    for (const b of bindings.values()) {
      if (b.primaryOrganization) orgs.add(b.primaryOrganization)
      for (const o of b.organizations) if (o) orgs.add(o)
    }
  } catch {
    // Kratos directory scan failed — degrade to the mapped orgs only.
  }
  return [...orgs]
}

/**
 * Self-service ("me") routes — scoped to the authenticated caller.
 *
 * GET /me/organizations
 *   The organisations the caller may administer, with a `scope`:
 *     - global super_admin → `scope: "all"` + EVERY org (the union of
 *       org_service_map keys and identity-derived org ids, see
 *       allOrganizations). Super admins already pass the gateway + guard for
 *       any org via their global "*", so the list must reflect that (they
 *       aren't members of every org, so manageable_orgs would wrongly return
 *       few/none, and mapped-orgs-only would hide unmapped ones).
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
      // DEV MODE: mirror the whoami/requireServiceAdmin bypass — no OPA. The
      // dev user is effectively a super_admin, so show the full org universe
      // (scope: 'all') rather than an empty delegated list, which was hiding
      // every org from the local console.
      if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
        return reply.send({ organizations: await allOrganizations(), scope: 'all' })
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
        return reply.send({ organizations: await allOrganizations(), scope: 'all' })
      }

      const organizations = await opaService.manageableOrgs(email)
      return reply.send({ organizations, scope: 'delegated' })
    }
  )
}
