import { FastifyInstance, FastifyRequest } from 'fastify'
import { callerRights } from '../middleware/require-permission.js'
import { rights as opaRights } from '../authz/opa.js'
import { userActions } from '../services/user-permissions.js'
import { callerOrganisations, callerOrganisationsScope } from '../services/caller-organisations.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { kratosService } from '../services/kratos.service.js'
import { env } from '../config/env.js'
import {
  allOrganisations as heldOrganisations,
  organisationsById,
  organisationStoreConfigured,
} from '../services/organisation-store.js'

/**
 * The full org universe a global super_admin administers. The union of three sources, because each
 * one alone hides organisations the others hold:
 *   0. the records this service owns, where it owns them — the only source that knows about an
 *      organisation nobody belongs to yet, which is exactly the one somebody is about to assign,
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
  // The records this service owns, first: since it took ownership of organisations, an organisation
  // with members but no service mapping and nobody carrying it on their identity existed only here.
  // It was therefore absent from the one list the console offers when somebody assigns — so the
  // organisations that actually exist could not be assigned, only the ones already in use.
  if (organisationStoreConfigured()) {
    try {
      for (const held of await heldOrganisations()) orgs.add(held.id)
    } catch {
      // A store that cannot answer costs its own entries and never the rest of the list.
    }
  }
  try {
    const bindings = await kratosService.getAllIdentitiesWithBindings()
    for (const b of bindings.values()) {
      if (b.primaryOrganization) orgs.add(b.primaryOrganization)
      for (const o of b.organizations) if (o) orgs.add(o)
    }
  } catch {
    // Kratos directory scan failed — degrade to whatever the other sources gave.
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
/**
 * What to call each organisation on screen.
 *
 * Only this service's own records carry a label, so nothing is invented when there are none: the
 * caller falls back to the identifier, which is worse to read and still correct. A store that
 * cannot answer costs a label and never the list — losing the list would turn a display problem
 * into somebody appearing to belong nowhere.
 */
async function namesFor(ids: readonly string[]): Promise<Record<string, string>> {
  if (!organisationStoreConfigured() || ids.length === 0) return {}
  try {
    return Object.fromEntries((await organisationsById(ids)).map((o) => [o.id, o.name]))
  } catch {
    return {}
  }
}

export async function meRoutes(fastify: FastifyInstance) {
  /**
   * What the caller may do, so a console offers only the actions the API would accept.
   *
   * `actions` names every user-management permission and the coarse pair, each true or false — the
   * SAME rule the routes enforce (a coarse permission covers the fine ones under it), so a button is
   * shown exactly when its request would pass. A console must still expect a 403: this is a hint for
   * what to draw, never the decision.
   *
   * Answered by OPA, the engine the gateway decides with: `permissions`/`roles` are jinbe's (global
   * roles included), `apps.kuma` the console's own.
   */
  fastify.get(
    '/permissions',
    {
      schema: {
        description: "The caller's effective permissions across the platform, and which user-management actions they allow.",
        tags: ['me'],
        response: {
          200: {
            type: 'object',
            properties: {
              subject: { type: 'string' },
              groups: { type: 'array', items: { type: 'string' } },
              roles: { type: 'array', items: { type: 'string' } },
              permissions: { type: 'array', items: { type: 'string' } },
              actions: { type: 'object', additionalProperties: { type: 'boolean' } },
              apps: {
                type: 'object',
                additionalProperties: {
                  type: 'object',
                  properties: {
                    roles: { type: 'array', items: { type: 'string' } },
                    permissions: { type: 'array', items: { type: 'string' } },
                  },
                },
              },
            },
          },
          401: { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } },
          503: { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } },
        },
      },
    },
    async (request, reply) => {
      const rights = await callerRights(request, reply)
      if (!rights) return reply
      let kuma: { roles: string[]; permissions: string[] } = { roles: [], permissions: [] }
      if (!(env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development')) {
        try {
          const held = await opaRights(rights.email, 'kuma')
          kuma = { roles: held.roles, permissions: held.permissions }
        } catch (err) {
          // Same rule as jinbe's own: "could not tell" is not "holds nothing".
          request.log.warn({ err: (err as Error).message }, '[me/permissions] OPA could not answer for kuma')
          return reply.status(503).send({ error: 'Service Unavailable', message: 'Unable to verify authorization. Please try again later.' })
        }
      }
      return reply.send({
        subject: request.userContext?.id,
        groups: rights.groups,
        roles: rights.roles,
        permissions: rights.permissions,
        actions: userActions(rights.permissions),
        apps: { jinbe: { roles: rights.roles, permissions: rights.permissions }, kuma },
      })
    },
  )

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
              // What to call each one on screen, keyed by the identifier above. Additive: a caller that
              // only knows identifiers keeps working, and one that shows them to a person no longer has
              // to display a UUID nobody can tell from another.
              names: { type: 'object', additionalProperties: { type: 'string' } },
              // Where the answer came from — the directory or the token — never how wide it is.
              scope: { type: 'string', enum: ['delegated', 'claim'] },
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
        const organizations = await allOrganizations()
        return reply.send({ organizations, names: await namesFor(organizations), scope: 'all' })
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

      // MINE, whoever asks. This used to answer with EVERY organisation when the caller was a
      // super admin, so the same URL meant two different things depending on who called it — and
      // the `scope` field existed to tell the caller which of the two they had received. A screen
      // asking for everything and getting less could not tell a short answer from a complete one.
      //
      // Every organisation is a separate question with a separate answer: GET /admin/organizations,
      // which refuses with a 403 rather than narrowing.
      const organizations = await callerOrganisations(request)
      return reply.send({
        organizations,
        names: await namesFor(organizations),
        scope: callerOrganisationsScope(),
      })
    }
  )
}
