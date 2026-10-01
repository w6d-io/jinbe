import { FastifyInstance, FastifyRequest } from 'fastify'
import { callerRights } from '../middleware/require-permission.js'
import { orgPermissionsByOrg } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
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
import { open } from '../policy/route-access.js'
import { getSecondFactorSetting } from '../second-factor/settings.js'
import { userSecondFactor, type UserSecondFactor } from '../second-factor/requirements.js'
import { userSecondFactorJsonSchema } from '../schemas/second-factor.schema.js'
import type { MfaMethod } from '../services/kratos.service.js'

/**
 * The caller's own second-factor picture: which of their groups require it, whether they enrolled,
 * their session's level and how old its second factor is, and which permissions need a recent one.
 * Best effort — null when the setting cannot be read; the permissions answer never waits on it.
 */
async function ownSecondFactor(request: FastifyRequest, groups: string[], permissions: string[]): Promise<UserSecondFactor | null> {
  const uc = request.userContext
  let setting
  try {
    setting = await getSecondFactorSetting()
  } catch {
    return null
  }
  let methods: MfaMethod[] | null = null
  // An aal2 session has a factor by definition; below it, ask Kratos (skipped in local dev).
  if (uc?.aal !== 'aal2' && uc?.id && !(env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development')) {
    try {
      methods = await kratosService.mfaMethodsOf(uc.id)
    } catch {
      methods = null
    }
  }
  return userSecondFactor({
    groups,
    permissions,
    setting,
    methods,
    session: { aal: uc?.aal, secondFactorAt: uc?.secondFactorAt, authVia: uc?.authVia },
  })
}

/**
 * Every organisation, for local development's bypass (its user acts as super_admin, which holds every
 * org permission in every org). The union of three sources, because each alone hides some:
 *   0. the records this service owns, where it owns them — the only source that knows about an
 *      organisation nobody belongs to yet,
 *   1. the orgs entitled to a site (rbac:org_sites), and
 *   2. the org ids identities carry (native organization_id + any metadata_admin.organizations).
 * FAIL-SOFT: a source that cannot answer costs its own entries and never the rest of the list.
 */
async function allOrganizations(): Promise<string[]> {
  const orgs = new Set<string>(
    Object.keys(await redisRbacRepository.getOrgSites()),
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
 *   The organisations the caller belongs to (the directory, or the token's claim), with their names.
 *   What they may do in each is `orgPermissions` on GET /me/permissions. Requires a valid session.
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
   * Answered by OPA, the engine the gateway decides with: `permissions`/`roles` are jinbe's platform
   * ones; `orgPermissions` what the caller holds in each organisation (org roles assigned there, and
   * the every-org map) — what the org routes decide with.
   */
  fastify.get(
    '/permissions',
    {
      ...open('self'),
      schema: {
        description:
          "The caller's effective permissions across the platform, which user-management actions they allow, and their " +
          'second-factor picture (secondFactor: requiredBecause groups, enrolled, currentAal, factorAgeMin, stepUpFresh, stepUpPermissions).',
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
              orgPermissions: { type: 'object', additionalProperties: { type: 'array', items: { type: 'string' } } },
              secondFactor: userSecondFactorJsonSchema,
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
      let orgPermissions: Record<string, string[]> = {}
      if (!(env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development')) {
        try {
          orgPermissions = await orgPermissionsByOrg(rights.email)
        } catch (err) {
          // Same rule as the platform ones: "could not tell" is not "holds nothing".
          request.log.warn({ err: (err as Error).message }, '[me/permissions] OPA could not answer for the organisations')
          return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: 'Unable to verify authorization. Please try again later.' })
        }
      }
      return reply.send({
        subject: request.userContext?.id,
        groups: rights.groups,
        roles: rights.roles,
        permissions: rights.permissions,
        actions: userActions(rights.permissions),
        orgPermissions,
        secondFactor: await ownSecondFactor(request, rights.groups, rights.permissions),
      })
    },
  )

  fastify.get(
    '/organizations',
    {
      ...open('self'),
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
      // DEV MODE: mirror the whoami bypass — no OPA. The dev user acts as super_admin, which holds
      // every org permission in every org, so show the full org universe (scope: 'all').
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
