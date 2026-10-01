import type { FastifyInstance } from 'fastify'
import { kratosService } from '../services/kratos.service.js'
import { organisationsOf } from '../services/org-membership.service.js'
import { organisationStoreConfigured, organisationsById } from '../services/organisation-store.js'
import { orgGrantsRepository } from '../services/org-grants.repository.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { needs } from '../policy/route-access.js'
import { manageableOrgs, memberOrgs, rights } from '../authz/opa.js'
import { orgAdminView } from '../services/org-admin.js'
import { getSecondFactorSetting } from '../second-factor/settings.js'
import { userSecondFactor, type UserSecondFactor } from '../second-factor/requirements.js'
import { userSecondFactorJsonSchema } from '../schemas/second-factor.schema.js'
import {
  notFoundResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
  forbiddenResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * GET /admin/users/:id/access — one person's access, both layers side by side.
 *
 *   site: the groups they hold and the roles those give per service (org membership never touches it)
 *   orgs: each org they belong to, whether they administer it, and the groups granted to them there
 *
 * `admin` is the authoritative guard's answer — OPA `manageable_orgs` (on the roster AND a member),
 * the query requireOrgAdmin asks — never the roster store read beside it: the two disagreed on case,
 * on membership and on OPAL lag, and `admin: true` was shown for somebody the org routes refused.
 * `rostered` is the store's view; `why` says what keeps a rostered person from administering.
 *
 * Needs access:read (enforced here: nothing stops a pod from calling jinbe directly). A store that cannot be read
 * answers 503: an empty `grants` would read as "nothing granted".
 */

const stringList = { type: 'array', items: { type: 'string' } }

/**
 * Their second-factor picture: which of their groups require it, whether they enrolled, and which of
 * their permissions need a recent one. Nothing about a session (they may have none, or several).
 * Each part is best effort; the whole is null only when the setting itself cannot be read.
 */
async function secondFactorOf(id: string, email: string, groups: string[]): Promise<UserSecondFactor | null> {
  const [setting, methods, held] = await Promise.all([
    getSecondFactorSetting().catch(() => null),
    (async () => kratosService.mfaMethodsOf(id))().catch(() => null),
    (async () => (email ? rights(email) : null))().catch(() => null),
  ])
  if (!setting) return null
  return userSecondFactor({ groups, permissions: held?.permissions ?? null, setting, methods, session: null })
}

async function namesFor(ids: readonly string[]): Promise<Record<string, string>> {
  if (!organisationStoreConfigured() || ids.length === 0) return {}
  try {
    return Object.fromEntries((await organisationsById(ids)).map((o) => [o.id, o.name]))
  } catch {
    return {}
  }
}

export async function userAccessRoutes(fastify: FastifyInstance) {
  fastify.get('/users/:id/access', {
    ...needs('access:read'),
    schema: {
      description:
        "A user's site access (groups → roles per service) and org access (per org: `admin` as OPA decides it " +
        "(manageable_orgs), `rostered` as jinbe's roster store says, `why` when they differ, and the groups " +
        'granted there), and secondFactor (requiredBecause, enrolled, stepUpPermissions; session fields null). Needs access:read.',
      tags: ['admin'],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'string', maxLength: 128 } } },
      response: {
        200: {
          type: 'object',
          properties: {
            site: {
              type: 'object',
              properties: { groups: stringList, byService: { type: 'object', additionalProperties: stringList } },
            },
            orgs: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  orgId: { type: 'string' },
                  name: { type: 'string' },
                  admin: { type: 'boolean', description: "OPA would let them manage this org's people (manageable_orgs)" },
                  rostered: { type: 'boolean', description: "On the org's admin roster in jinbe's store" },
                  why: {
                    type: 'string',
                    enum: ['not_a_member_per_policy', 'email_case_mismatch', 'policy_not_yet_loaded'],
                    description: 'Only when rostered but not admin: what keeps them from administering',
                  },
                  grants: stringList,
                },
              },
            },
            secondFactor: userSecondFactorJsonSchema,
          },
        },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        404: notFoundResponseSchema,
        503: serviceUnavailableResponseSchema,
      },
    },
  }, async (request, reply) => {
    const { id } = request.params as { id: string }
    let identity
    try {
      identity = await kratosService.getIdentity(id)
    } catch (err) {
      if ((err as { statusCode?: number })?.statusCode === 404) {
        return reply.status(404).send({ error: 'Not Found', message: 'User not found' })
      }
      throw err
    }
    // As the RBAC bindings key it (OPA is asked with this), and lowercased for the stores.
    const address = String(identity.traits?.email ?? '')
    const email = address.toLowerCase()
    const metadata = identity.metadata_admin as { groups?: unknown } | null | undefined
    // Same default the bindings apply to an identity carrying no groups.
    const groups = Array.isArray(metadata?.groups)
      ? metadata.groups.filter((g): g is string => typeof g === 'string')
      : ['users']

    let orgIds: string[], definitions, grants, rosters, manageable: string[], members: string[]
    try {
      ;[orgIds, definitions, grants, rosters, manageable, members] = await Promise.all([
        organisationsOf(identity),
        redisRbacRepository.getGroups(),
        orgGrantsRepository.getAll(),
        redisRbacRepository.getOrgAdminMap(),
        address ? manageableOrgs(address) : Promise.resolve([]),
        address ? memberOrgs(address) : Promise.resolve([]),
      ])
    } catch (err) {
      request.log.warn({ err, id }, '[user-access] a store could not be read')
      return reply.status(503).send({ error: 'Service Unavailable', message: 'Access could not be read. Please try again later.' })
    }

    const byService: Record<string, string[]> = {}
    for (const group of groups) {
      for (const [service, roles] of Object.entries(definitions[group] ?? {})) {
        byService[service] = [...new Set([...(byService[service] ?? []), ...roles])]
      }
    }

    const names = await namesFor(orgIds)
    const orgs = orgIds.map((orgId) => ({
      orgId,
      name: names[orgId] ?? orgId,
      ...orgAdminView(address, orgId, { manageable, memberOrgs: members, roster: rosters[orgId] ?? [] }),
      grants: grants[orgId]?.[address] ?? grants[orgId]?.[email] ?? [],
    }))

    return reply.send({ site: { groups, byService }, orgs, secondFactor: await secondFactorOf(id, email, groups) })
  })
}
