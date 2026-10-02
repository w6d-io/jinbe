import type { FastifyInstance } from 'fastify'
import { kratosService } from '../services/kratos.service.js'
import { organisationsOf } from '../services/org-membership.service.js'
import { organisationStoreConfigured, organisationsById } from '../services/organisation-store.js'
import { directGrantsRepository, isActive, type DirectGrant } from '../services/direct-grants.repository.js'
import { orgRolesRepository } from '../services/org-roles.repository.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { needs } from '../policy/route-access.js'
import { orgPermissionsByOrg, rights } from '../authz/opa.js'
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
 *   orgs: each org they belong to, the org roles assigned to them there, and the org permissions OPA
 *         says they hold there (assigned roles ∪ the every-org map) — the same answer the org gate reads
 *
 * Needs access:read (enforced here: nothing stops a pod from calling jinbe directly). A store that cannot be read
 * answers 503: an empty `roles` would read as "nothing assigned".
 */

const stringList = { type: 'array', items: { type: 'string' } }

/**
 * Their second-factor picture: which of their groups require it, whether they enrolled, and which of
 * their permissions need a recent one. Nothing about a session (they may have none, or several).
 * Each part is best effort; the whole is null only when the setting itself cannot be read.
 */
async function secondFactorOf(id: string, address: string, groups: string[]): Promise<UserSecondFactor | null> {
  const [setting, methods, held] = await Promise.all([
    getSecondFactorSetting().catch(() => null),
    (async () => kratosService.mfaMethodsOf(id))().catch(() => null),
    // As the RBAC bindings key it, like every other OPA question here: never lowercased.
    (async () => (address ? rights(address) : null))().catch(() => null),
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

/** A direct grant as this view shows it: marked `direct`, with who, when, why and until when. */
const directGrantView = {
  type: 'object',
  properties: {
    source: { type: 'string', enum: ['direct'] },
    id: { type: 'string' }, app: { type: 'string' }, kind: { type: 'string', enum: ['role', 'permission'] }, name: { type: 'string' },
    grantedBy: { type: 'string' }, grantedAt: { type: 'string' }, reason: { type: 'string' }, expiresAt: { type: 'string' },
    active: { type: 'boolean' },
  },
} as const

const directView = (g: DirectGrant) => ({
  source: 'direct' as const, id: g.id, app: g.app, kind: g.kind, name: g.name, grantedBy: g.grantedBy, grantedAt: g.grantedAt,
  ...(g.reason ? { reason: g.reason } : {}), ...(g.expiresAt ? { expiresAt: g.expiresAt } : {}), active: isActive(g),
})

export async function userAccessRoutes(fastify: FastifyInstance) {
  fastify.get('/users/:id/access', {
    ...needs('access:read'),
    schema: {
      description:
        "A user's site access (groups → roles per service, and `direct`: roles and permissions held directly, platform-wide) " +
        'and org access (per org: the org roles assigned there, `direct` grants there, and the org permissions held there, ' +
        'as OPA decides them), and secondFactor (requiredBecause, enrolled, stepUpPermissions; session fields null). ' +
        'A direct grant carries source "direct", who granted it and when, its reason and expiry, and whether it still counts. Needs access:read.',
      tags: ['admin'],
      params: { type: 'object', required: ['id'], properties: { id: { type: 'string', maxLength: 128 } } },
      response: {
        200: {
          type: 'object',
          properties: {
            site: {
              type: 'object',
              properties: {
                groups: stringList,
                byService: { type: 'object', additionalProperties: stringList },
                direct: { type: 'array', items: directGrantView, description: 'Roles and permissions held directly, platform-wide' },
              },
            },
            orgs: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  orgId: { type: 'string' },
                  name: { type: 'string' },
                  roles: { ...stringList, description: 'Org roles assigned here (svc:role)' },
                  permissions: { ...stringList, description: 'Org permissions held here (OPA rbac.org_permissions_by_org)' },
                  direct: { type: 'array', items: directGrantView, description: 'Org roles and permissions held directly here' },
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
    // As the RBAC bindings key it: OPA is asked with this, never a lowercased copy.
    const address = String(identity.traits?.email ?? '')
    const metadata = identity.metadata_admin as { groups?: unknown } | null | undefined
    // No groups is no groups: the base group `users` the previous model added is gone.
    const groups = Array.isArray(metadata?.groups)
      ? metadata.groups.filter((g): g is string => typeof g === 'string')
      : []

    let orgIds: string[], definitions, assignments, held: Record<string, string[]>, direct: DirectGrant[]
    try {
      ;[orgIds, definitions, assignments, held, direct] = await Promise.all([
        organisationsOf(identity),
        redisRbacRepository.getGroups(),
        orgRolesRepository.getAll(),
        address ? orgPermissionsByOrg(address) : Promise.resolve({}),
        directGrantsRepository.getFor(id),
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
      roles: assignments[orgId]?.[id] ?? [],
      permissions: held[orgId] ?? [],
      direct: direct.filter((g) => g.scope === orgId).map(directView),
    }))

    const site = { groups, byService, direct: direct.filter((g) => g.scope === 'platform').map(directView) }
    return reply.send({ site, orgs, secondFactor: await secondFactorOf(id, address, groups) })
  })
}
