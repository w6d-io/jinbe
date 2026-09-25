import type { FastifyInstance } from 'fastify'
import { kratosService } from '../services/kratos.service.js'
import { organisationsOf } from '../services/org-membership.service.js'
import { organisationStoreConfigured, organisationsById } from '../services/organisation-store.js'
import { orgGrantsRepository } from '../services/org-grants.repository.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { requirePlatformPermission } from '../middleware/require-platform-permission.js'
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
 * Mounted inside the admin plugin, so its admin:read gate runs first. A store that cannot be read
 * answers 503: an empty `grants` would read as "nothing granted".
 */

const stringList = { type: 'array', items: { type: 'string' } }

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
    // The gateway checks admin:read too, but nothing stops a pod from calling jinbe directly.
    preHandler: requirePlatformPermission('admin:read'),
    schema: {
      description:
        "A user's site access (groups → roles per service) and org access (per org: admin flag and the " +
        'groups granted there). Needs admin:read.',
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
                  admin: { type: 'boolean' },
                  grants: stringList,
                },
              },
            },
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
    const email = String(identity.traits?.email ?? '').toLowerCase()
    const metadata = identity.metadata_admin as { groups?: unknown } | null | undefined
    // Same default the bindings apply to an identity carrying no groups.
    const groups = Array.isArray(metadata?.groups)
      ? metadata.groups.filter((g): g is string => typeof g === 'string')
      : ['users']

    let orgIds: string[], definitions, grants, rosters
    try {
      ;[orgIds, definitions, grants, rosters] = await Promise.all([
        organisationsOf(identity),
        redisRbacRepository.getGroups(),
        orgGrantsRepository.getAll(),
        redisRbacRepository.getOrgAdminMap(),
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
      admin: (rosters[orgId] ?? []).some((e) => e.toLowerCase() === email),
      grants: grants[orgId]?.[email] ?? [],
    }))

    return reply.send({ site: { groups, byService }, orgs })
  })
}
