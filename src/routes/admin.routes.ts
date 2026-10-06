import { FastifyInstance } from 'fastify'
import { adminController } from '../controllers/admin.controller.js'
import { requireMembershipChange } from '../middleware/require-membership-change.js'
import { needs } from '../policy/route-access.js'
import { realtimeService } from '../services/realtime.service.js'
import { accessReviewService } from '../services/access-review.service.js'
import {
  userIdParamSchema,
  kratosIdentityJsonSchema,
  userEmailParamSchema,
  updateUserGroupsBodyJsonSchema,
  userGroupsResponseJsonSchema,
  userGroupsUpdateResponseJsonSchema,
} from '../schemas/admin.schema.js'
import { zodToJsonSchema } from 'zod-to-json-schema'
import {
  badRequestResponseSchema,
  forbiddenResponseSchema,
  notFoundResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { allOrganisations, organisationsById, organisationStoreConfigured, organisationStoreNotConfigured } from '../services/organisation-store.js'
import { organisationAdminRoutes } from './organisation-admin.routes.js'
import { orgKeysAdminRoutes } from './org-keys-admin.routes.js'
import { orgRolesRepository } from '../services/org-roles.repository.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { JINBE, qualified } from '../policy/roles.js'
import { userAccessRoutes } from './user-access.routes.js'
import { sitesRoutes } from '../sites/routes.js'
import { gatewayRoutes } from '../gateway/routes.js'

/**
 * Admin routes. Each declares its catalogue permission (policy/catalog.ts); there is no plugin-wide
 * gate any more — `admin:read` opened every route here, writes included.
 *
 * Listing, reading, creating, editing and deleting users, their sessions, recovery and sign-in links
 * live in `user-management.routes.ts`: one permission per action, so a support role can reach them
 * without this plugin's gate.
 */
export async function adminRoutes(fastify: FastifyInstance) {
  // Real-time change stream (Server-Sent Events), stats:read until it folds into /audit/tail. It
  // emits a minimal {type} signal on any RBAC/directory change; the client
  // reacts by refetching through the normal auth'd endpoints (no data on wire).
  fastify.get('/events', needs('stats:read'), (request, reply) => {
    // NB: do NOT send a `Connection: keep-alive` header. It is a
    // connection-specific header field, forbidden under HTTP/2 (RFC 7540
    // §8.1.2.2). When this SSE response is fronted by an HTTP/2 ingress/gateway
    // the header makes the stream malformed and the browser aborts it with
    // ERR_HTTP2_PROTOCOL_ERROR. It is also redundant on HTTP/1.1 (keep-alive is
    // already the default). `X-Accel-Buffering: no` (nginx) + `no-transform`
    // keep proxies from buffering the stream.
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'X-Accel-Buffering': 'no',
    })
    reply.raw.write(': connected\n\n')
    realtimeService.addClient(reply)
    const cleanup = () => realtimeService.removeClient(reply)
    request.raw.on('close', cleanup)
    // A socket can error before 'close' fires; without this listener that
    // async 'error' would be unhandled and could crash the process under churn.
    reply.raw.on('error', cleanup)
    reply.hijack()
  })

  // Directory stats (cached counts — total/active/perGroup/perOrg)
  fastify.get(
    '/stats',
    {
      ...needs('stats:read'),
      schema: {
        description: 'Directory statistics (cached; total/active/per-group/per-org counts)',
        tags: ['admin'],
        response: {
          200: {
            type: 'object',
            properties: {
              total: { type: 'number' },
              active: { type: 'number' },
              fullAccess: { type: 'number' },
              unassigned: { type: 'number' },
              perGroup: { type: 'object', additionalProperties: { type: 'number' } },
              perOrg: { type: 'object', additionalProperties: { type: 'number' } },
              perService: { type: 'object', additionalProperties: { type: 'number' } },
              computedAt: { type: 'string' },
            },
          },
          401: unauthorizedResponseSchema,
        },
      },
    },
    adminController.getStats.bind(adminController)
  )

  // Access review (Part B / [P1-5]) — "who can do anything, and how".
  // Resolves power across ALL services from the group definitions, tiers each
  // identity (T0 global super-admin → T3 broad reach), joins MFA + last-active +
  // grant provenance, and ranks by power score. SWR-cached (getDirectoryStats
  // pattern), fail-closed on a directory/group read error. Response is additive/permissive so the kuma
  // AccessReview contract fields are never stripped.
  fastify.get(
    '/access-review',
    {
      ...needs('access:read'),
      schema: {
        description:
          'Access review: privileged identities across all services, tiered + ranked, with grant paths, MFA, last-active and provenance.',
        tags: ['admin'],
        response: {
          200: { type: 'object', additionalProperties: true },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
        },
      },
    },
    async (_request, reply) => {
      const data = await accessReviewService.getAccessReview()
      return reply.send(data)
    },
  )

  /**
   * Every organisation, for the screen that administers them.
   *
   * A SEPARATE ROUTE FROM `/me/organizations`, deliberately. That one used to return every
   * organisation when the caller was a super admin and only theirs otherwise, so the same URL meant
   * two different things depending on who asked — and it shipped a `scope` field whose only job was
   * to tell the caller which of the two they had received. A screen asking for everything and
   * getting less had no way to tell a short answer from a complete one.
   *
   * Here the question is unambiguous and the refusal is a 403.
   */
  fastify.get(
    '/organizations',
    {
      ...needs('orgs:read'),
      schema: {
        description:
          'Every organisation the directory holds, with its owners (identity ids holding jinbe:owner there) and the sites it is ' +
          'entitled to (org_sites: jinbe and the sites serving it). Needs orgs:read.',
        tags: ['admin'],
        response: {
          200: {
            type: 'object',
            properties: {
              organizations: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    name: { type: 'string' },
                    tenant: { type: 'string' },
                    owners: { type: 'array', items: { type: 'string' } },
                    sites: { type: 'array', items: { type: 'string' } },
                  },
                },
              },
            },
          },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          503: serviceUnavailableResponseSchema,
        },
      },
    },
    async (request, reply) => {
      if (!organisationStoreConfigured()) {
        return reply.status(503).send(organisationStoreNotConfigured())
      }
      try {
        const [organizations, assignments, orgSites] = await Promise.all([
          allOrganisations(), orgRolesRepository.getAll(), redisRbacRepository.getOrgSites(),
        ])
        const owner = qualified(JINBE, 'owner')
        return reply.send({
          organizations: organizations.map(({ id, name, tenant }) => ({
            id,
            name,
            tenant,
            owners: Object.entries(assignments[id] ?? {}).filter(([, roles]) => roles.includes(owner)).map(([subject]) => subject).sort(),
            sites: [...new Set([JINBE, ...(orgSites[id] ?? [])])],
          })),
        })
      } catch (err) {
        // Never a short list: a screen showing four of eight organisations says the other four do
        // not exist, which is the one thing that is certainly false.
        request.log.error({ err }, 'The organisation directory could not be read')
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'The organisation directory could not be read.',
        })
      }
    },
  )

  // One organisation, from the platform: who owns it, which sites it is entitled to.
  fastify.get(
    '/organizations/:id',
    {
      ...needs('orgs:read'),
      schema: {
        description:
          'One organisation: its owners (identity ids holding jinbe:owner there) and the sites it is entitled to (org_sites: jinbe ' +
          'and the sites serving it). Needs orgs:read.',
        tags: ['admin'],
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string', format: 'uuid' } } },
        response: {
          200: {
            type: 'object',
            properties: {
              id: { type: 'string' }, name: { type: 'string' }, tenant: { type: 'string' },
              owners: { type: 'array', items: { type: 'string' } },
              sites: { type: 'array', items: { type: 'string' } },
            },
          },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } },
          503: serviceUnavailableResponseSchema,
        },
      },
    },
    async (request, reply) => {
      if (!organisationStoreConfigured()) return reply.status(503).send(organisationStoreNotConfigured())
      const { id } = request.params as { id: string }
      const [org] = await organisationsById([id])
      if (!org) return reply.status(404).send({ error: 'organisation_not_found', message: `No organisation ${id} is held.` })
      const [owners, orgSites] = await Promise.all([
        orgRolesRepository.holdersOf(id, qualified(JINBE, 'owner')), redisRbacRepository.getOrgSites(),
      ])
      return reply.send({
        id, name: org.name, tenant: org.tenant,
        owners,
        sites: [...new Set([JINBE, ...(orgSites[id] ?? [])])],
      })
    },
  )

  // Creating an organisation: its own file. Its API keys, made by staff: another.
  await organisationAdminRoutes(fastify)
  await orgKeysAdminRoutes(fastify)
  // One user's site + org access.
  await userAccessRoutes(fastify)
  // Plug a site: intent, drafts, preview, apply (its own plugin, so its zod-only validation stays local).
  await fastify.register(sitesRoutes, { prefix: '/sites' })
  await fastify.register(gatewayRoutes, { prefix: '/gateway' })

  // Patch user metadata (merge into metadata_public / metadata_admin)
  fastify.patch(
    '/users/:id/metadata',
    {
      ...needs('users.metadata:write'),
      schema: {
        description: 'Merge-patch user metadata_public or metadata_admin. Needs users.metadata:write.',
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        body: {
          type: 'object',
          properties: {
            metadata_public: { type: 'object', additionalProperties: true },
            metadata_admin: { type: 'object', additionalProperties: true },
          },
        },
        response: {
          200: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.setUserMetadata.bind(adminController) as never
  )

  // Set user state (active/inactive)
  fastify.patch(
    '/users/:id/state',
    {
      ...needs('users:disable'),
      schema: {
        description: 'Set user state to active or inactive',
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        body: {
          type: 'object',
          required: ['state'],
          properties: { state: { type: 'string', enum: ['active', 'inactive'] } },
        },
        response: {
          200: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.setUserState.bind(adminController) as never
  )

  // Set user organization
  fastify.patch(
    '/users/:id/organization',
    {
      // Organisation membership (to be merged into PUT /organizations/:o/users/:id/membership).
      ...needs('orgs.members:write'),
      schema: {
        description: "Set or remove a user's primary organization (organization_id). A new one keeps the old primary as one of their organizations; null removes the primary one.",
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        body: {
          type: 'object',
          required: ['organization_id'],
          properties: {
            organization_id: {
              type: 'string',
              format: 'uuid',
              nullable: true,
              description: 'Organization UUID to assign, or null to remove',
            },
          },
        },
        response: {
          200: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.setUserOrganization.bind(adminController) as never
  )

  // ===========================================================================
  // User Group Management (Kratos-backed)
  // ===========================================================================

  // Get user's groups
  fastify.get(
    '/users/:email/groups',
    {
      ...needs('access:read'),
      schema: {
        description:
          "Get a user's groups and available groups for assignment",
        tags: ['admin'],
        params: zodToJsonSchema(userEmailParamSchema),
        response: {
          200: userGroupsResponseJsonSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.getUserGroups.bind(adminController)
  )

  // Update user's groups: removing only needs groups.members:revoke; adding needs groups.members:write
  // and a step-up (require-membership-change.ts).
  fastify.put(
    '/users/:email/groups',
    {
      ...needs('groups.members:revoke', { alsoAccepts: ['groups.members:write'] }),
      preHandler: requireMembershipChange,
      schema: {
        description:
          "Replace a user's platform groups. Removing only needs groups.members:revoke; adding needs groups.members:write and a second factor proven within 15 minutes. Groups must exist in the model.",
        tags: ['admin'],
        params: zodToJsonSchema(userEmailParamSchema),
        body: updateUserGroupsBodyJsonSchema,
        response: {
          200: userGroupsUpdateResponseJsonSchema,
          400: badRequestResponseSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.updateUserGroups.bind(adminController) as never
  )

}
