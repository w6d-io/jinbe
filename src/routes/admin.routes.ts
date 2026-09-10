import { FastifyInstance } from 'fastify'
import { adminController } from '../controllers/admin.controller.js'
import { requireAdmin, requireSuperAdmin } from '../middleware/require-admin.js'
import { realtimeService } from '../services/realtime.service.js'
import { accessReviewService } from '../services/access-review.service.js'
import {
  enforcedConfiguration,
  EnforcedConfigUnavailableError,
} from '../services/enforced-config.service.js'
import {
  userIdParamSchema,
  usersQuerySchema,
  kratosIdentityJsonSchema,
  kratosIdentityListJsonSchema,
  userCreateJsonSchema,
  userUpdateJsonSchema,
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
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { assignableGroupsFor, authorizationModel } from '../services/authorization-model.service.js'
import { requirePlatformPermission } from '../middleware/require-platform-permission.js'
import { allOrganisations, organisationStoreConfigured } from '../services/organisation-store.js'

/**
 * Admin routes for user management via Kratos Admin API
 *
 * All routes require `admin:*` permission (enforced by OPAL)
 *
 * GET    /users     - List all users
 * GET    /users/:id - Get user by ID
 * POST   /users     - Create new user
 * PUT    /users/:id - Update user by ID
 * DELETE /users/:id - Delete user by ID
 */
export async function adminRoutes(fastify: FastifyInstance) {
  // Require admin group membership for all routes in this plugin
  fastify.addHook('preHandler', requireAdmin)

  // Real-time change stream (Server-Sent Events). Auth: inherits the plugin's
  // requireAdmin (Kratos session) — same gate as every other /admin route. It
  // emits a minimal {type} signal on any RBAC/directory change; the client
  // reacts by refetching through the normal auth'd endpoints (no data on wire).
  fastify.get('/events', (request, reply) => {
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

  // List all users
  fastify.get(
    '/users',
    {
      schema: {
        description: 'List all users from Kratos identity service',
        tags: ['admin'],
        querystring: zodToJsonSchema(usersQuerySchema),
        response: {
          200: {
            type: 'object',
            properties: {
              data: kratosIdentityListJsonSchema,
              next_page_token: { type: 'string', nullable: true },
            },
          },
          401: unauthorizedResponseSchema,
        },
      },
    },
    adminController.listUsers.bind(adminController)
  )

  // Directory stats (cached counts — total/active/perGroup/perOrg)
  fastify.get(
    '/stats',
    {
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
  // pattern), fail-closed on a directory/group read error. Inherits the plugin's
  // requireAdmin preHandler. Response is additive/permissive so the kuma
  // AccessReview contract fields are never stripped.
  fastify.get(
    '/access-review',
    {
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
      preHandler: requirePlatformPermission('admin.organisation:read'),
      schema: {
        description: 'Every organisation the directory holds. Needs admin.organisation:read.',
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
                  },
                },
              },
            },
          },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          503: {
            type: 'object',
            properties: { error: { type: 'string' }, message: { type: 'string' } },
          },
        },
      },
    },
    async (request, reply) => {
      if (!organisationStoreConfigured()) {
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'No organisation directory is configured.',
        })
      }
      try {
        const organizations = await allOrganisations()
        return reply.send({
          organizations: organizations.map(({ id, name, tenant }) => ({ id, name, tenant })),
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

  /**
   * The authorization model the engine decides against: what each group grants, and where.
   *
   * The screen showing this read a catalogue from Redis, laid out as a column per SERVICE — the
   * previous model's shape. It listed groups the policy does not define and omitted every group it
   * does, and it offered to EDIT them, which wrote where nothing reads.
   */
  fastify.get(
    '/authorization-model',
    {
      preHandler: requirePlatformPermission('admin:read'),
      schema: {
        description: 'What each group grants, per organisation, and what each role carries.',
        tags: ['admin'],
        response: {
          200: {
            type: 'object',
            properties: {
              groups: { type: 'object', additionalProperties: true },
              roles: { type: 'object', additionalProperties: true },
            },
          },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          503: {
            type: 'object',
            properties: { error: { type: 'string' }, message: { type: 'string' } },
          },
        },
      },
    },
    async (request, reply) => {
      try {
        return reply.send(await authorizationModel())
      } catch (err) {
        // An empty model and an unreadable one look the same on a screen, and only one of them
        // means "nobody grants anything".
        request.log.error({ err }, 'The authorization model could not be read')
        return reply.status(503).send({
          error: 'authorization_model_unavailable',
          message: 'The authorization model could not be read.',
        })
      }
    },
  )

  /**
   * The groups this caller may hand out, from the model the engine decides against.
   *
   * The screen that assigns groups was offering a catalogue from the previous model — names the
   * policy does not define, so assigning one wrote a membership that granted nothing while looking
   * like it had worked. And it greyed the privileged ones by asking whether the session carried a
   * role literally called `super_admin`, a name this model does not have: global power is a group
   * granting in EVERY organisation, read off the shape.
   *
   * Both answers come from here now, so the screen offers exactly what the mutation would accept.
   */
  fastify.get(
    '/assignable-groups',
    {
      schema: {
        description: 'The groups the caller may assign, and whether they may assign at all.',
        tags: ['admin'],
        response: {
          200: {
            type: 'object',
            properties: {
              groups: { type: 'array', items: { type: 'string' } },
              mayAssign: { type: 'boolean' },
            },
          },
          401: unauthorizedResponseSchema,
          503: {
            type: 'object',
            properties: { error: { type: 'string' }, message: { type: 'string' } },
          },
        },
      },
    },
    async (request, reply) => {
      const subject = request.userContext?.id
      if (!subject || subject === 'unknown') {
        return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
      }
      try {
        const groups = await assignableGroupsFor(subject)
        return reply.send({ groups, mayAssign: groups.length > 0 })
      } catch (err) {
        // An empty list reads as "you may assign nothing", which is a legitimate answer. "I could
        // not read the model" is not, and must not look like one.
        request.log.error({ err }, 'The authorization model could not be read')
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'Unable to read the authorization model. Please try again later.',
        })
      }
    },
  )

  // What actually decides, read from where it actually lives — the rule resources the edge is fed
  // from and the ConfigMaps the policy engine loads. Read-only on purpose: the source of truth is a
  // repository synced by Argo, so a screen that edited it in place would invite a change the next
  // sync reverts without telling anybody.
  fastify.get(
    '/enforced-config',
    {
      schema: {
        description:
          'The enforced authorization configuration as YAML, read from the cluster objects the engines load. Read-only.',
        tags: ['admin'],
        response: {
          200: {
            type: 'object',
            properties: {
              documents: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    kind: { type: 'string' },
                    name: { type: 'string' },
                    namespace: { type: 'string' },
                    decides: { type: 'string' },
                    yaml: { type: 'string' },
                    // Declared, or the serializer removes them without a word — which is exactly
                    // how the memberships column came to be empty on a route that resolved it.
                    routes: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          method: { type: 'string' },
                          path: { type: 'string' },
                          class: { type: 'string' },
                          permission: { type: 'string' },
                        },
                      },
                    },
                    roles: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          role: { type: 'string' },
                          permissions: { type: 'array', items: { type: 'string' } },
                        },
                      },
                    },
                    grants: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          subject: { type: 'string' },
                          email: { type: 'string' },
                          held: {
                            type: 'array',
                            items: {
                              type: 'object',
                              properties: {
                                organisation: { type: 'string' },
                                organisationName: { type: 'string' },
                                roles: { type: 'array', items: { type: 'string' } },
                                // The hop that explains the rest. Declared, or the serializer drops
                                // it without a word.
                                viaGroups: { type: 'array', items: { type: 'string' } },
                              },
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          503: {
            type: 'object',
            properties: { error: { type: 'string' }, message: { type: 'string' } },
          },
        },
      },
    },
    async (request, reply) => {
      try {
        return reply.send({ documents: await enforcedConfiguration() })
      } catch (err) {
        if (err instanceof EnforcedConfigUnavailableError) {
          // 503 and never an empty list: a screen showing no rules would say nothing is enforced,
          // which is the one thing that is certainly false.
          request.log.error({ err }, 'Could not read the enforced configuration')
          return reply.status(503).send({
            error: 'Service Unavailable',
            message: 'The enforced configuration could not be read from the cluster.',
          })
        }
        throw err
      }
    },
  )

  // Substring search over identities (email + name), cached in-memory.
  // Declared before /users/:id; Fastify's router prefers the static segment.
  fastify.get(
    '/users/search',
    {
      schema: {
        description: 'Search identities by email or name substring (cached; no directory walk)',
        tags: ['admin'],
        querystring: {
          type: 'object',
          properties: { q: { type: 'string' }, limit: { type: 'string' } },
        },
        response: {
          200: {
            type: 'object',
            properties: { data: { type: 'array', items: { type: 'object', additionalProperties: true } } },
          },
          401: unauthorizedResponseSchema,
        },
      },
    },
    adminController.searchUsers.bind(adminController)
  )

  // Get user by ID
  fastify.get(
    '/users/:id',
    {
      schema: {
        description: 'Get user by ID from Kratos identity service',
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        response: {
          200: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.getUser.bind(adminController)
  )

  // Create new user
  fastify.post(
    '/users',
    {
      schema: {
        description: 'Create new user in Kratos identity service',
        tags: ['admin'],
        body: {
          oneOf: [
            // Simplified flat format from kuma UI
            {
              type: 'object',
              required: ['email'],
              properties: {
                email: { type: 'string', format: 'email' },
                name: { type: 'string' },
                groups: { type: 'array', items: { type: 'string' } },
                sendInvite: { type: 'boolean' },
              },
              additionalProperties: false,
            },
            // Full Kratos format
            userCreateJsonSchema,
          ],
        },
        response: {
          201: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
        },
      },
    },
    adminController.createUser.bind(adminController)
  )

  // Update user by ID
  fastify.put(
    '/users/:id',
    {
      schema: {
        description: 'Update user by ID in Kratos identity service',
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        body: userUpdateJsonSchema,
        response: {
          200: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.updateUser.bind(adminController)
  )

  // Patch user metadata (merge into metadata_public / metadata_admin)
  fastify.patch(
    '/users/:id/metadata',
    {
      schema: {
        description: 'Merge-patch user metadata_public or metadata_admin',
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
      schema: {
        description: 'Set or remove the organization_id on a user (Kratos JSON Patch)',
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

  // Delete user by ID
  fastify.delete(
    '/users/:id',
    {
      schema: {
        description: 'Delete user by ID from Kratos identity service',
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        response: {
          204: {
            type: 'null',
            description: 'User deleted successfully',
          },
          401: unauthorizedResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.deleteUser.bind(adminController)
  )

  // ===========================================================================
  // User Group Management (Kratos-backed)
  // ===========================================================================

  // Get user's groups
  fastify.get(
    '/users/:email/groups',
    {
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

  // Update user's groups (requires super_admin)
  fastify.put(
    '/users/:email/groups',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description:
          "Update a user's group memberships. Requires super_admin group. Groups must exist in groups.json.",
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

  // Send recovery email to user (one-click password reset)
  fastify.post(
    '/users/:id/recovery-email',
    {
      schema: {
        description: 'Send a recovery email to the user. Triggers Kratos self-service recovery flow.',
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        response: {
          204: { type: 'null', description: 'Recovery email sent' },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.sendRecoveryEmail.bind(adminController) as never
  )

  // List sessions for an identity (proxied from Kratos admin — never exposed directly to browser)
  fastify.get(
    '/users/:id/sessions',
    {
      schema: {
        description: 'List active sessions for a Kratos identity. Requires admin.',
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        response: {
          200: { type: 'array', items: { type: 'object', additionalProperties: true } },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.listUserSessions.bind(adminController) as never
  )

  // Revoke a single session
  fastify.delete(
    '/sessions/:sessionId',
    {
      schema: {
        description: 'Revoke a session by ID. Requires admin.',
        tags: ['admin'],
        params: { type: 'object', properties: { sessionId: { type: 'string' } }, required: ['sessionId'] },
        response: {
          204: { type: 'null' },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
        },
      },
    },
    adminController.revokeSession.bind(adminController) as never
  )

  // Revoke all sessions for an identity
  fastify.delete(
    '/users/:id/sessions',
    {
      schema: {
        description: 'Revoke all sessions for a Kratos identity. Requires admin.',
        tags: ['admin'],
        params: zodToJsonSchema(userIdParamSchema),
        response: {
          204: { type: 'null' },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    adminController.revokeAllUserSessions.bind(adminController) as never
  )
}
