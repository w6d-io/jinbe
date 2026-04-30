import { FastifyInstance } from 'fastify'
import { adminController } from '../controllers/admin.controller.js'
import { requireAdmin, requireSuperAdmin } from '../middleware/require-admin.js'
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
