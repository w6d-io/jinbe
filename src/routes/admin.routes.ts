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
        body: userCreateJsonSchema,
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
