import { FastifyInstance } from 'fastify'
import { organizationUserController } from '../controllers/organization-user.controller.js'
import { requireServiceAdmin } from '../middleware/require-service-admin.js'
import {
  organizationIdParamJsonSchema,
  organizationUserIdParamJsonSchema,
  organizationUserCreateBodyJsonSchema,
  organizationUserUpdateBodyJsonSchema,
} from '../schemas/organization-user.schema.js'
import { kratosIdentityJsonSchema } from '../schemas/admin.schema.js'
import {
  forbiddenResponseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * Organization-scoped user management routes
 *
 * Authorization via OPA/OPAL: requires admin role for the target
 * organization or super_admin (global *).
 *
 * GET    /users     - List users in organization
 * GET    /users/:id - Get user by ID in organization
 * POST   /users     - Create user in organization
 * PUT    /users/:id - Update user in organization
 * DELETE /users/:id - Delete user from organization
 */
export async function organizationUserRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', requireServiceAdmin())

  fastify.get(
    '/users',
    {
      schema: {
        description: 'List users belonging to this organization',
        tags: ['organization-users'],
        params: organizationIdParamJsonSchema,
        querystring: {
          type: 'object',
          properties: {
            page_size: { type: 'string' },
            credentials_identifier: { type: 'string' },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              data: { type: 'array', items: kratosIdentityJsonSchema },
              total: { type: 'number' },
            },
          },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
        },
      },
    },
    organizationUserController.listUsers.bind(organizationUserController)
  )

  fastify.get(
    '/users/:id',
    {
      schema: {
        description: 'Get a user by ID within this organization',
        tags: ['organization-users'],
        params: organizationUserIdParamJsonSchema,
        response: {
          200: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    organizationUserController.getUser.bind(organizationUserController)
  )

  fastify.post(
    '/users',
    {
      schema: {
        description: 'Create a new user in this organization',
        tags: ['organization-users'],
        params: organizationIdParamJsonSchema,
        body: organizationUserCreateBodyJsonSchema,
        response: {
          201: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
        },
      },
    },
    organizationUserController.createUser.bind(organizationUserController)
  )

  fastify.put(
    '/users/:id',
    {
      schema: {
        description: 'Update a user within this organization',
        tags: ['organization-users'],
        params: organizationUserIdParamJsonSchema,
        body: organizationUserUpdateBodyJsonSchema,
        response: {
          200: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    organizationUserController.updateUser.bind(organizationUserController)
  )

  fastify.delete(
    '/users/:id',
    {
      schema: {
        description: 'Delete a user from this organization',
        tags: ['organization-users'],
        params: organizationUserIdParamJsonSchema,
        response: {
          204: { type: 'null', description: 'User deleted' },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    organizationUserController.deleteUser.bind(organizationUserController)
  )
}
