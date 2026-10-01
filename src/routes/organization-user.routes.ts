import { FastifyInstance } from 'fastify'
import { organizationUserController } from '../controllers/organization-user.controller.js'
import { needs } from '../policy/route-access.js'
import {
  organizationIdParamJsonSchema,
  organizationUserIdParamJsonSchema,
  organizationUserCreateBodyJsonSchema,
  organizationUserUpdateBodyJsonSchema,
} from '../schemas/organization-user.schema.js'
import {
  kratosIdentityJsonSchema,
} from '../schemas/admin.schema.js'
import {
  forbiddenResponseSchema,
  notFoundResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/** Decided per organisation by this plugin's gate, never by a platform guard (route-access.ts). */
const ORG = { org: 'organizationId' }

/**
 * Organization-scoped user management routes
 *
 * Authorization via OPA/OPAL: the caller's grants in the target organization (org roles assigned
 * there, or the every-org map of their platform roles) — the org clause, per route.
 *
 * GET    /users     - List users in organization
 * GET    /users/:id - Get user by ID in organization
 * POST   /users     - Create user in organization
 * PUT    /users/:id - Update user in organization
 * DELETE /users/:id - Remove user from organization (membership only; identity kept)
 * PUT    /users/:id/membership - Add an existing user to organization
 */
export async function organizationUserRoutes(fastify: FastifyInstance) {
  // Each route's gate is the org clause for that request, attached by the route-access hook from
  // its `org` declaration (policy/route-access.ts).

  fastify.get(
    '/users',
    {
      ...needs('org.members:read', ORG),
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
      ...needs('org.members:read', ORG),
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
      ...needs('org.members:write', ORG),
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
      ...needs('org.members:write', ORG),
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
      ...needs('org.members:write', ORG),
      schema: {
        description:
          'Remove a user from this organization. Only this membership is dropped: the identity, its other organizations and its site access are kept.',
        tags: ['organization-users'],
        params: organizationUserIdParamJsonSchema,
        response: {
          204: { type: 'null', description: 'Membership removed' },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
          503: serviceUnavailableResponseSchema,
        },
      },
    },
    organizationUserController.deleteUser.bind(organizationUserController)
  )

  fastify.put(
    '/users/:id/membership',
    {
      ...needs('org.members:write', ORG),
      schema: {
        description:
          'Add an existing user to this organization, keeping their other memberships. Idempotent.',
        tags: ['organization-users'],
        params: organizationUserIdParamJsonSchema,
        response: {
          200: kratosIdentityJsonSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
          503: serviceUnavailableResponseSchema,
        },
      },
    },
    organizationUserController.addMembership.bind(organizationUserController)
  )

}
