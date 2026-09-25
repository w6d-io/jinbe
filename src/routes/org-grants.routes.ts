import type { FastifyInstance } from 'fastify'
import { orgGrantsController } from '../controllers/org-grants.controller.js'
import { requireOrgAdmin } from '../middleware/require-org-permission.js'
import {
  organizationIdParamJsonSchema,
  organizationUserIdParamJsonSchema,
} from '../schemas/organization-user.schema.js'
import {
  badRequestResponseSchema,
  forbiddenResponseSchema,
  notFoundResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * Org grants, mounted under /api/organizations/:organizationId. The org's own admin or super_admin
 * only; what may be granted is then OPA's `can_grant` (see the controller).
 *
 * GET /grants                 - { grants: { email: [group] } } for this org
 * PUT /users/:id/grants       - replace one member's grants in this org
 * GET /assignable-groups      - the groups the caller may grant here, with their roles per service
 */

const errorSchema = { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' } } }

const groupListSchema = { type: 'array', items: { type: 'string' } }

export async function orgGrantsRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', requireOrgAdmin('organizationId'))

  fastify.get('/grants', {
    schema: {
      description: "Groups handed out in this organization, per member (data.org_grants[org]). Org admin or super_admin.",
      tags: ['organization-users'],
      params: organizationIdParamJsonSchema,
      response: {
        200: {
          type: 'object',
          properties: { grants: { type: 'object', additionalProperties: groupListSchema } },
        },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        503: serviceUnavailableResponseSchema,
      },
    },
  }, orgGrantsController.list.bind(orgGrantsController) as never)

  fastify.put('/users/:id/grants', {
    schema: {
      description:
        "Replace a member's grants in this organization. Every group being added must pass OPA " +
        'data.rbac.delegation.can_grant; one refusal refuses the whole write (403 with `refused`) and ' +
        'nothing is written. 503 when OPA_URL / OPA_TOKEN are unset, 502 when OPA does not answer.',
      tags: ['organization-users'],
      params: organizationUserIdParamJsonSchema,
      body: {
        type: 'object',
        required: ['groups'],
        properties: { groups: groupListSchema },
      },
      response: {
        200: { type: 'object', properties: { email: { type: 'string' }, groups: groupListSchema } },
        400: badRequestResponseSchema,
        401: unauthorizedResponseSchema,
        403: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' },
            refused: {
              type: 'array',
              items: { type: 'object', properties: { group: { type: 'string' }, reason: { type: 'string' } } },
            },
          },
        },
        404: notFoundResponseSchema,
        502: errorSchema,
        503: serviceUnavailableResponseSchema,
      },
    },
  }, orgGrantsController.replace.bind(orgGrantsController) as never)

  fastify.get('/assignable-groups', {
    schema: {
      description:
        'Groups the caller may grant in this organization (OPA data.rbac.delegation.assignable_groups, kept ' +
        "to this org's service bundle), each with its roles per service.",
      tags: ['organization-users'],
      params: organizationIdParamJsonSchema,
      response: {
        200: {
          type: 'object',
          properties: {
            groups: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  services: { type: 'object', additionalProperties: groupListSchema },
                },
              },
            },
          },
        },
        401: unauthorizedResponseSchema,
        403: forbiddenResponseSchema,
        502: errorSchema,
        503: serviceUnavailableResponseSchema,
      },
    },
  }, orgGrantsController.assignable.bind(orgGrantsController) as never)
}
