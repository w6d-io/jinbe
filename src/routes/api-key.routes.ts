import { FastifyInstance } from 'fastify'
import { apiKeyController } from '../controllers/api-key.controller.js'
import { needs } from '../policy/route-access.js'
import { apiKeyScopesController } from '../controllers/api-key-scopes.controller.js'
import {
  organizationIdParamJsonSchema,
  apiKeyClientIdParamJsonSchema,
  apiKeyViewJsonSchema,
  apiKeyListResponseJsonSchema,
  apiKeyPolicyJsonSchema,
} from '../schemas/api-key.schema.js'
import {
  forbiddenResponseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/** Decided per organisation by this plugin's gate, never by a platform guard (route-access.ts). */
const ORG = { org: 'organizationId' }

/**
 * Organization-scoped API-key (Hydra OAuth2 client) management.
 *
 * Mounted under /api/organizations/:organizationId. Every route requires its `org.keys:*`
 * permission IN THAT organization: an org role assigned there (owner, key_manager, …) or the
 * every-org map of a platform role. Holding it in another organization counts for nothing.
 * Declared in jinbe's route_map with `org_param` so the gateway draws the same org boundary.
 *
 * Keys are created by staff (POST /api/admin/organizations/:id/api-keys, orgs.keys:write,
 * org-keys-admin.routes.ts); the organization lists and revokes them here.
 *
 * GET    /api-keys            - list keys (no secrets)
 * GET    /api-key-policy      - DEPRECATED: personal keys are no longer org-bound, the value is ignored
 * PUT    /api-key-policy      - allow or forbid them
 * GET    /api-keys/:clientId  - get one key (no secret)
 * DELETE /api-keys/:clientId  - revoke a key
 */
export async function apiKeyRoutes(fastify: FastifyInstance) {
  // Each route's gate is the org clause for its declared permission (org.keys:*), attached by the
  // route-access hook from its `org` declaration.

  fastify.get(
    '/api-keys',
    {
      ...needs('org.keys:read', ORG),
      schema: {
        description: 'List API keys belonging to this organization (no secrets).',
        tags: ['api-keys'],
        params: organizationIdParamJsonSchema,
        response: {
          200: apiKeyListResponseJsonSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
        },
      },
    },
    apiKeyController.list.bind(apiKeyController)
  )

  fastify.get(
    '/api-key-policy',
    {
      ...needs('org.keys:read', ORG),
      schema: {
        description: 'DEPRECATED — personal keys are bound to no organization and inherit their holder, so this value is stored but no longer enforced (404 unless delegated tokens are enabled).',
        tags: ['api-keys'],
        params: organizationIdParamJsonSchema,
        response: { 200: apiKeyPolicyJsonSchema, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema },
      },
    },
    apiKeyScopesController.getPolicy.bind(apiKeyScopesController)
  )

  fastify.put(
    '/api-key-policy',
    {
      ...needs('org.keys:write', ORG),
      schema: {
        description: 'DEPRECATED — stored but no longer enforced: personal keys are bound to no organization (MCP is limited by group in the AI assistants setting).',
        tags: ['api-keys'],
        params: organizationIdParamJsonSchema,
        body: apiKeyPolicyJsonSchema,
        response: { 200: apiKeyPolicyJsonSchema, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema },
      },
    },
    apiKeyScopesController.setPolicy.bind(apiKeyScopesController)
  )

  fastify.get(
    '/api-keys/:clientId',
    {
      ...needs('org.keys:read', ORG),
      schema: {
        description: 'Get a single API key within this organization (no secret).',
        tags: ['api-keys'],
        params: apiKeyClientIdParamJsonSchema,
        response: {
          200: apiKeyViewJsonSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    apiKeyController.get.bind(apiKeyController)
  )

  fastify.delete(
    '/api-keys/:clientId',
    {
      ...needs('org.keys:revoke', ORG),
      schema: {
        description: 'Revoke an API key. Deletes the Hydra client; opaque tokens stop on next introspection.',
        tags: ['api-keys'],
        params: apiKeyClientIdParamJsonSchema,
        response: {
          204: { type: 'null', description: 'Key revoked' },
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          404: notFoundResponseSchema,
        },
      },
    },
    apiKeyController.revoke.bind(apiKeyController)
  )
}
