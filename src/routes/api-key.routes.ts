import { FastifyInstance } from 'fastify'
import { apiKeyController } from '../controllers/api-key.controller.js'
import { requireServiceAdmin } from '../middleware/require-service-admin.js'
import {
  organizationIdParamJsonSchema,
  apiKeyClientIdParamJsonSchema,
  apiKeyCreateBodyJsonSchema,
  apiKeySecretViewJsonSchema,
  apiKeyViewJsonSchema,
  apiKeyListResponseJsonSchema,
} from '../schemas/api-key.schema.js'
import {
  badRequestResponseSchema,
  forbiddenResponseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * Organization-scoped API-key (Hydra OAuth2 client) management.
 *
 * Mounted under /api/organizations/:organizationId. Every route requires the
 * caller to be an admin of the target organization (OPA-resolved, via
 * requireServiceAdmin) — i.e. an authenticated Kratos admin (Hydra spec §4).
 *
 * POST   /api-keys            - create a key (returns client_secret ONCE)
 * GET    /api-keys            - list keys (no secrets)
 * GET    /api-keys/:clientId  - get one key (no secret)
 * DELETE /api-keys/:clientId  - revoke a key
 */
export async function apiKeyRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', requireServiceAdmin())

  fastify.post(
    '/api-keys',
    {
      schema: {
        description:
          'Create an API key (Hydra client_credentials client) for this organization. ' +
          'Returns client_id + client_secret ONCE. organization_id is enforced server-side.',
        tags: ['api-keys'],
        params: organizationIdParamJsonSchema,
        body: apiKeyCreateBodyJsonSchema,
        response: {
          201: apiKeySecretViewJsonSchema,
          400: badRequestResponseSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
        },
      },
    },
    apiKeyController.create.bind(apiKeyController)
  )

  fastify.get(
    '/api-keys',
    {
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
    '/api-keys/:clientId',
    {
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

/**
 * Internal (no-auth) API-key routes for cluster-internal callers.
 *
 * Mounted under /api/internal — Oathkeeper does NOT route this prefix from the
 * public internet. Upstream services use it to resolve an injected X-Client-Id
 * header to its owning organization (Hydra spec §5.3 Option A).
 */
export async function apiKeyInternalRoutes(fastify: FastifyInstance) {
  fastify.get(
    '/oauth-clients/:clientId/organization',
    {
      schema: {
        description: 'Resolve a client_id to its owning organization and scopes (internal only).',
        tags: ['api-keys-internal'],
        params: {
          type: 'object',
          required: ['clientId'],
          properties: { clientId: { type: 'string' } },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              organization_id: { type: 'string' },
              scopes: { type: 'array', items: { type: 'string' } },
            },
          },
          404: notFoundResponseSchema,
        },
      },
    },
    apiKeyController.resolveOrganization.bind(apiKeyController)
  )
}
