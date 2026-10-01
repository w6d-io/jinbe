import { FastifyInstance } from 'fastify'
import { apiKeyController } from '../controllers/api-key.controller.js'
import { needs } from '../policy/route-access.js'
import { apiKeyScopesController } from '../controllers/api-key-scopes.controller.js'
import {
  organizationIdParamJsonSchema,
  apiKeyClientIdParamJsonSchema,
  apiKeyCreateBodyJsonSchema,
  apiKeySecretViewJsonSchema,
  apiKeyViewJsonSchema,
  apiKeyListResponseJsonSchema,
  apiKeyPolicyJsonSchema,
  scopeCatalogResponseJsonSchema,
} from '../schemas/api-key.schema.js'
import {
  badRequestResponseSchema,
  forbiddenResponseSchema,
  notFoundResponseSchema,
  unauthorizedResponseSchema,
  serviceUnavailableResponseSchema,
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
 * POST   /api-keys            - create a key (returns client_secret ONCE)
 * GET    /api-keys            - list keys (no secrets)
 * GET    /api-keys/scopes     - the scopes a key may be given: permissions of this org's sites the caller holds
 * GET    /api-key-policy      - DEPRECATED: personal keys are no longer org-bound, the value is ignored
 * PUT    /api-key-policy      - allow or forbid them
 * GET    /api-keys/:clientId  - get one key (no secret)
 * DELETE /api-keys/:clientId  - revoke a key
 */
// The 400 carries WHY (e.g. details.invalid_scopes / details.allowed_scopes): the shared
// badRequestResponseSchema would strip it on serialization.
const apiKeyBadRequestResponseSchema = {
  ...badRequestResponseSchema,
  properties: { ...badRequestResponseSchema.properties, details: { type: 'object', additionalProperties: true } },
}

export async function apiKeyRoutes(fastify: FastifyInstance) {
  // Each route's gate is the org clause for its declared permission (org.keys:*), attached by the
  // route-access hook from its `org` declaration.

  fastify.post(
    '/api-keys',
    {
      ...needs('org.keys:write', ORG),
      schema: {
        description:
          'Create an API key (Hydra client_credentials client) for this organization. ' +
          'Returns client_id + client_secret ONCE. organization_id is enforced server-side.',
        tags: ['api-keys'],
        params: organizationIdParamJsonSchema,
        body: apiKeyCreateBodyJsonSchema,
        response: {
          201: apiKeySecretViewJsonSchema,
          400: apiKeyBadRequestResponseSchema,
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

  // The console offers these as choices instead of a free-text field it could only correct from a
  // refused create's details.allowed_scopes. Same guard as every key route: the catalogue is shown to
  // whoever may create a key in this organization, and is what THEY hold here.
  fastify.get(
    '/api-keys/scopes',
    {
      ...needs('org.keys:read', ORG),
      schema: {
        description:
          'The scopes an API key of this organization may be given: the permissions required by routes of the sites ' +
          'this organization runs that the caller holds here (site grants and org grants), under API_KEY_ALLOWED_SCOPES ' +
          'when set. Never a wildcard. Sorted by scope, each with the sites that ask for it.',
        tags: ['api-keys'],
        params: organizationIdParamJsonSchema,
        response: {
          200: scopeCatalogResponseJsonSchema,
          401: unauthorizedResponseSchema,
          403: forbiddenResponseSchema,
          503: serviceUnavailableResponseSchema,
        },
      },
    },
    apiKeyScopesController.catalog.bind(apiKeyScopesController)
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
