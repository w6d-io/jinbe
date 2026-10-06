import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { needs } from '../policy/route-access.js'
import { apiKeyService } from '../services/api-key.service.js'
import { scopeCatalog } from '../services/api-key-scopes.js'
import { decorateKeyViews } from '../services/api-key-views.js'
import { organisationsById, organisationStoreConfigured, organisationStoreNotConfigured } from '../services/organisation-store.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { handleError } from '../controllers/api-key.controller.js'
import {
  apiKeyCreateBodyJsonSchema,
  apiKeyCreateBodySchema,
  apiKeyListResponseJsonSchema,
  apiKeySecretViewJsonSchema,
  scopeCatalogResponseJsonSchema,
} from '../schemas/api-key.schema.js'
import {
  badRequestResponseSchema,
  forbiddenResponseSchema,
  notFoundResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * An organisation's API keys, from the platform (mounted under /api/admin):
 *
 *   GET  /organizations/:id/api-keys          orgs:read         its keys (no secrets)
 *   GET  /organizations/:id/api-keys/scopes   orgs.keys:write   what a key of it may be given
 *   POST /organizations/:id/api-keys          orgs.keys:write   make one (the secret is shown once)
 *
 * Made by staff only for now (owner decision 2026-10-06): a key is a machine acting in that
 * organisation on every site serving it. The organisation's own people list and revoke its keys
 * under /api/organizations/:organizationId/api-keys (org.keys:read, org.keys:revoke); they do not
 * create them.
 */

const params = { type: 'object', required: ['id'], properties: { id: { type: 'string', format: 'uuid' } } }
const badRequest = {
  ...badRequestResponseSchema,
  properties: { ...badRequestResponseSchema.properties, details: { type: 'object', additionalProperties: true } },
}
const notFound = { ...notFoundResponseSchema, properties: { ...notFoundResponseSchema.properties, error: { type: 'string' } } }

type OrgRequest = FastifyRequest<{ Params: { id: string } }>

/** 404 when the organisation is not held, 503 without a store; null when it is there. */
async function organisationMissing(request: OrgRequest, reply: FastifyReply): Promise<FastifyReply | null> {
  if (!organisationStoreConfigured()) return reply.status(503).send(organisationStoreNotConfigured())
  const [org] = await organisationsById([request.params.id])
  return org ? null : reply.status(404).send({ error: 'organisation_not_found', message: `No organisation ${request.params.id} is held.` })
}

export async function orgKeysAdminRoutes(fastify: FastifyInstance) {
  fastify.get('/organizations/:id/api-keys', {
    ...needs('orgs:read'),
    schema: {
      description: "An organisation's API keys (no secrets). Needs orgs:read.",
      tags: ['api-keys'],
      params,
      response: { 200: apiKeyListResponseJsonSchema, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFound, 503: serviceUnavailableResponseSchema },
    },
  }, async (request: OrgRequest, reply) => {
    const missing = await organisationMissing(request, reply)
    if (missing) return missing
    try {
      const data = await decorateKeyViews(request, await apiKeyService.list(request.params.id))
      return reply.send({ data, total: data.length })
    } catch (err) {
      return handleError(err, reply)
    }
  })

  fastify.get('/organizations/:id/api-keys/scopes', {
    ...needs('orgs.keys:write'),
    schema: {
      description:
        'What an API key of this organisation may be given, for the sites serving it (never jinbe, kuma or global): each ' +
        'permission a route of those sites asks for, each site role (`role:<site>:<role>`) and each group binding only those ' +
        "sites' roles (`group:<name>`), with what it stands for today, under API_KEY_ALLOWED_SCOPES when set. Sorted by scope.",
      tags: ['api-keys'],
      params,
      response: { 200: scopeCatalogResponseJsonSchema, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFound, 503: serviceUnavailableResponseSchema },
    },
  }, async (request: OrgRequest, reply) => {
    const missing = await organisationMissing(request, reply)
    if (missing) return missing
    return reply.send({ scopes: await scopeCatalog(request.params.id) })
  })

  fastify.post('/organizations/:id/api-keys', {
    ...needs('orgs.keys:write'),
    schema: {
      description:
        'Create an API key (Hydra client_credentials client) of this organisation, valid on every site serving it. Scopes from ' +
        'GET …/api-keys/scopes: permissions, site roles, groups. Returns client_id + client_secret ONCE. Needs orgs.keys:write ' +
        'and a recent second factor.',
      tags: ['api-keys'],
      params,
      body: apiKeyCreateBodyJsonSchema,
      response: {
        201: apiKeySecretViewJsonSchema, 400: badRequest, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFound, 503: serviceUnavailableResponseSchema,
      },
    },
  }, async (request: OrgRequest, reply) => {
    const missing = await organisationMissing(request, reply)
    if (missing) return missing
    const organizationId = request.params.id
    const body = apiKeyCreateBodySchema.parse(request.body)
    try {
      const result = await apiKeyService.create({ organizationId, body, createdBy: request.userContext?.id, callerEmail: request.userContext?.email ?? '' })
      auditEventService.emit({
        type: 'api_key.created',
        actor: auditActor(request),
        target: { type: 'oauth2_client', id: result.client_id },
        details: { organizationId, label: body.label, scopes: result.scopes, expires_at: result.expires_at },
        source: 'jinbe-api',
      }).catch(() => {})
      return reply.status(201).send(result)
    } catch (err) {
      return handleError(err, reply)
    }
  })
}
