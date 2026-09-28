import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { mcpGate } from '../mcp/settings.js'
import { personalKeyService } from '../services/personal-key.service.js'
import { handleError } from '../controllers/api-key.controller.js'
import { decorateKeyViews } from '../services/api-key-views.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import {
  apiKeyListResponseJsonSchema,
  apiKeySecretViewJsonSchema,
  personalKeyCreateBodyJsonSchema,
  personalKeyCreateBodySchema,
  personalScopesQuerySchema,
  scopeCatalogResponseJsonSchema,
} from '../schemas/api-key.schema.js'
import {
  forbiddenResponseSchema,
  notFoundResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'

/**
 * The caller's own API keys — /api/me/api-keys (services/personal-key.service.ts).
 *
 * 404 on every route unless MCP is on: DELEGATED_TOKENS_ENABLED (the deployment's ceiling) and the
 * administrator's switch (mcp/settings.ts, Settings → AI assistants). A person only: a machine caller has no
 * personal keys, and a delegated caller never reaches here (middleware/delegation-gate.ts).
 *
 * GET    /            - the caller's keys (no secrets)
 * GET    /scopes      - ?organization_id=: the scopes the caller may give a key there (what they hold)
 * POST   /            - create one (returns client_secret ONCE)
 * DELETE /:clientId   - revoke one of the caller's keys
 */
async function personOnly(request: FastifyRequest, reply: FastifyReply) {
  const gate = await mcpGate()
  if (gate.off === 'unavailable') {
    return reply.status(503).send({ error: 'settings_unavailable', message: 'The AI assistant settings cannot be read right now.' })
  }
  if (!gate.on) {
    const message = gate.off === 'deployment'
      ? 'Personal API keys are not enabled on this deployment.'
      : 'Personal API keys are turned off by an administrator.'
    return reply.status(404).send({ error: 'Not Found', message })
  }
  const via = request.userContext?.authVia
  if (via === 'machine' || via === 'delegated') {
    return reply.status(403).send({ error: 'Forbidden', message: 'Personal API keys are managed by a person, in a browser.' })
  }
}

const personalKeySecretJsonSchema = {
  ...apiKeySecretViewJsonSchema,
  properties: {
    ...apiKeySecretViewJsonSchema.properties,
    kind: { type: 'string', enum: ['personal'] },
    key: { type: 'string', description: 'Shown only once: stk_mcp_<client_id>.<secret>, the header value an MCP client sends' },
  },
}

const bodyWithDetails = { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' }, details: { type: 'object', additionalProperties: true } } }

export async function personalKeyRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', personOnly)

  fastify.get('/', {
    schema: {
      description: 'Your personal API keys (no secrets).',
      tags: ['api-keys'],
      response: { 200: apiKeyListResponseJsonSchema, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema },
    },
  }, async (request, reply) => {
    try {
      const data = await decorateKeyViews(request, await personalKeyService.list(request.userContext!.id))
      return reply.send({ data, total: data.length })
    } catch (err) {
      return handleError(err, reply)
    }
  })

  fastify.get('/scopes', {
    schema: {
      description:
        'The scopes you may give a personal key in one organization: the same catalog as its machine keys ' +
        '(GET /api/organizations/:organizationId/api-keys/scopes), computed from what YOU hold there. ' +
        '403 when you are not a member of it.',
      tags: ['api-keys'],
      querystring: {
        type: 'object',
        required: ['organization_id'],
        properties: { organization_id: { type: 'string', format: 'uuid', description: 'The organization the key would act in' } },
      },
      response: {
        200: scopeCatalogResponseJsonSchema,
        400: bodyWithDetails,
        401: unauthorizedResponseSchema,
        403: bodyWithDetails,
        404: notFoundResponseSchema,
        503: serviceUnavailableResponseSchema,
      },
    },
  }, async (request, reply) => {
    const { organization_id } = personalScopesQuerySchema.parse(request.query)
    try {
      return reply.send({ scopes: await personalKeyService.scopes({ email: request.userContext!.email }, organization_id) })
    } catch (err) {
      return handleError(err, reply)
    }
  })

  fastify.post('/', {
    schema: {
      description:
        'Create a personal API key acting as you in ONE organization: scopes among the permissions you hold there, ' +
        "expiry at most 30 days, or the administrator's shorter maximum (the default). Returns client_secret ONCE. " +
        '403 when the organization forbids personal keys or is outside the AI assistant scope.',
      tags: ['api-keys'],
      body: personalKeyCreateBodyJsonSchema,
      response: { 201: personalKeySecretJsonSchema, 400: bodyWithDetails, 401: unauthorizedResponseSchema, 403: bodyWithDetails, 404: notFoundResponseSchema, 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    const body = personalKeyCreateBodySchema.parse(request.body)
    const uc = request.userContext!
    try {
      const result = await personalKeyService.create({ id: uc.id, email: uc.email }, body)
      auditEventService
        .emit({
          type: 'api_key.created',
          actor: auditActor(request),
          target: { type: 'oauth2_client', id: result.client_id },
          details: { organizationId: body.organization_id, label: body.label, scopes: result.scopes, kind: 'personal', expires_at: result.expires_at },
          source: 'jinbe-api',
        })
        .catch(() => {})
      return reply.status(201).send(result)
    } catch (err) {
      return handleError(err, reply)
    }
  })

  fastify.delete('/:clientId', {
    schema: {
      description: 'Revoke one of your personal API keys. Its tokens stop at the next introspection.',
      tags: ['api-keys'],
      params: { type: 'object', required: ['clientId'], properties: { clientId: { type: 'string', minLength: 1 } } },
      response: { 204: { type: 'null' }, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema },
    },
  }, async (request: FastifyRequest<{ Params: { clientId: string } }>, reply) => {
    try {
      const revoked = await personalKeyService.revoke(request.userContext!.id, request.params.clientId)
      auditEventService
        .emit({
          type: 'api_key.revoked',
          actor: auditActor(request),
          target: { type: 'oauth2_client', id: revoked.client_id },
          details: { organizationId: revoked.organization_id, kind: 'personal' },
          source: 'jinbe-api',
        })
        .catch(() => {})
      return reply.status(204).send()
    } catch (err) {
      return handleError(err, reply)
    }
  })
}

