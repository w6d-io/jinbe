import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { mcpGate } from '../mcp/settings.js'
import { personalKeyService } from '../services/personal-key.service.js'
import { handleError } from '../controllers/api-key.controller.js'
import { decorateKeyViews } from '../services/api-key-views.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import {
  personalKeyCreateBodyJsonSchema,
  personalKeyCreateBodySchema,
  personalKeyListResponseJsonSchema,
  personalKeySecretViewJsonSchema,
  personalScopeCatalogResponseJsonSchema,
} from '../schemas/api-key.schema.js'
import {
  forbiddenResponseSchema,
  notFoundResponseSchema,
  serviceUnavailableResponseSchema,
  unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { open } from '../policy/route-access.js'

/**
 * The caller's own API keys — /api/me/api-keys (services/personal-key.service.ts).
 *
 * 404 on every route unless MCP is on: DELEGATED_TOKENS_ENABLED (the deployment's ceiling) and the
 * administrator's switch (mcp/settings.ts, Settings → AI assistants). A person only: a machine caller has no
 * personal keys, and a delegated caller never reaches here (middleware/delegation-gate.ts).
 *
 * GET    /            - the caller's keys (no secrets)
 * GET    /scopes      - the permissions the caller may narrow a key to (what they hold, concrete)
 * POST   /            - create one: all my permissions, or a chosen subset (returns the key ONCE)
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

const bodyWithDetails = { type: 'object', properties: { error: { type: 'string' }, message: { type: 'string' }, details: { type: 'object', additionalProperties: true } } }

export async function personalKeyRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', personOnly)

  fastify.get('/', {
    ...open('self'),
    schema: {
      description: 'Your personal API keys (no secrets).',
      tags: ['api-keys'],
      response: { 200: personalKeyListResponseJsonSchema, 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFoundResponseSchema },
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
    ...open('self'),
    schema: {
      description:
        'The permissions you may narrow a personal key to: the jinbe permissions you hold (from your groups), ' +
        'concrete — a wildcard is expanded to the permissions the routes declare, never offered as such — and ' +
        'never one that only opens routes a key may not use. Grouped by resource. 403 when your groups may not use MCP.',
      tags: ['api-keys'],
      response: {
        200: personalScopeCatalogResponseJsonSchema,
        400: bodyWithDetails,
        401: unauthorizedResponseSchema,
        403: bodyWithDetails,
        404: notFoundResponseSchema,
        503: serviceUnavailableResponseSchema,
      },
    },
  }, async (request, reply) => {
    try {
      return reply.send({ scopes: await personalKeyService.scopes({ email: request.userContext!.email }) })
    } catch (err) {
      return handleError(err, reply)
    }
  })

  fastify.post('/', {
    ...open('self'),
    schema: {
      description:
        'Create a personal API key acting as you, bound to no organization. Without `scopes` it carries all your ' +
        'permissions as they are at each call; with them, that subset of what you hold (still re-checked at each ' +
        "call). Expiry at most 30 days, or the administrator's shorter maximum (the default). Returns the key ONCE. " +
        '403 when your groups may not use MCP.',
      tags: ['api-keys'],
      body: personalKeyCreateBodyJsonSchema,
      response: { 201: personalKeySecretViewJsonSchema, 400: bodyWithDetails, 401: unauthorizedResponseSchema, 403: bodyWithDetails, 404: notFoundResponseSchema, 503: serviceUnavailableResponseSchema },
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
          details: { label: body.label, scopes: result.scopes, all_permissions: result.all_permissions, kind: 'personal', expires_at: result.expires_at },
          source: 'jinbe-api',
        })
        .catch(() => {})
      return reply.status(201).send(result)
    } catch (err) {
      return handleError(err, reply)
    }
  })

  fastify.delete('/:clientId', {
    ...open('self'),
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
          details: { kind: 'personal', all_permissions: revoked.all_permissions },
          source: 'jinbe-api',
        })
        .catch(() => {})
      return reply.status(204).send()
    } catch (err) {
      return handleError(err, reply)
    }
  })
}

