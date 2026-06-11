import { FastifyReply, FastifyRequest } from 'fastify'
import { apiKeyService, ApiKeyError } from '../services/api-key.service.js'
import { HydraApiError } from '../services/hydra.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import {
  ApiKeyCreateBody,
  apiKeyCreateBodySchema,
} from '../schemas/api-key.schema.js'

function handleError(err: unknown, reply: FastifyReply): FastifyReply {
  if (err instanceof ApiKeyError) {
    return reply.status(err.statusCode).send({
      error: err.statusCode === 404 ? 'Not Found' : 'Bad Request',
      message: err.message,
      ...(err.details ? { details: err.details } : {}),
    })
  }
  if (err instanceof HydraApiError) {
    // Surface upstream auth-server failures as 502 — do not leak internals.
    return reply.status(502).send({
      error: 'Bad Gateway',
      message: 'OAuth2 server request failed',
    })
  }
  throw err
}

export class ApiKeyController {
  /**
   * Create an API key (Hydra client_credentials client) for an organization.
   * POST /api/organizations/:organizationId/api-keys
   * Returns the client_id + client_secret ONCE.
   */
  async create(
    request: FastifyRequest<{
      Params: { organizationId: string }
      Body: ApiKeyCreateBody
    }>,
    reply: FastifyReply
  ) {
    const { organizationId } = request.params
    const body = apiKeyCreateBodySchema.parse(request.body)

    try {
      const result = await apiKeyService.create({
        organizationId,
        body,
        createdBy: request.userContext?.id,
      })

      auditEventService
        .emit({
          type: 'api_key.created',
          actor: { email: request.userContext?.email, ip: request.ip },
          target: { type: 'oauth2_client', id: result.client_id },
          details: { organizationId, label: body.label, scopes: result.scopes },
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(201).send(result)
    } catch (err) {
      return handleError(err, reply)
    }
  }

  /**
   * List API keys for an organization (never returns secrets).
   * GET /api/organizations/:organizationId/api-keys
   */
  async list(
    request: FastifyRequest<{ Params: { organizationId: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId } = request.params
    const data = await apiKeyService.list(organizationId)
    return reply.send({ data, total: data.length })
  }

  /**
   * Get one API key within an organization.
   * GET /api/organizations/:organizationId/api-keys/:clientId
   */
  async get(
    request: FastifyRequest<{ Params: { organizationId: string; clientId: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId, clientId } = request.params
    try {
      return reply.send(await apiKeyService.get(organizationId, clientId))
    } catch (err) {
      return handleError(err, reply)
    }
  }

  /**
   * Internal: resolve a client_id to its owning organization + scopes.
   * GET /api/internal/oauth-clients/:clientId/organization
   *
   * For upstream services (Hydra spec §5.3 Option A) to map an injected
   * X-Client-Id header to a tenant. Intended for the private network only —
   * it is NOT behind requireServiceAdmin, so it must not be exposed publicly
   * (Oathkeeper does not route /api/internal externally).
   */
  async resolveOrganization(
    request: FastifyRequest<{ Params: { clientId: string } }>,
    reply: FastifyReply
  ) {
    const { clientId } = request.params
    try {
      const resolved = await apiKeyService.resolveOrganization(clientId)
      if (!resolved) {
        return reply.status(404).send({ error: 'Not Found', message: 'Unknown client_id' })
      }
      return reply.send(resolved)
    } catch (err) {
      return handleError(err, reply)
    }
  }

  /**
   * Revoke an API key.
   * DELETE /api/organizations/:organizationId/api-keys/:clientId
   */
  async revoke(
    request: FastifyRequest<{ Params: { organizationId: string; clientId: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId, clientId } = request.params
    try {
      await apiKeyService.revoke(organizationId, clientId)

      auditEventService
        .emit({
          type: 'api_key.revoked',
          actor: { email: request.userContext?.email, ip: request.ip },
          target: { type: 'oauth2_client', id: clientId },
          details: { organizationId },
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(204).send()
    } catch (err) {
      return handleError(err, reply)
    }
  }
}

export const apiKeyController = new ApiKeyController()
