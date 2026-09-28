import { FastifyReply, FastifyRequest } from 'fastify'
import { apiKeyService, ApiKeyError } from '../services/api-key.service.js'
import { HydraApiError, HydraUnavailableError } from '../services/hydra.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { recordApiKeyUse } from '../audit/record.js'
import { touchApiKeyUse } from '../services/api-key-last-used.js'
import { decorateKeyViews } from '../services/api-key-views.js'
import { AuthzUnavailableError } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import {
  ApiKeyCreateBody,
  apiKeyCreateBodySchema,
} from '../schemas/api-key.schema.js'
import { clientIp } from '../utils/client-ip.js'

export function handleError(err: unknown, reply: FastifyReply): FastifyReply {
  if (err instanceof AuthzUnavailableError) {
    // The scope catalog is what the caller holds, asked of OPA: "could not tell" is never a 400.
    return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: 'Unable to verify authorization. Please try again later.' })
  }
  if (err instanceof ApiKeyError) {
    return reply.status(err.statusCode).send({
      error: err.statusCode === 404 ? 'Not Found' : err.statusCode === 403 ? 'Forbidden' : 'Bad Request',
      message: err.message,
      ...(err.details ? { details: err.details } : {}),
    })
  }
  if (err instanceof HydraUnavailableError) {
    // Not deployed or down: say so, instead of a bare 500 the console can only call "Internal Server Error".
    reply.log.warn({ err: err.message }, '[api-keys] OAuth2 server unreachable')
    return reply.status(503).send({
      error: 'oauth2_server_unavailable',
      message: 'API keys are unavailable: the OAuth2 server (Hydra) cannot be reached on this deployment.',
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
        callerEmail: request.userContext?.email ?? '',
      })

      auditEventService
        .emit({
          type: 'api_key.created',
          actor: { email: request.userContext?.email, ip: clientIp(request) },
          target: { type: 'oauth2_client', id: result.client_id },
          details: { organizationId, label: body.label, scopes: result.scopes, expires_at: result.expires_at },
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
    const data = await decorateKeyViews(request, await apiKeyService.list(organizationId))
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
      const [view] = await decorateKeyViews(request, [await apiKeyService.get(organizationId, clientId)])
      return reply.send(view)
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
      // The introspection path: the first resolution per client per day is recorded (apikey.used).
      void recordApiKeyUse(clientId, resolved.organization_id ?? null)
      touchApiKeyUse(clientId)
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
          actor: { email: request.userContext?.email, ip: clientIp(request) },
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
