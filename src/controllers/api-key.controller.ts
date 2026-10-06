import { FastifyReply, FastifyRequest } from 'fastify'
import { apiKeyService, ApiKeyError } from '../services/api-key.service.js'
import { HydraApiError, HydraUnavailableError } from '../services/hydra.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { decorateKeyViews } from '../services/api-key-views.js'
import { AuthzUnavailableError } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { clientIp } from '../utils/client-ip.js'

export function handleError(err: unknown, reply: FastifyReply): FastifyReply {
  if (err instanceof AuthzUnavailableError) {
    // OPA could not be asked: "could not tell" is never a 400.
    return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: 'Unable to verify authorization. Please try again later.' })
  }
  if (err instanceof ApiKeyError) {
    return reply.status(err.statusCode).send({
      error: err.statusCode === 404 ? 'Not Found' : err.statusCode === 403 ? 'Forbidden' : err.statusCode === 503 ? 'Service Unavailable' : 'Bad Request',
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

/** An organisation's keys, from inside it: list, read, revoke (staff create them: org-keys-admin.routes.ts). */
export class ApiKeyController {
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
