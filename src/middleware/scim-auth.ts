import { FastifyRequest, FastifyReply } from 'fastify'
import { scimTokenService, type ScimTokenPrincipal } from '../services/scim-token.service.js'
import { auditEventService } from '../services/audit-event.service.js'

/**
 * SCIM bearer-token authentication (SCIM provisioning spec §3).
 *
 * SCIM routes never see the Kratos session cookie nor the K8s TokenReview —
 * the ONLY accepted credential is a long-lived bearer token minted by
 * scim-token.service (SHA-256 hash in Redis, constant-time compare). The
 * /scim/v2 prefix is on the require-auth public-route bypass; THIS hook is the
 * gate, registered as the first hook of every SCIM route, fail-closed 401
 * with an RFC 7644 error body when the token is missing or invalid.
 */

export const SCIM_ERROR_URN = 'urn:ietf:params:scim:api:messages:2.0:Error'
export const SCIM_CONTENT_TYPE = 'application/scim+json'

declare module 'fastify' {
  interface FastifyRequest {
    /** Set by scimAuth when a valid SCIM bearer token was presented. */
    scimToken?: ScimTokenPrincipal
  }
}

/** RFC 7644 §3.12 error body — `status` is a STRING per the RFC examples. */
export function scimErrorBody(status: number, detail: string, scimType?: string) {
  return {
    schemas: [SCIM_ERROR_URN],
    ...(scimType ? { scimType } : {}),
    detail,
    status: String(status),
  }
}

/** Send an RFC 7644 error response with the SCIM media type. */
export function sendScimError(
  reply: FastifyReply,
  status: number,
  detail: string,
  scimType?: string
) {
  return reply
    .status(status)
    .header('Content-Type', SCIM_CONTENT_TYPE)
    .send(scimErrorBody(status, detail, scimType))
}

/** `Authorization: Bearer <token>` → token, or null. */
function extractBearerToken(header?: string): string | null {
  if (!header) return null
  const match = /^Bearer\s+(.+)$/i.exec(header.trim())
  return match ? match[1].trim() : null
}

export async function scimAuth(request: FastifyRequest, reply: FastifyReply) {
  const path = (request.url || '').split('?')[0]
  const token = extractBearerToken(request.headers.authorization)
  const principal = token ? await scimTokenService.verify(token) : null

  if (!principal) {
    auditEventService.emit({
      category: 'access',
      verb:     'deny',
      target:   `${request.method} ${path}`,
      result:   'denied',
      actor:    { email: null, ip: request.ip, ua: (request.headers['user-agent'] as string) || null },
      method:   request.method,
      path,
      source:   'scim',
      reason:   token ? 'scim_token_invalid' : 'scim_token_missing',
    }).catch(() => {})
    return reply
      .status(401)
      .header('WWW-Authenticate', 'Bearer realm="scim"')
      .header('Content-Type', SCIM_CONTENT_TYPE)
      .send(scimErrorBody(401, 'Valid SCIM bearer token required.'))
  }

  request.scimToken = principal
}
