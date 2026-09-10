import { FastifyRequest, FastifyReply } from 'fastify'
import { auditEventService } from '../services/audit-event.service.js'
import { env } from '../config/index.js'

/**
 * What a caller may actually present, listed from what this deployment enables.
 *
 * A 401 that enumerates the accepted credentials and omits one sends the reader looking for a
 * method that was never going to work — so the list is derived rather than written down.
 */
function acceptedCredentials(): string {
  const accepted: string[] = []
  if (env.AUTH_COOKIE_ENABLED !== false) accepted.push('a valid ory_kratos_session cookie')
  if (env.AUTH_BEARER_ENABLED) accepted.push('an OIDC access token as a Bearer credential')
  accepted.push('a Kubernetes ServiceAccount token as a Bearer credential')
  return accepted.length > 1
    ? `${accepted.slice(0, -1).join(', ')} or ${accepted[accepted.length - 1]}`
    : accepted[0]
}

/**
 * Routes that don't require authentication (exact prefix match)
 */
const PUBLIC_ROUTES = [
  '/api/health',
  '/api/whoami',
  '/api/opa/bundle',
  '/api/oathkeeper/rules',
  // [P0-1] Narrowed from '/api/webhooks' (a startsWith prefix that made every
  // sub-path public) to the EXACT Kratos webhook path. The handler still
  // self-authenticates via a shared secret; this only lifts the session gate.
  '/api/webhooks/kratos',
  // Its own credential, checked by its own hook: a machine token, hashed at rest. Listed here for
  // the same reason the SCIM prefix is — the session gate would refuse it before that hook runs.
  '/api/directory',
  // Same arrangement, and the same trap: the policy engine presents a machine token, which this
  // gate refuses before the route's own hook is ever reached. Listing it here does not make it
  // public — it makes it guarded by the credential it actually takes.
  '/api/opa',
  '/docs',
  '/docs/',
  // SCIM provisioning endpoints enforce their OWN bearer-token auth (hashed
  // tokens in rbac:scim:tokens, constant-time compare — see middleware/
  // scim-auth.ts, registered as the first hook of every /scim/v2 route).
  // Bypassing the session gate here does NOT open them: scimAuth fails closed
  // 401 with an RFC 7644 error body when the token is missing or invalid.
  '/scim/v2',
]

/**
 * Dynamic public route patterns (OPAL data endpoints)
 * Matches both canonical /admin/rbac/* and compat /admin/rbac/develop/*
 */
const PUBLIC_ROUTE_PATTERNS = [
  /^\/api\/admin\/rbac\/(develop\/)?opal-datasource/,
  /^\/api\/admin\/rbac\/(develop\/)?bindings/,
  /^\/api\/admin\/rbac\/(develop\/)?opal\//,
]

/**
 * Check if a path matches any public route
 */
export function isPublicRoute(path: string): boolean {
  if (PUBLIC_ROUTES.some((route) => path === route || path.startsWith(`${route}/`))) {
    return true
  }
  return PUBLIC_ROUTE_PATTERNS.some((pattern) => pattern.test(path))
}

/**
 * Authentication middleware
 *
 * Blocks requests without valid authentication (except for public routes).
 * Must be registered AFTER extractIdentity middleware.
 */
export async function requireAuth(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const path = (request.url || '').split('?')[0]

  if (isPublicRoute(path)) {
    return
  }

  if (!request.userContext || request.userContext.email === 'unknown') {
    // Distinguish "no credential at all" from "a credential was presented but
    // rejected" (expired/revoked cookie, bad SA token — sessionError is set by
    // extractIdentity). Clients use `code` to decide between a plain login
    // redirect and a forced re-auth (login?refresh=true) that regenerates the
    // broken session.
    const credentialRejected = !!request.sessionError
    auditEventService.emit({
      category: 'access',
      verb:     'deny',
      target:   `${request.method} ${path}`,
      result:   'denied',
      actor:    { email: null, ip: request.ip, ua: request.headers['user-agent'] as string || null },
      method:   request.method,
      path,
      reason:   credentialRejected ? 'session_invalid' : 'unauthenticated',
    }).catch(() => {})
    return reply.status(401).send({
      error: 'Unauthorized',
      code: credentialRejected ? 'session_invalid' : 'authentication_required',
      message: `Valid authentication required. Provide ${acceptedCredentials()}.`,
    })
  }
}
