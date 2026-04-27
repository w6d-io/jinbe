import { FastifyRequest, FastifyReply } from 'fastify'
import { auditEventService } from '../services/audit-event.service.js'

/**
 * Routes that don't require authentication (exact prefix match)
 */
const PUBLIC_ROUTES = [
  '/api/health',
  '/api/whoami',
  '/api/opa/bundle',
  '/api/oathkeeper/rules',
  '/api/webhooks',
  '/docs',
  '/docs/',
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
 * Exact internal hostnames trusted for auth bypass.
 * SECURITY: Uses exact match — NOT substring. Host header spoofing mitigated.
 * Extend via INTERNAL_TRUSTED_HOSTS env var (comma-separated).
 */
const INTERNAL_HOSTS = new Set([
  'jinbe.w6d-ops',
  'jinbe.w6d-ops:8080',
  'jinbe.w6d-ops.svc.cluster.local',
  'jinbe.w6d-ops.svc.cluster.local:8080',
  // Inject from env: INTERNAL_TRUSTED_HOSTS=auth-w6d-jinbe:8080,auth-w6d-jinbe
  ...(process.env.INTERNAL_TRUSTED_HOSTS || '').split(',').map(h => h.trim()).filter(Boolean),
])

/**
 * Check if request is from internal cluster (exact host match only)
 */
export function isInternalRequest(request: FastifyRequest): boolean {
  const host = request.headers.host || ''
  return INTERNAL_HOSTS.has(host)
}

/**
 * Check if a path matches any public route
 */
function isPublicRoute(path: string): boolean {
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
  reply: FastifyReply
) {
  // Bypass auth for internal cluster requests (exact host match)
  if (isInternalRequest(request)) {
    return
  }

  const path = (request.url || '').split('?')[0]

  // Skip auth for public routes
  if (isPublicRoute(path)) {
    return
  }

  // Check if user is authenticated
  if (!request.userContext || request.userContext.email === 'unknown') {
    auditEventService.emit({
      category: 'access',
      verb:     'deny',
      target:   `${request.method} ${path}`,
      result:   'denied',
      actor:    { email: null, ip: request.ip, ua: request.headers['user-agent'] as string || null },
      method:   request.method,
      path,
      reason:   'unauthenticated',
    }).catch(() => {})
    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'Valid authentication required. Please provide a valid ory_kratos_session cookie.',
    })
  }
}
