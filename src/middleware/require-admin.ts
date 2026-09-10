import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/env.js'
import { auditEventService } from '../services/audit-event.service.js'
import { rbacResolverService } from '../services/rbac-resolver.service.js'
import type { UserRbacInfo } from '../services/authorization-resolution.js'

/**
 * Admin groups that grant access to protected routes.
 *
 * Canonical names from groups.json: "admins", "super_admins"
 * Also accept legacy/shorthand variants for robustness.
 * Comparison is case-insensitive (see hasAnyGroup).
 */
const ADMIN_GROUPS = ['admins', 'super_admins', 'admin', 'superadmin']

/**
 * Extend FastifyRequest to include RBAC info
 */
declare module 'fastify' {
  interface FastifyRequest {
    rbacInfo?: UserRbacInfo
  }
}

/**
 * Check if user belongs to any of the specified groups
 */
function hasAnyGroup(userGroups: string[], requiredGroups: string[]): boolean {
  return requiredGroups.some((group) =>
    userGroups.some((userGroup) => userGroup.toLowerCase() === group.toLowerCase())
  )
}

/**
 * Authorization middleware for admin routes
 *
 * Requires the user to be a member of 'admin' or 'superadmin' group.
 * Must be registered AFTER extractIdentity and requireAuth middleware.
 *
 * Fetches RBAC info from OPAL and attaches it to request.rbacInfo
 * for downstream handlers.
 *
 * In DEV mode with DEV_BYPASS_AUTH=true, skips OPAL check and grants admin access.
 */
/**
 * What the caller holds, or null when that could not be established.
 *
 * The distinction is the whole point of this file: "holds nothing" is a decision and answers 403,
 * "cannot be established" is an outage and answers 503. Letting the second pass as the first would
 * turn every failure of the model into a permission somebody would go and ask about.
 */
async function resolveOrNull(email: string): Promise<UserRbacInfo | null> {
  try {
    return await rbacResolverService.resolveUserRbac(email, env.APP_NAME)
  } catch {
    return null
  }
}

export async function requireAdmin(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const email = request.userContext?.email

  if (!email || email === 'unknown') {
    // This shouldn't happen if requireAuth is used first
    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'Authentication required',
    })
  }

  // DEV MODE: Bypass OPAL check and grant admin access
  if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
    request.log.warn(
      { email },
      '⚠️  DEV MODE: Admin authorization bypassed'
    )
    request.rbacInfo = {
      email,
      groups: ['super_admins', 'admins'],
      roles: ['super_admin', 'admin'],
      permissions: ['*'],
    }
    return
  }

  // Fetch RBAC info from OPAL
  const rbacInfo = await resolveOrNull(email)

  if (!rbacInfo) {
    request.log.warn(
      { email },
      'Could not resolve what this caller holds — refusing rather than guessing'
    )
    return reply.status(503).send({
      error: 'Service Unavailable',
      message: 'Unable to verify authorization. Please try again later.',
    })
  }

  // Attach RBAC info to request for downstream use
  request.rbacInfo = rbacInfo

  // Check if user is in admin or superadmin group
  if (!hasAnyGroup(rbacInfo.groups, ADMIN_GROUPS)) {
    request.log.warn(
      {
        email,
        groups: rbacInfo.groups,
        requiredGroups: ADMIN_GROUPS,
      },
      'Access denied - user not in admin group'
    )
    auditEventService.emit({
      category: 'access',
      verb:     'deny',
      target:   `${request.method} ${(request.url || '').split('?')[0]}`,
      result:   'denied',
      actor:    { email, ip: request.ip, ua: request.headers['user-agent'] as string || null },
      method:   request.method,
      path:     (request.url || '').split('?')[0],
      reason:   'not_admin',
    }).catch(() => {})
    return reply.status(403).send({
      error: 'Forbidden',
      message: 'Admin or superadmin access required',
    })
  }

  request.log.debug(
    {
      email,
      groups: rbacInfo.groups,
    },
    'Admin access granted'
  )
}

/**
 * Factory function to create a middleware that checks for specific groups
 *
 * @param allowedGroups - Array of group names that grant access
 * @returns Fastify preHandler middleware
 *
 * @example
 * // Require user to be in 'developers' or 'admins' group
 * fastify.get('/protected', { preHandler: requireGroups(['developers', 'admins']) }, handler)
 */
export function requireGroups(allowedGroups: string[]) {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email

    if (!email || email === 'unknown') {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    }

    // Fetch RBAC info from OPAL if not already fetched
    if (!request.rbacInfo) {
      const rbacInfo = await resolveOrNull(email)

      if (!rbacInfo) {
        request.log.warn(
          { email },
          'Could not resolve what this caller holds — refusing rather than guessing'
        )
        return reply.status(503).send({
          error: 'Service Unavailable',
          message: 'Unable to verify authorization. Please try again later.',
        })
      }

      request.rbacInfo = rbacInfo
    }

    // Check if user is in any of the allowed groups
    if (!hasAnyGroup(request.rbacInfo.groups, allowedGroups)) {
      request.log.warn(
        {
          email,
          groups: request.rbacInfo.groups,
          requiredGroups: allowedGroups,
        },
        'Access denied - user not in required group'
      )
      return reply.status(403).send({
        error: 'Forbidden',
        message: `Access requires membership in one of: ${allowedGroups.join(', ')}`,
      })
    }

    request.log.debug(
      {
        email,
        groups: request.rbacInfo.groups,
        allowedGroups,
      },
      'Group-based access granted'
    )
  }
}

/**
 * Super admin groups that grant access to sensitive operations.
 *
 * Canonical name from groups.json: "super_admins"
 * Also accept legacy/shorthand variants for robustness.
 */
const SUPER_ADMIN_GROUPS = ['super_admins', 'superadmin', 'superadmins']

/**
 * Middleware requiring super_admin group membership
 *
 * Use for sensitive operations like changing user groups.
 * More restrictive than requireAdmin - only super_admins allowed.
 */
export async function requireSuperAdmin(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const email = request.userContext?.email

  if (!email || email === 'unknown') {
    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'Authentication required',
    })
  }

  // DEV MODE: Bypass OPAL check and grant super admin access
  if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
    request.log.warn(
      { email },
      '⚠️  DEV MODE: Super admin authorization bypassed'
    )
    request.rbacInfo = {
      email,
      groups: ['super_admins', 'admins'],
      roles: ['super_admin', 'admin'],
      permissions: ['*'],
    }
    return
  }

  // Fetch RBAC info from OPAL
  const rbacInfo = await resolveOrNull(email)

  if (!rbacInfo) {
    request.log.warn(
      { email },
      'Could not resolve what this caller holds — refusing rather than guessing'
    )
    return reply.status(503).send({
      error: 'Service Unavailable',
      message: 'Unable to verify authorization. Please try again later.',
    })
  }

  request.rbacInfo = rbacInfo

  // Check if user is in super_admin group specifically
  if (!hasAnyGroup(rbacInfo.groups, SUPER_ADMIN_GROUPS)) {
    request.log.warn(
      {
        email,
        groups: rbacInfo.groups,
        requiredGroups: SUPER_ADMIN_GROUPS,
      },
      'Access denied - user not in super_admin group'
    )
    auditEventService.emit({
      category: 'access',
      verb:     'deny',
      target:   `${request.method} ${(request.url || '').split('?')[0]}`,
      result:   'denied',
      actor:    { email, ip: request.ip, ua: request.headers['user-agent'] as string || null },
      method:   request.method,
      path:     (request.url || '').split('?')[0],
      reason:   'not_super_admin',
      source: 'jinbe-api',
    }).catch(() => {})
    return reply.status(403).send({
      error: 'Forbidden',
      message: 'Super admin access required to modify user groups',
    })
  }

  request.log.debug(
    {
      email,
      groups: rbacInfo.groups,
    },
    'Super admin access granted'
  )
}

/**
 * Step-up gate (R2), reused by the org-admin roster endpoint: the actor must
 * hold a SECOND FACTOR proven within the last 15 minutes (AAL2 + a fresh
 * authenticated_at from the Kratos session, surfaced on request.userContext).
 * Returns 422 reauth_required (status pinned to 422 so cluster ingress does not
 * strip the body) when the factor is absent or stale. Fail-closed on missing
 * AAL/timestamp. The dev-bypass identity is stamped AAL2, so local dev passes.
 */
// The super-admin gate that read a resolved flag from an engine is gone with the routes it kept:
// the access-rule and service writes that propagated to the gateway at runtime. It asked
// `data.rbac.simulate`, a path that stopped existing when the model became `strada.authz`, so it
// had been refusing every one of those writes in silence.
//
// What decides who may hand out rights now is `rbacService.assertSuperAdmin`, which reads the same
// documents the engine decides against.

const STEP_UP_MAX_AGE_MS = 15 * 60 * 1000
export async function requireRecentMfa(request: FastifyRequest, reply: FastifyReply) {
  const aal = request.userContext?.aal
  const authAt = request.userContext?.authenticatedAt
  const authedMs = authAt ? new Date(authAt).getTime() : 0
  const fresh =
    aal === 'aal2' &&
    !!authedMs &&
    !Number.isNaN(authedMs) &&
    Date.now() - authedMs <= STEP_UP_MAX_AGE_MS
  if (!fresh) {
    // Emit the currently-silent step-up denial (A2).
    auditEventService.emit({
      category: 'access',
      kind:     'change',
      verb:     'deny',
      target:   `${request.method} ${(request.url || '').split('?')[0]}`,
      result:   'denied',
      severity: 'warn',
      reason:   'reauth_required',
      actor:    {
        email: request.userContext?.email ?? null,
        ip: request.ip,
        ua: (request.headers['user-agent'] as string) || null,
        sessionId: request.userContext?.sessionId ?? null,
      },
      requestId: (request.headers['x-request-id'] as string) || null,
      method:   request.method,
      path:     (request.url || '').split('?')[0],
      statusCode: 422,
      source:   'jinbe-api',
    }).catch(() => {})
    return reply.status(422).send({
      error: 'reauth_required',
      message:
        'This action requires a recent second factor. Re-verify two-factor authentication (TOTP) within the last 15 minutes and retry.',
      stepUp: { requiredAal: 'aal2', maxAgeMinutes: STEP_UP_MAX_AGE_MS / 60000 },
      hint: 'Re-verify at /login?aal=aal2&refresh=true, then retry.',
    })
  }
}
