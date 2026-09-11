import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/env.js'
import { auditEventService } from '../services/audit-event.service.js'
import { platformRightsOf } from '../services/authorization-model.service.js'
import { permits } from '../services/authorization-resolution.js'
import { STEP_UP_MAX_AGE_MS, canProveSecondFactor, secondFactorIsFresh } from '../services/step-up.js'

/** Reading the administration API. `admin:write` does not imply it — a role needing both carries both. */
const READ_ADMIN = 'admin:read'
import type { UserRbacInfo } from '../services/authorization-resolution.js'


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
 * What the caller holds across the platform, or null when that could not be established.
 *
 * The distinction is the whole point of this file: "holds nothing" is a decision and answers 403,
 * "cannot be established" is an outage and answers 503. Letting the second pass as the first would
 * turn every failure of the model into a permission somebody would go and ask about.
 *
 * Read from the model the engine decides against, keyed on the immutable identity. It used to come
 * from Kratos metadata through a cache — the previous model — so what let somebody into the console
 * was decided by something nobody enforces.
 */
async function resolveOrNull(subjectId: string, email: string): Promise<UserRbacInfo | null> {
  try {
    return { email, ...(await platformRightsOf(subjectId)) }
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
      // The model's shape, not the previous one's. It stamped `*`, which covers nothing here: a
      // permission is `<resource>:<verb>` and there is no wildcard — so local development would
      // have been refused by the very gate this bypass exists to skip.
      groups: ['platform-admin'],
      roles: ['platform-admin'],
      permissions: ['admin:read', 'admin:write'],
    }
    return
  }

  const subject = request.userContext?.id
  if (!subject || subject === 'unknown') {
    return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
  }

  const rbacInfo = await resolveOrNull(subject, email)

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

  // A DECLARED PERMISSION, not a list of group names. This matched `super_admins` or `admins` by
  // name, so a group named like an admin group waved somebody through whatever it granted, and a
  // group granting everything under another name did not. Reading the administration API needs
  // `admin:read`, and the coverage rule admits `admin:read` held on any ancestor.
  if (!permits(rbacInfo.permissions, READ_ADMIN)) {
    request.log.warn(
      {
        email,
        subject,
        permissions: rbacInfo.permissions,
        required: READ_ADMIN,
      },
      'Access denied — the caller does not hold the permission this API requires'
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
    const subject = request.userContext?.id

    if (!subject || subject === 'unknown' || !email || email === 'unknown') {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    }

    // Fetch RBAC info from OPAL if not already fetched
    if (!request.rbacInfo) {
      const rbacInfo = await resolveOrNull(subject, email)

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

    // Named groups still, because this factory is CALLED with a list of names by its callers. The
    // holder's groups now come from the model, so the names it matches are the model's — but naming
    // a group is still weaker than naming a permission, and this is the last gate that does it.
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
/** Writing the administration API. Verbs do not imply one another, so this is not `admin:read`. */
const WRITE_ADMIN = 'admin:write'

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
      // The model's shape, not the previous one's. It stamped `*`, which covers nothing here: a
      // permission is `<resource>:<verb>` and there is no wildcard — so local development would
      // have been refused by the very gate this bypass exists to skip.
      groups: ['platform-admin'],
      roles: ['platform-admin'],
      permissions: ['admin:read', 'admin:write'],
    }
    return
  }

  const subject = request.userContext?.id
  if (!subject || subject === 'unknown') {
    return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
  }

  const rbacInfo = await resolveOrNull(subject, email)

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

  // Writing the administration API. `admin:write` covers every write under it, and the roles that
  // carry it are declared in the model rather than matched by name.
  if (!permits(rbacInfo.permissions, WRITE_ADMIN)) {
    request.log.warn(
      {
        email,
        permissions: rbacInfo.permissions,
        required: WRITE_ADMIN,
      },
      'Access denied — the caller does not hold the permission this write requires'
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
 * hold a SECOND FACTOR proven within the last 15 minutes — measured on the aal2
 * method's own completed_at, not the session's first-factor authenticated_at.
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

export async function requireRecentMfa(request: FastifyRequest, reply: FastifyReply) {
  const stepUp = {
    aal: request.userContext?.aal,
    secondFactorAt: request.userContext?.secondFactorAt,
    authVia: request.userContext?.authVia,
  }
  if (!secondFactorIsFresh(stepUp)) {
    const unprovable = !canProveSecondFactor(stepUp)
    // Emit the currently-silent step-up denial (A2).
    auditEventService.emit({
      category: 'access',
      kind:     'change',
      verb:     'deny',
      target:   `${request.method} ${(request.url || '').split('?')[0]}`,
      result:   'denied',
      severity: 'warn',
      reason:   unprovable ? 'step_up_unavailable' : 'reauth_required',
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
    if (unprovable) {
      return reply.status(422).send({
        error: 'step_up_unavailable',
        message:
          'This action requires a second factor proven in a browser session. The credential you presented cannot carry one.',
        hint: 'Sign in to the console in a browser and retry there.',
      })
    }
    return reply.status(422).send({
      error: 'reauth_required',
      message:
        'This action requires a recent second factor. Re-verify two-factor authentication (TOTP) within the last 15 minutes and retry.',
      stepUp: { requiredAal: 'aal2', maxAgeMinutes: STEP_UP_MAX_AGE_MS / 60000 },
      hint: 'Re-verify at /login?aal=aal2&refresh=true, then retry.',
    })
  }
}
