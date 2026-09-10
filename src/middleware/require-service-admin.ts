import { FastifyRequest, FastifyReply } from 'fastify'
import { rightsOf, type HeldRights } from '../services/authorization-model.service.js'
import { env } from '../config/index.js'
import { auditEventService } from '../services/audit-event.service.js'

/**
 * Middleware factory: requires the caller to hold at least one permission IN the organisation named
 * by the route parameter `paramName`.
 *
 * Resolved from the same two documents the engine decides against — a group gives roles in a named
 * organisation or in every one, and each role carries permissions. No role list is written here.
 *
 * What this replaced asked an engine for `data.rbac.user_info`, a path that stopped existing when the
 * model became `strada.authz`; it answered nothing, so every route behind this gate refused with a
 * 503 that read like an outage. It also resolved the organisation's id to a registered service name
 * through Redis first, because the retired model keyed grants per service. This one keys them per
 * organisation, so there is nothing to translate and one store fewer to be up.
 */
export function requireServiceAdmin(paramName = 'organizationId') {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email
    // The immutable identity is what rights are keyed on; the address is carried for the log and the
    // audit trail only.
    const subject = request.userContext?.id
    const route = `${request.method} ${(request.url || '').split('?')[0]}`

    request.log.debug({ email, subject, route }, '[requireServiceAdmin] start')

    if (!subject || subject === 'unknown') {
      request.log.debug('[requireServiceAdmin] no identity — 401')
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    }

    // DEV MODE: bypass
    if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
      request.log.debug({ email }, '[requireServiceAdmin] DEV_BYPASS_AUTH — model not read')
      request.rbacInfo = {
        email: email ?? subject,
        groups: ['super_admins', 'admins'],
        roles: ['super_admin', 'admin'],
        permissions: ['*'],
      }
      return
    }

    const organizationId = (request.params as Record<string, string>)[paramName]

    let held: HeldRights
    try {
      held = await rightsOf(subject, organizationId)
    } catch (err) {
      // "Holds nothing" and "I could not tell" are opposite facts. Refusing with 403 here would read
      // as a missing right; 503 says the model could not be read, which is what happened.
      request.log.warn(
        { subject, organizationId, err },
        '[requireServiceAdmin] the authorization model could not be read'
      )
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    }

    const rbacInfo = { email: email ?? subject, ...held }

    request.log.debug(
      {
        email,
        organizationId,
        groups: rbacInfo.groups,
        roles: rbacInfo.roles,
        permissions: rbacInfo.permissions,
      },
      '[requireServiceAdmin] OPA resolved RBAC'
    )

    request.rbacInfo = rbacInfo

    // OPA resolves permissions for the target service — if the user has
    // none, they are not authorized for this organization.
    if (rbacInfo.permissions.length === 0) {
      request.log.warn(
        { email, organizationId, groups: rbacInfo.groups, roles: rbacInfo.roles },
        '[requireServiceAdmin] access denied — no permissions for service'
      )
      auditEventService
        .emit({
          category: 'access',
          verb: 'deny',
          target: route,
          result: 'denied',
          actor: {
            id: subject,
            email: email ?? null,
            ip: request.ip,
            ua: (request.headers['user-agent'] as string) || null,
          },
          method: request.method,
          path: (request.url || '').split('?')[0],
          reason: 'not_service_admin',
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(403).send({
        error: 'Forbidden',
        message: `Admin access required for organization '${organizationId}'`,
      })
    }

    request.log.debug(
      { email, organizationId, roles: rbacInfo.roles, permissions: rbacInfo.permissions },
      '[requireServiceAdmin] access granted'
    )
  }
}

/**
 * Middleware factory: requires a specific OPA-resolved permission on the
 * rbacInfo already populated by requireServiceAdmin.
 *
 * Must run AFTER requireServiceAdmin (which populates request.rbacInfo).
 * Checks permissions resolved by OPA for the target organization — no
 * hardcoded group/role list.
 *
 * @param requiredPermission - permission string to check (e.g. 'rbac:write').
 *   The wildcard permission '*' always grants access.
 */
export function requireServicePermission(requiredPermission: string) {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email
    const route = `${request.method} ${(request.url || '').split('?')[0]}`
    const rbacInfo = request.rbacInfo

    request.log.debug(
      { email, route, requiredPermission, rbacInfo },
      '[requireServicePermission] checking OPA-resolved permissions'
    )

    if (!rbacInfo) {
      request.log.warn(
        { email, route },
        '[requireServicePermission] no rbacInfo — requireServiceAdmin must run first'
      )
      return reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Authorization context not initialized',
      })
    }

    const hasPermission =
      rbacInfo.permissions.includes('*') ||
      rbacInfo.permissions.includes(requiredPermission)

    if (!hasPermission) {
      request.log.warn(
        {
          email,
          route,
          requiredPermission,
          groups: rbacInfo.groups,
          roles: rbacInfo.roles,
          permissions: rbacInfo.permissions,
        },
        '[requireServicePermission] access denied — missing permission'
      )
      auditEventService
        .emit({
          category: 'access',
          verb: 'deny',
          target: route,
          result: 'denied',
          actor: {
            email: email ?? null,
            ip: request.ip,
            ua: (request.headers['user-agent'] as string) || null,
          },
          method: request.method,
          path: (request.url || '').split('?')[0],
          reason: `missing_permission:${requiredPermission}`,
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(403).send({
        error: 'Forbidden',
        message: `Permission '${requiredPermission}' required`,
      })
    }

    request.log.debug(
      { email, requiredPermission, permissions: rbacInfo.permissions },
      '[requireServicePermission] access granted'
    )
  }
}
