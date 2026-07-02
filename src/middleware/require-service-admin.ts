import { FastifyRequest, FastifyReply } from 'fastify'
import { opaService } from '../services/opa.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { env } from '../config/index.js'
import { auditEventService } from '../services/audit-event.service.js'

/**
 * Middleware factory: requires the caller to have permissions for the
 * service identified by the route parameter `paramName`.
 *
 * Uses OPA/OPAL to resolve RBAC — passes organizationId as the `app` param
 * so OPA resolves groups → roles → permissions for that specific service.
 *
 * Access is granted when OPA returns at least one permission for the user
 * on the target service. Role/permission definitions live entirely in OPA
 * policy — no hardcoded role list here.
 */
export function requireServiceAdmin(paramName = 'organizationId') {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email
    const route = `${request.method} ${(request.url || '').split('?')[0]}`

    request.log.debug({ email, route }, '[requireServiceAdmin] start')

    if (!email || email === 'unknown') {
      request.log.debug('[requireServiceAdmin] no email — 401')
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    }

    // DEV MODE: bypass
    if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
      request.log.debug({ email }, '[requireServiceAdmin] DEV_BYPASS_AUTH — skipping OPA')
      request.rbacInfo = {
        email,
        groups: ['super_admins', 'admins'],
        roles: ['super_admin', 'admin'],
        permissions: ['*'],
      }
      return
    }

    const organizationId = (request.params as Record<string, string>)[paramName]

    // Resolve org UUID → RBAC service name so OPA gets a registered service
    // (service names must match ^[a-z0-9_]+$ — UUIDs with hyphens are rejected)
    const serviceName = await redisRbacRepository.getServiceForOrg(organizationId) ?? organizationId

    request.log.debug(
      { email, organizationId, serviceName, paramName },
      '[requireServiceAdmin] querying OPA with resolved service name'
    )

    const rbacInfo = await opaService.getUserInfo(email, serviceName)

    if (!rbacInfo) {
      request.log.warn(
        { email, organizationId },
        '[requireServiceAdmin] OPA returned null — service unavailable'
      )
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    }

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
            email,
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
