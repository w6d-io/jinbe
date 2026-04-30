import { FastifyRequest, FastifyReply } from 'fastify'
import { opaService } from '../services/opa.service.js'
import { env } from '../config/index.js'
import { auditEventService } from '../services/audit-event.service.js'

const ADMIN_ROLES = ['admin', 'super_admin']

/**
 * Middleware factory: requires the caller to have admin role for the
 * service identified by the route parameter `paramName`.
 *
 * Uses OPA/OPAL to resolve RBAC — passes organizationId as the `app` param
 * so OPA resolves groups → roles → permissions for that specific service.
 *
 * Access is granted when the user has:
 * - `*` permission (super_admin), OR
 * - `admin` role resolved for the target service
 */
export function requireServiceAdmin(paramName = 'organizationId') {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email
    if (!email || email === 'unknown') {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    }

    // DEV MODE: bypass
    if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
      request.rbacInfo = {
        email,
        groups: ['super_admins', 'admins'],
        roles: ['super_admin', 'admin'],
        permissions: ['*'],
      }
      return
    }

    const organizationId = (request.params as Record<string, string>)[paramName]

    // Query OPA with organizationId as the app — resolves RBAC for that service
    const rbacInfo = await opaService.getUserInfo(email, organizationId)

    if (!rbacInfo) {
      request.log.warn(
        { email, organizationId },
        'Failed to fetch RBAC info from OPA - access denied'
      )
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    }

    request.rbacInfo = rbacInfo

    const isAdmin =
      rbacInfo.permissions.includes('*') ||
      rbacInfo.roles.some((r) => ADMIN_ROLES.includes(r))

    if (!isAdmin) {
      request.log.warn(
        { email, organizationId, roles: rbacInfo.roles },
        'Access denied - user not admin for service'
      )
      auditEventService
        .emit({
          category: 'access',
          verb: 'deny',
          target: `${request.method} ${(request.url || '').split('?')[0]}`,
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
      { email, organizationId, roles: rbacInfo.roles },
      'Service admin access granted'
    )
  }
}
