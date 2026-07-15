import { FastifyRequest, FastifyReply } from 'fastify'
import { opaService } from '../services/opa.service.js'
import { auditEventService } from '../services/audit-event.service.js'

/**
 * Middleware factory: scopes an org-parameterised route to organisations the
 * caller is actually entitled to administer.
 *
 * MUST run AFTER requireServiceAdmin (which populates request.rbacInfo and has
 * already rejected callers with no permission for the org's service).
 *
 * Two-tier authority, preserving legacy while adding delegated scoping:
 *  - A caller resolved to the wildcard `*` (global super_admin or a service
 *    admin whose role is `*`) keeps UNRESTRICTED reach across the service —
 *    the pre-delegation behaviour, unchanged.
 *  - Any other caller (e.g. a delegated org admin holding `org:manage_users`
 *    but not `*`) is confined to `manageable_orgs`: the request org must be one
 *    they are a member of AND administer. This is what stops an org admin of
 *    one org reaching a sibling org in the same service (tenant isolation).
 *
 * FAIL-CLOSED: manageable_orgs is resolved by OPA from OPAL data by email;
 * opaService.manageableOrgs returns `[]` on any OPA error, so an unreachable
 * OPA denies rather than grants.
 */
export function requireManageableOrg(paramName = 'organizationId') {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email
    const route = `${request.method} ${(request.url || '').split('?')[0]}`
    const rbacInfo = request.rbacInfo

    // requireServiceAdmin must have run first and populated rbacInfo.
    if (!rbacInfo) {
      request.log.warn(
        { email, route },
        '[requireManageableOrg] no rbacInfo — requireServiceAdmin must run first'
      )
      return reply.status(500).send({
        error: 'Internal Server Error',
        message: 'Authorization context not initialized',
      })
    }

    // Legacy full access: a global/service wildcard admin keeps unrestricted
    // reach across the service (super_admin, or a service role resolving to *).
    if (rbacInfo.permissions.includes('*')) {
      return
    }

    if (!email || email === 'unknown') {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    }

    const organizationId = (request.params as Record<string, string>)[paramName]

    // Resolved server-side from OPAL data by email — never trusted from input.
    const manageable = await opaService.manageableOrgs(email)

    if (!manageable.includes(organizationId)) {
      request.log.warn(
        { email, organizationId, manageable },
        '[requireManageableOrg] access denied — org not administered by caller'
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
          reason: 'not_org_admin',
          source: 'jinbe-api',
        })
        .catch(() => {})

      return reply.status(403).send({
        error: 'Forbidden',
        message: `You may only manage organizations you administer ('${organizationId}' is not one)`,
      })
    }
  }
}
