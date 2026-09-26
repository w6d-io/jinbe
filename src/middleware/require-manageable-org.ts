import { FastifyRequest, FastifyReply } from 'fastify'
import { memberOrgs } from '../authz/opa.js'
import { denyAudit } from '../audit/deny.js'

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
 *    but not `*`) is confined to the organisations OPA says they belong to
 *    (`rbac.caller_organizations`, the membership the org layer reads). This is
 *    what stops an org admin of one org reaching a sibling org (tenant isolation).
 *
 * FAIL-CLOSED: OPA unreachable → 503, never an allow and never a quiet 403.
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

    // Resolved server-side by OPA — never trusted from input.
    let manageable: string[]
    try {
      manageable = await memberOrgs(email)
    } catch (err) {
      request.log.warn({ email, organizationId, err: (err as Error).message }, '[requireManageableOrg] OPA could not be asked')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    }

    if (!manageable.includes(organizationId)) {
      request.log.warn(
        { email, organizationId, manageable },
        '[requireManageableOrg] access denied — org not administered by caller'
      )
      denyAudit(request, 'not_org_admin')

      return reply.status(403).send({
        error: 'Forbidden',
        message: `You may only manage organizations you administer ('${organizationId}' is not one)`,
      })
    }
  }
}
