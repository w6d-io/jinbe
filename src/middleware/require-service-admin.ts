import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/index.js'
import { decide, manageableOrgs, rights } from '../authz/opa.js'
import type { HeldRights } from '../services/authorization-resolution.js'
import { ORG_ADMIN_PERMISSIONS, ORG_ADMIN_ROLE } from '../services/org-admin.js'
import { denyAudit } from '../audit/deny.js'

/** The path OPA is asked about: the request's own, without its query string. */
export function requestPath(request: FastifyRequest): string {
  return (request.url || '').split('?')[0]
}

/** What the gateway passes as `client`: an OAuth2 client, not a person's session. */
export function isClient(request: FastifyRequest): boolean {
  return request.userContext?.authVia === 'machine'
}

/**
 * Middleware factory: admits a request to a route of ONE organisation (named by the route parameter
 * `paramName`) exactly when the gateway would — OPA's `rbac.decision` for this very request: the
 * jinbe route_map, the org layer (membership, org grants, the per-org admin roster) and the site
 * layer. The same rule and the same data, asked again here because the gateway is not the only way
 * in (NetworkPolicy is not enforced).
 *
 * Then attaches what the caller holds for the downstream checks: their jinbe rights (`user_info`)
 * and, with `orgAdmin`, the org-admin management set when OPA lists the org among their
 * `manageable_orgs` — opt-in, because those rights mean something only on the routes that manage an
 * organisation's people.
 *
 * "Holds nothing" and "could not tell" stay apart: OPA unreachable → 503, never 403, never an allow.
 */
export function requireServiceAdmin(
  paramName = 'organizationId',
  options: { orgAdmin?: boolean } = {}
) {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = request.userContext?.email
    const subject = request.userContext?.id

    if (!subject || subject === 'unknown' || !email || email === 'unknown') {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'Authentication required',
      })
    }

    // DEV MODE: bypass
    if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
      request.log.debug({ email }, '[requireServiceAdmin] DEV_BYPASS_AUTH — OPA not asked')
      request.rbacInfo = {
        email,
        groups: ['super_admins', 'admins'],
        roles: ['super_admin', 'admin'],
        permissions: ['*'],
      }
      return
    }

    const organizationId = (request.params as Record<string, string>)[paramName]

    let allow: boolean
    let held: HeldRights
    let orgAdmin = false
    try {
      ;({ allow } = await decide({
        email,
        method: request.method,
        path: requestPath(request),
        aal: request.userContext?.aal,
        client: isClient(request),
      }))
      held = await rights(email)
      if (allow && options.orgAdmin) orgAdmin = (await manageableOrgs(email)).includes(organizationId)
    } catch (err) {
      request.log.warn({ subject, organizationId, err: (err as Error).message }, '[requireServiceAdmin] OPA could not be asked')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Unable to verify authorization. Please try again later.',
      })
    }

    if (!allow) {
      request.log.warn({ email, organizationId }, '[requireServiceAdmin] access denied by OPA')
      denyAudit(request, 'not_service_admin')
      return reply.status(403).send({
        error: 'Forbidden',
        message: `Admin access required for organization '${organizationId}'`,
      })
    }

    if (orgAdmin) {
      held = {
        groups: held.groups,
        roles: [...new Set([...held.roles, ORG_ADMIN_ROLE])].sort(),
        permissions: [...new Set([...held.permissions, ...ORG_ADMIN_PERMISSIONS])].sort(),
      }
    }
    request.rbacInfo = { email, ...held }
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
      denyAudit(request, `missing_permission:${requiredPermission}`)

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
