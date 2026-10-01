import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/index.js'
import { decide, manageableOrgs, rights } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import type { HeldRights } from '../services/authorization-resolution.js'
import { ORG_ADMIN_PERMISSIONS, ORG_ADMIN_ROLE } from '../services/org-admin.js'
import { denyAudit } from '../audit/deny.js'
import { grants } from '../policy/catalog.js'
import { holdsDeclaredPermissionGlobally } from './platform-holder.js'
import { refusalDetails } from '../services/permission-refusal.js'

/** The path OPA is asked about: the request's own, without its query string. */
export function requestPath(request: FastifyRequest): string {
  return (request.url || '').split('?')[0]
}

/**
 * What the gateway passes as `client`: an OAuth2 token, not a person's session — a machine, or a user
 * through a client (a delegated token: MCP, a personal key). A token carries no AAL, so the policy's
 * platform 2FA (rbac.rego § 8c) does not judge it — its human met the rule in the browser session
 * that connected the client or created the key (second-factor/gate.ts judges every session route).
 * Sent as false, a delegated super admin was refused every org route here as `needs_2fa`.
 */
export function isClient(request: FastifyRequest): boolean {
  const via = request.userContext?.authVia
  return via === 'machine' || via === 'delegated'
}

/** What OPA is told about a delegated caller (RouteQuestion.delegation), or undefined. */
export function delegationOf(request: FastifyRequest) {
  const d = request.userContext?.authVia === 'delegated' ? request.userContext.delegation : undefined
  return d ? { scopes: d.scopes, client_id: d.clientId, ...(d.org ? { org: d.org } : {}) } : undefined
}

/**
 * The 403 for an org route OPA refused, carrying OPA's own reason instead of one flattened message
 * (a delegated super admin refused as `needs_2fa` read "Admin access required", and was not one to
 * fix). Same shape as every permission refusal (`error`, `code`, `message`, `reason`, `permission`,
 * `grantedBy`, `hint`), so kuma and auth-mcp render it without a special case:
 *
 *   needs_2fa  → code `needs_2fa`: granted, but the sign-in is too weak for this route (per-site 2FA,
 *                or platform 2FA for a session). A client caller cannot step up: `step_up_unavailable`.
 *   not_found  → code `route_not_published`: OPA holds no row for this route (its route map lags).
 *   forbidden  → code `permission_required`, the route's declared permission and who grants it.
 */
export async function serviceAdminRefusal(
  request: FastifyRequest,
  organizationId: string,
  reason: string,
): Promise<Record<string, unknown>> {
  const declared = request.routeOptions?.config?.permission
  const permission = typeof declared === 'string' ? declared : undefined
  const base = { error: 'Forbidden', reason, ...(permission ? { permission } : {}) }
  if (reason === 'needs_2fa') {
    const client = isClient(request)
    return {
      ...base,
      code: client ? 'step_up_unavailable' : 'needs_2fa',
      message: client
        ? `Organization '${organizationId}' requires a second factor on this route, which this credential cannot carry.`
        : `A second factor is required for this route in organization '${organizationId}'.`,
      grantedBy: [],
      stepUp: { requiredAal: 'aal2' },
      hint: client
        ? 'Sign in to the console in a browser and retry there.'
        : 'Complete two-step sign-in at /two-step on the sign-in site, then retry.',
    }
  }
  if (reason === 'not_found') {
    return {
      ...base,
      code: 'route_not_published',
      message: `The policy holds no rule for this route yet; organization '${organizationId}' cannot be decided.`,
      grantedBy: [],
      hint: 'The route map may not have reached the policy engine yet. Retry in a minute, or ask an administrator.',
    }
  }
  const details = await refusalDetails(permission ? [permission] : [])
  return {
    ...base,
    code: 'permission_required',
    message: permission
      ? `This needs ${permission} in organization '${organizationId}'.`
      : `Admin access required for organization '${organizationId}'`,
    ...details,
  }
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
  return async function requireServiceAdmin(request: FastifyRequest, reply: FastifyReply) {
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
    let reason: string
    let held: HeldRights
    let orgAdmin = false
    try {
      ;({ allow, reason } = await decide({
        email,
        method: request.method,
        path: requestPath(request),
        aal: request.userContext?.aal,
        client: isClient(request),
        delegation: delegationOf(request),
      }))
      held = await rights(email)
      // A staff role holding the route's permission across the platform passes in every org.
      if (!allow) allow = await holdsDeclaredPermissionGlobally(request)
      if (allow && options.orgAdmin) orgAdmin = (await manageableOrgs(email)).includes(organizationId)
    } catch (err) {
      request.log.warn({ subject, organizationId, err: (err as Error).message }, '[requireServiceAdmin] OPA could not be asked')
      return reply.status(503).send({
        error: POLICY_UNAVAILABLE,
        message: 'Unable to verify authorization. Please try again later.',
      })
    }

    if (!allow) {
      request.log.warn({ email, organizationId, reason }, '[requireServiceAdmin] access denied by OPA')
      denyAudit(request, `not_service_admin:${reason}`)
      return reply.status(403).send(await serviceAdminRefusal(request, organizationId, reason))
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
  return async function requireServicePermission(request: FastifyRequest, reply: FastifyReply) {
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

    const hasPermission = grants(rbacInfo.permissions, requiredPermission)

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
