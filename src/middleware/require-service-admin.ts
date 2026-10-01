import { FastifyRequest } from 'fastify'
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
