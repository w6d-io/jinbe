import type { FastifyReply, FastifyRequest } from 'fastify'
import { decide } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { enforcing } from '../policy/declared-routes.js'
import { denyAudit } from '../audit/deny.js'
import { delegationOf, isClient, requestPath, serviceAdminRefusal } from './require-service-admin.js'
import { delegationRefusal } from './delegation-gate.js'

/**
 * The ONE gate of a route that acts on one organisation (authz-v2-design §2.3), attached by the
 * route-access hook to every route declaring `org`: exactly what the gateway decides, OPA's
 * `rbac.decision` for this very request — the caller's grants IN THAT ORG (org roles assigned to a
 * member, the org entitled to the app) or the every-org map of their platform roles. Platform
 * permissions count for nothing here, and there is no super-admin flag and no roster.
 *
 * Asked again here because the gateway is not the only way in. "Is not" and "cannot tell" stay
 * apart: OPA unreachable is a 503, never a quiet 403 and never an allow.
 */

function caller(request: FastifyRequest): string | null {
  const email = request.userContext?.email
  const subject = request.userContext?.id
  return subject && subject !== 'unknown' && email && email !== 'unknown' ? email : null
}

/**
 * `permission` in the org named by `paramName`. Without `fixed`, the permission is the route's own
 * declaration (`config.permission`).
 */
export function requireOrgPermission(fixed?: string, paramName = 'organizationId') {
  const gate = async function requireOrgPermission(request: FastifyRequest, reply: FastifyReply) {
    const email = caller(request)
    if (!email) return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    const organizationId = (request.params as Record<string, string>)[paramName]
    const permission = fixed ?? request.routeOptions?.config?.permission
    if (!permission) {
      denyAudit(request, 'route_declares_no_permission')
      return reply.status(403).send({ error: 'Forbidden', message: `Not allowed in organization '${organizationId}'` })
    }

    // A user through a client: the token must cover THIS permission, whatever the user holds.
    const narrowed = delegationRefusal(request, permission)
    if (narrowed) {
      denyAudit(request, narrowed)
      return reply.status(403).send({ error: 'Forbidden', message: `Not allowed in organization '${organizationId}'`, reason: narrowed })
    }

    let decision: { allow: boolean; reason: string }
    try {
      decision = await decide({
        email,
        method: request.method,
        path: requestPath(request),
        aal: request.userContext?.aal,
        client: isClient(request),
        delegation: delegationOf(request),
      })
    } catch (err) {
      request.log.warn({ organizationId, err: (err as Error).message }, '[org-gate] OPA could not be asked — 503')
      return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: 'Unable to verify authorization. Please try again later.' })
    }
    if (decision.allow) return
    denyAudit(request, `${decision.reason}:${permission}`)
    return reply.status(403).send(await serviceAdminRefusal(request, organizationId, decision.reason))
  }
  // Marked when fixed, so a route carrying it is checked against its declaration.
  return fixed ? enforcing(gate, fixed) : gate
}
