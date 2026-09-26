import { FastifyRequest, FastifyReply } from 'fastify'
import { env } from '../config/env.js'
import { denyAudit } from '../audit/deny.js'
import { rights } from '../authz/opa.js'
import { allows, type CheckedPermission } from '../services/user-permissions.js'
import { enforcing } from '../policy/declared-routes.js'
import type { UserRbacInfo } from '../services/authorization-resolution.js'

/**
 * What the caller holds in jinbe (global roles included), attached to the request; or null with a
 * reply already sent.
 *
 * Asked of OPA — the engine the gateway decides with — never of a model read beside it. Keyed on the
 * address because that is what the RBAC bindings are keyed on. "Holds nothing" answers 403 later;
 * "could not tell" answers 503 here, since a refusal would read as a missing right.
 */
export async function callerRights(request: FastifyRequest, reply: FastifyReply): Promise<UserRbacInfo | null> {
  // Not reusing `request.rbacInfo`: another guard may have filled it from another source. The
  // short cache makes asking again cheap.
  const subject = request.userContext?.id
  const email = request.userContext?.email
  if (!subject || subject === 'unknown' || !email || email === 'unknown') {
    reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    return null
  }

  if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
    // The same stamp `requireAdmin` gives local development: the coarse pair, which every
    // user-management permission refines.
    request.rbacInfo = { email, groups: ['platform-admin'], roles: ['platform-admin'], permissions: ['admin:read', 'admin:write'] }
    return request.rbacInfo
  }

  try {
    request.rbacInfo = { email, ...(await rights(email)) }
    return request.rbacInfo
  } catch (err) {
    request.log.warn({ subject, err: (err as Error).message }, '[permission] OPA could not say what the caller holds')
    reply.status(503).send({ error: 'Service Unavailable', message: 'Unable to verify authorization. Please try again later.' })
    return null
  }
}

/**
 * Refuses unless the caller holds every one of `required`. Returns whether the request may go on.
 *
 * For the checks that depend on the request itself (an edit needs what it changes); the fixed ones
 * use `requirePermission`.
 */
export async function demandPermissions(
  request: FastifyRequest,
  reply: FastifyReply,
  required: readonly CheckedPermission[],
): Promise<boolean> {
  const rights = await callerRights(request, reply)
  if (!rights) return false

  const missing = required.filter((p) => !allows(rights.permissions, p))
  if (missing.length === 0) return true

  request.log.warn({ subject: request.userContext?.id, missing }, 'Access denied — missing a user-management permission')
  denyAudit(request, `missing:${missing.join(',')}`, { statusCode: 403 })
  reply.status(403).send({ error: 'Forbidden', message: `This needs ${missing.join(' and ')}.` })
  return false
}

/**
 * Requires one user-management permission, in THIS service — never only at the gateway, which a pod
 * in the cluster can go around (NetworkPolicy is not enforced).
 *
 * Holding the coarse permission it refines (`admin:read` / `admin:write`) or the per-service `*`
 * passes, so existing administrators keep every action.
 */
export function requirePermission(required: CheckedPermission) {
  return enforcing(async function (request: FastifyRequest, reply: FastifyReply) {
    if (!(await demandPermissions(request, reply, [required]))) return reply
  }, required)
}
