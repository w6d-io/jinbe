import type { FastifyReply, FastifyRequest } from 'fastify'
import { decide, isSuperAdmin } from '../authz/opa.js'
import { administersOrganisation } from '../services/org-admin.js'
import { enforcing } from '../policy/declared-routes.js'
import { denyAudit } from '../audit/deny.js'
import { isClient, requestPath } from './require-service-admin.js'

/**
 * Gates for routes that act on ONE organisation — the one named by the route parameter — decided by
 * OPA, the engine the gateway decides with.
 *
 * super_admin is a holder of a GLOBAL `*` role (`rbac.super_admin`). Org admin is on that org's
 * roster and a member of it (`rbac.delegation.manageable_orgs`). Nothing held in another
 * organisation counts: a service admin of Globex is nobody in Acme.
 *
 * "Is not" and "cannot tell" stay apart: when OPA could not be asked, the answer is 503, never a
 * quiet 403 — and never an allow.
 */

function unavailable(request: FastifyRequest, reply: FastifyReply, organizationId: string, err?: unknown) {
  request.log.warn({ organizationId, err: (err as Error | undefined)?.message }, '[org-gate] OPA could not be asked — 503')
  return reply.status(503).send({
    error: 'Service Unavailable',
    message: 'Unable to verify authorization. Please try again later.',
  })
}

function refuse(request: FastifyRequest, reply: FastifyReply, organizationId: string, reason: string) {
  denyAudit(request, reason)
  return reply.status(403).send({
    error: 'Forbidden',
    message: `Not allowed in organization '${organizationId}'`,
  })
}

function unauthenticated(reply: FastifyReply) {
  return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
}

function caller(request: FastifyRequest): string | null {
  const email = request.userContext?.email
  const subject = request.userContext?.id
  return subject && subject !== 'unknown' && email && email !== 'unknown' ? email : null
}

/** The org's own admin, or super_admin. For the routes that hand out that org's grants. */
export function requireOrgAdmin(paramName = 'organizationId') {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const email = caller(request)
    if (!email) return unauthenticated(reply)
    const organizationId = (request.params as Record<string, string>)[paramName]

    let superAdmin: boolean
    try {
      superAdmin = await isSuperAdmin(email)
    } catch (err) {
      return unavailable(request, reply, organizationId, err)
    }
    if (superAdmin) return

    const orgAdmin = await administersOrganisation(request, organizationId)
    if (orgAdmin === null) return unavailable(request, reply, organizationId)
    if (orgAdmin) return
    return refuse(request, reply, organizationId, 'not_org_admin')
  }
}

/**
 * `permission` in the org named by the route, exactly as the gateway decides it: OPA's
 * `rbac.decision` for this request — super_admin; that org's roster admin for the org-management
 * set; or a MEMBER of that org holding the route's permission from site grants ∪ org_grants[that org].
 * `permission` names what the jinbe route_map requires of these routes, and marks the guard for the
 * published route table.
 */
export function requireOrgPermission(permission: string, paramName = 'organizationId') {
  return enforcing(async function (request: FastifyRequest, reply: FastifyReply) {
    const email = caller(request)
    if (!email) return unauthenticated(reply)
    const organizationId = (request.params as Record<string, string>)[paramName]

    let allow: boolean
    try {
      ;({ allow } = await decide({
        email,
        method: request.method,
        path: requestPath(request),
        aal: request.userContext?.aal,
        client: isClient(request),
      }))
    } catch (err) {
      return unavailable(request, reply, organizationId, err)
    }
    if (allow) return
    return refuse(request, reply, organizationId, `missing_permission:${permission}`)
  }, permission)
}
