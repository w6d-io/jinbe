import type { FastifyReply, FastifyRequest } from 'fastify'
import { holdsPlatformPermission, rightsOf } from '../services/authorization-model.service.js'
import { permits } from '../services/authorization-resolution.js'
import { administersOrganisation, ORG_ADMIN_PERMISSIONS } from '../services/org-admin.js'
import { callerOrganisations } from '../services/caller-organisations.js'
import { orgGrantPermissions } from '../services/org-grants.service.js'
import { enforcing } from '../policy/declared-routes.js'
import { denyAudit } from '../audit/deny.js'

/**
 * Gates for routes that act on ONE organisation — the one named by the route parameter.
 *
 * super_admin is whoever holds `admin:write` across the platform (the same test as requireSuperAdmin).
 * Org admin is the J-2 path: on that org's roster and a member of it, or its directory `org_admin`.
 * Nothing held in another organisation counts: a service admin of Globex is nobody in Acme.
 *
 * "Is not" and "cannot tell" stay apart, as in requireServiceAdmin: when an authority could not be
 * read and nothing else admitted the caller, the answer is 503, never a quiet 403 — and never an allow.
 */

const SUPER_ADMIN = 'admin:write'

type Verdict = true | false | null // admitted | refused | could not tell

async function tell(fn: () => Promise<boolean>): Promise<Verdict> {
  try {
    return await fn()
  } catch {
    return null
  }
}

function refuse(request: FastifyRequest, reply: FastifyReply, organizationId: string, reason: string, verdicts: Verdict[]) {
  const route = `${request.method} ${(request.url || '').split('?')[0]}`
  if (verdicts.includes(null)) {
    request.log.warn({ organizationId, route, reason }, '[org-gate] an authority could not be read — 503')
    return reply.status(503).send({
      error: 'Service Unavailable',
      message: 'Unable to verify authorization. Please try again later.',
    })
  }
  denyAudit(request, reason)
  return reply.status(403).send({
    error: 'Forbidden',
    message: `Not allowed in organization '${organizationId}'`,
  })
}

function unauthenticated(reply: FastifyReply) {
  return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
}

/** The org's own admin, or super_admin. For the routes that hand out that org's grants. */
export function requireOrgAdmin(paramName = 'organizationId') {
  return async function (request: FastifyRequest, reply: FastifyReply) {
    const subject = request.userContext?.id
    if (!subject || subject === 'unknown') return unauthenticated(reply)
    const organizationId = (request.params as Record<string, string>)[paramName]

    const superAdmin = await tell(() => holdsPlatformPermission(subject, SUPER_ADMIN))
    if (superAdmin === true) return
    const orgAdmin = await administersOrganisation(request, organizationId)
    if (orgAdmin === true) return

    return refuse(request, reply, organizationId, 'not_org_admin', [superAdmin, orgAdmin])
  }
}

/**
 * `permission` in the org named by the route: super_admin; that org's admin when the permission is
 * one an org admin holds; or a MEMBER of that org holding it from site grants ∪ org_grants[that org].
 */
export function requireOrgPermission(permission: string, paramName = 'organizationId') {
  return enforcing(async function (request: FastifyRequest, reply: FastifyReply) {
    const subject = request.userContext?.id
    if (!subject || subject === 'unknown') return unauthenticated(reply)
    const email = request.userContext?.email ?? ''
    const organizationId = (request.params as Record<string, string>)[paramName]

    const superAdmin = await tell(() => holdsPlatformPermission(subject, SUPER_ADMIN))
    if (superAdmin === true) return

    let orgAdmin: Verdict = false
    if ((ORG_ADMIN_PERMISSIONS as readonly string[]).includes(permission)) {
      orgAdmin = await administersOrganisation(request, organizationId)
      if (orgAdmin === true) return
    }

    const member = await tell(async () => (await callerOrganisations(request)).includes(organizationId))
    if (member !== true) {
      return refuse(request, reply, organizationId, 'not_member', [superAdmin, orgAdmin, member])
    }

    const held = await tell(async () => {
      if (permits((await rightsOf(subject, organizationId)).permissions, permission)) return true
      return email !== '' && (await orgGrantPermissions(email, organizationId)).includes(permission)
    })
    if (held === true) return

    return refuse(request, reply, organizationId, `missing_permission:${permission}`, [superAdmin, orgAdmin, held])
  }, permission)
}
