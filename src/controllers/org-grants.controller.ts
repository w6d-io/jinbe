import type { FastifyReply, FastifyRequest } from 'fastify'
import { z } from 'zod'
import { kratosService } from '../services/kratos.service.js'
import { isMemberOf } from '../services/org-membership.service.js'
import { orgGrantsRepository } from '../services/org-grants.repository.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { assignableGroupNames, canGrant } from '../services/org-grants.service.js'
import { OpaQueryError, OpaUnavailableError } from '../services/opa-client.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'

/**
 * Org grants: the groups an org admin hands out IN THEIR ORG (data.org_grants). They count only on
 * that org's routes, and only their service roles (opal-policies org.rego).
 *
 * Who may grant what is OPA's `can_grant`, asked per group being added; one refusal refuses the
 * whole write and nothing is written. Removing a grant only narrows access, so it is not asked.
 */

export const GROUP_NAME = /^[A-Za-z0-9_.:-]{1,128}$/

const grantsBody = z.object({ groups: z.array(z.string().regex(GROUP_NAME)).max(100) })

type OrgParams = { organizationId: string }
type MemberParams = OrgParams & { id: string }

const REFUSED_REASON = 'not delegable: outside this org, a wildcard or global role, or more than you hold'

/** OPA unset → 503, OPA silent → 502: a grant nobody could check is never written. */
function opaFailure(reply: FastifyReply, err: unknown) {
  if (err instanceof OpaUnavailableError) {
    return reply.status(503).send({ error: 'Service Unavailable', message: err.message })
  }
  if (err instanceof OpaQueryError) {
    return reply.status(502).send({ error: 'Bad Gateway', message: err.message })
  }
  throw err
}

function actorEmail(request: FastifyRequest): string {
  return (request.userContext?.email ?? '').toLowerCase()
}

/** The member in the route, or why not: unknown identity, or not in this org (both 404). */
async function memberOf(organizationId: string, id: string): Promise<KratosIdentity | string> {
  let identity: KratosIdentity
  try {
    identity = await kratosService.getIdentity(id)
  } catch (err) {
    if ((err as { statusCode?: number })?.statusCode === 404) return 'User not found'
    throw err
  }
  return (await isMemberOf(identity, organizationId)) ? identity : 'User is not a member of this organization'
}

export class OrgGrantsController {
  /** GET /api/organizations/:organizationId/grants */
  async list(request: FastifyRequest<{ Params: OrgParams }>, reply: FastifyReply) {
    return reply.send({ grants: await orgGrantsRepository.getForOrg(request.params.organizationId) })
  }

  /** PUT /api/organizations/:organizationId/users/:id/grants — replaces that member's grants here. */
  async replace(request: FastifyRequest<{ Params: MemberParams }>, reply: FastifyReply) {
    const { organizationId, id } = request.params
    const parsed = grantsBody.safeParse(request.body)
    if (!parsed.success) {
      return reply.status(400).send({ error: 'Bad Request', message: 'groups must be a list of group names' })
    }

    // Never Fastify's "Route METHOD:/path not found": kuma reads that as "endpoint not deployed".
    const identity = await memberOf(organizationId, id)
    if (typeof identity === 'string') return reply.status(404).send({ error: 'Not Found', message: identity })
    const email = String(identity.traits?.email ?? '').toLowerCase()
    if (!email) return reply.status(404).send({ error: 'Not Found', message: 'User has no email' })

    const groups = [...new Set(parsed.data.groups)].sort()
    const current = new Set(await orgGrantsRepository.getForMember(organizationId, email))
    const added = groups.filter((g) => !current.has(g))

    const refused: Array<{ group: string; reason: string }> = []
    try {
      for (const group of added) {
        if (!(await canGrant(actorEmail(request), organizationId, email, group))) {
          refused.push({ group, reason: REFUSED_REASON })
        }
      }
    } catch (err) {
      return opaFailure(reply, err)
    }

    const actor = auditActor(request)
    if (refused.length > 0) {
      auditEventService
        .emit({
          type: 'organization_user.grants_refused',
          actor,
          target: { type: 'user', id },
          details: { organizationId, refused: refused.map((r) => r.group) },
          source: 'jinbe-api',
        })
        .catch(() => {})
      return reply.status(403).send({
        error: 'Forbidden',
        message: `Not allowed to grant: ${refused.map((r) => r.group).join(', ')}`,
        refused,
      })
    }

    const before = await orgGrantsRepository.setForMember(organizationId, email, groups)
    rbacService.notifyBindingsChanged('org_grants_changed', actor).catch(() => {})
    auditEventService
      .emit({
        type: 'organization_user.grants_changed',
        actor,
        target: { type: 'user', id },
        details: { organizationId, before, after: groups },
        source: 'jinbe-api',
      })
      .catch(() => {})
    return reply.send({ email, groups })
  }

  /**
   * GET /api/organizations/:organizationId/assignable-groups — what the picker may offer: OPA's
   * `assignable_groups`, kept to groups that exist, carry no global role and stay inside this org's
   * service bundle (the policy's own bundle rule, so this never widens what OPA said).
   */
  async assignable(request: FastifyRequest<{ Params: OrgParams }>, reply: FastifyReply) {
    const { organizationId } = request.params
    let names: string[]
    try {
      names = await assignableGroupNames(actorEmail(request), organizationId)
    } catch (err) {
      return opaFailure(reply, err)
    }

    const [definitions, bundles] = await Promise.all([
      redisRbacRepository.getGroups(),
      redisRbacRepository.getOrgServiceMap(),
    ])
    const bundle = new Set(bundles[organizationId] ?? [])
    const groups = [...new Set(names)]
      .sort()
      .filter((name) => {
        const services = Object.keys(definitions[name] ?? {})
        return services.length > 0 && !services.includes('global') && services.every((svc) => bundle.has(svc))
      })
      .map((name) => ({ name, services: definitions[name] }))
    return reply.send({ groups })
  }
}

export const orgGrantsController = new OrgGrantsController()
