import type { FastifyInstance, FastifyReply } from 'fastify'
import { needs } from '../policy/route-access.js'
import { organizationIdParamJsonSchema, organizationUserIdParamJsonSchema } from '../schemas/organization-user.schema.js'
import {
  forbiddenResponseSchema, notFoundResponseSchema, serviceUnavailableResponseSchema, unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { JINBE, qualified } from '../policy/roles.js'
import { kratosService } from '../services/kratos.service.js'
import { join, organisationsOn } from '../services/organisation-store/membership.js'
import { orgRolesRepository } from '../services/org-roles.repository.js'
import { orgRoleRefusals, orgRoleRemovalRefusal, orgRolesFor } from '../services/org-role-grants.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'

/**
 * Org roles (authz-v2-design §2.2) — what an organisation's people may do in it:
 *
 *   GET /api/organizations/:organizationId/roles               org.members:read   the org's roles, which the caller may assign
 *   GET /api/organizations/:organizationId/users/:id/roles     org.members:read   one member's roles here
 *   PUT /api/organizations/:organizationId/users/:id/roles     org.members:write  one member's roles here (holding rule)
 *   PUT /api/admin/organizations/:organizationId/owners        orgs.owners:write  name an org's owners (platform, step-up)
 *
 * Assignments are jinbe's own records (rbac:org_assignments, by identity id; org-roles.repository.ts),
 * published to the policy as data.bindings.org_assignments. Each org route's gate is the org clause,
 * attached by the route-access hook from its `org` declaration.
 */

const ORG = { org: 'organizationId' } as const
const ROLE_PATTERN = '^[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$'

const rolesBody = {
  type: 'object',
  required: ['roles'],
  additionalProperties: false,
  properties: { roles: { type: 'array', maxItems: 32, items: { type: 'string', pattern: ROLE_PATTERN } } },
}

const ownersBody = {
  type: 'object',
  required: ['owners'],
  additionalProperties: false,
  properties: { owners: { type: 'array', maxItems: 16, items: { type: 'string', minLength: 1, maxLength: 64 } } },
}

const notFound = { ...notFoundResponseSchema, properties: { ...notFoundResponseSchema.properties, error: { type: 'string' } } }
const errors = { 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFound, 503: serviceUnavailableResponseSchema }
/** A 403 naming each refused org role (also the org user create route's). */
export const orgRoleRefusedSchema = {
  ...forbiddenResponseSchema,
  properties: {
    ...forbiddenResponseSchema.properties,
    refused: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          role: { type: 'string' }, reason: { type: 'string' },
          reasons: { type: 'array', items: { type: 'string' } },
          missing: { type: 'array', items: { type: 'string' } },
          grantedBy: { type: 'array', items: { type: 'string' } },
        },
      },
    },
  },
}
const memberRoles = { type: 'object', properties: { id: { type: 'string' }, roles: { type: 'array', items: { type: 'string' } } } }

function unavailable(reply: FastifyReply, err: unknown) {
  return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: `Unable to verify authorization: ${(err as Error).message}` })
}

/** The member's address when the identity belongs to the org; null otherwise (the routes answer 404). */
async function memberOf(id: string, organizationId: string): Promise<{ email: string } | null> {
  const identity = await kratosService.getIdentity(id).catch(() => null)
  if (!identity) return null
  const state = {
    organizationId: ((identity as Record<string, unknown>).organization_id as string | null | undefined) ?? null,
    metadataAdmin: (identity.metadata_admin as Record<string, unknown> | null) ?? {},
  }
  if (!organisationsOn(state).includes(organizationId)) return null
  return { email: String((identity.traits as { email?: unknown } | undefined)?.email ?? '') }
}

export async function orgRolesRoutes(fastify: FastifyInstance) {
  fastify.get('/roles', {
    ...needs('org.members:read', ORG),
    schema: {
      description: "This organization's org roles (jinbe's and its entitled sites'), each with its permissions and whether the caller may assign it (holding rule).",
      tags: ['organization-users'],
      params: organizationIdParamJsonSchema,
      response: {
        200: {
          type: 'object',
          properties: {
            roles: {
              type: 'array',
              items: { type: 'object', properties: { role: { type: 'string' }, permissions: { type: 'array', items: { type: 'string' } }, assignable: { type: 'boolean' } } },
            },
          },
        },
        ...errors,
      },
    },
  }, async (request, reply) => {
    const { organizationId } = request.params as { organizationId: string }
    try {
      return reply.send({ roles: await orgRolesFor(request.userContext?.email ?? '', organizationId) })
    } catch (err) {
      return unavailable(reply, err)
    }
  })

  fastify.get('/users/:id/roles', {
    ...needs('org.members:read', ORG),
    schema: {
      description: "One member's org roles in this organization.",
      tags: ['organization-users'],
      params: organizationUserIdParamJsonSchema,
      response: { 200: memberRoles, ...errors },
    },
  }, async (request, reply) => {
    const { organizationId, id } = request.params as { organizationId: string; id: string }
    if (!(await memberOf(id, organizationId))) return reply.status(404).send({ error: 'Not Found', message: `No member '${id}' in organization '${organizationId}'` })
    return reply.send({ id, roles: await orgRolesRepository.getForMember(organizationId, id) })
  })

  fastify.put('/users/:id/roles', {
    ...needs('org.members:write', ORG),
    schema: {
      description:
        "Replace one member's org roles in this organization. Decided by the policy (rbac.delegation): every role ADDED " +
        'must pass the holding rule (the caller holds org.members:write here and every permission of the role here); a removal ' +
        'needs org.members:write here. A refusal lists each role with its reasons, what is missing and which org roles cover it.',
      tags: ['organization-users'],
      params: organizationUserIdParamJsonSchema,
      body: rolesBody,
      response: { 200: memberRoles, ...errors, 403: orgRoleRefusedSchema },
    },
  }, async (request, reply) => {
    const { organizationId, id } = request.params as { organizationId: string; id: string }
    const wanted = [...new Set((request.body as { roles: string[] }).roles)].sort()
    const member = await memberOf(id, organizationId)
    if (!member) return reply.status(404).send({ error: 'Not Found', message: `No member '${id}' in organization '${organizationId}'` })

    const before = await orgRolesRepository.getForMember(organizationId, id)
    const added = wanted.filter((r) => !before.includes(r))
    const removed = before.filter((r) => !wanted.includes(r))
    const caller = request.userContext?.email ?? ''
    let refused
    try {
      refused = await orgRoleRefusals(caller, organizationId, added, { email: member.email })
      const removal = await orgRoleRemovalRefusal(caller, organizationId, removed)
      if (removal) refused.push(removal)
    } catch (err) {
      return unavailable(reply, err)
    }
    const actor = auditActor(request)
    if (refused.length > 0) {
      auditEventService.emit({
        type: 'organization_user.roles_refused', actor, target: { type: 'user', id },
        details: { organizationId, refused }, source: 'jinbe-api',
      }).catch(() => {})
      return reply.status(403).send({ error: 'Forbidden', message: `Not allowed to assign: ${refused.map((r) => r.role).join(', ')}`, refused })
    }

    await orgRolesRepository.setForMember(organizationId, id, wanted)
    rbacService.notifyBindingsChanged('org_roles_changed', actor).catch(() => {})
    auditEventService.emit({
      type: 'organization_user.roles_changed', actor, target: { type: 'user', id },
      details: { organizationId, before, after: wanted }, source: 'jinbe-api',
    }).catch(() => {})
    return reply.send({ id, roles: wanted })
  })
}

/** Platform side: `PUT /api/admin/organizations/:organizationId/owners` (onboarding, break-glass of one org). */
export async function orgOwnersRoutes(fastify: FastifyInstance) {
  fastify.put('/owners', {
    ...needs('orgs.owners:write'),
    schema: {
      description:
        "Name this organization's owners (jinbe:owner) by identity id: each joins the org if needed and holds jinbe:owner " +
        'there; everyone else loses it. Step-up; four-eyes in prod.',
      tags: ['organizations'],
      params: organizationIdParamJsonSchema,
      body: ownersBody,
      response: { 200: { type: 'object', properties: { owners: { type: 'array', items: { type: 'string' } } } }, ...errors },
    },
  }, async (request, reply) => {
    const { organizationId } = request.params as { organizationId: string }
    const owners = [...new Set((request.body as { owners: string[] }).owners)].sort()
    const owner = qualified(JINBE, 'owner')
    const current = await orgRolesRepository.holdersOf(organizationId, owner)
    const actor = auditActor(request)
    for (const id of owners) {
      await kratosService.updateAdminState(id, (s) => join(s, organizationId))
      const roles = await orgRolesRepository.getForMember(organizationId, id)
      await orgRolesRepository.setForMember(organizationId, id, [...roles, owner])
    }
    for (const id of current.filter((c) => !owners.includes(c))) {
      const roles = await orgRolesRepository.getForMember(organizationId, id)
      await orgRolesRepository.setForMember(organizationId, id, roles.filter((r) => r !== owner))
    }
    rbacService.notifyBindingsChanged('org_owners_changed', actor).catch(() => {})
    auditEventService.emit({
      type: 'organization.owners_changed', actor, target: { type: 'organization', id: organizationId },
      details: { before: current, after: owners }, source: 'jinbe-api',
    }).catch(() => {})
    return reply.send({ owners })
  })
}
