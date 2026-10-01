import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { requireOrgPermission } from '../middleware/require-org-permission.js'
import { needs } from '../policy/route-access.js'
import { organizationIdParamJsonSchema, organizationUserIdParamJsonSchema } from '../schemas/organization-user.schema.js'
import {
  forbiddenResponseSchema, notFoundResponseSchema, serviceUnavailableResponseSchema, unauthorizedResponseSchema,
} from '../schemas/response-schemas.js'
import { onlyInModel } from '../authz-v2/model.js'
import { loadDataV2 } from '../authz-v2/service.js'
import { assignableOrgRoles, mayAssignOrgRole } from '../authz-v2/holding.js'
import { isQualifiedOrgRole } from '../authz-v2/dataset.js'
import { JINBE, qualified } from '../authz-v2/roles.js'
import type { DataV2 } from '../authz-v2/resolve.js'
import { kratosService, type AdminState } from '../services/kratos.service.js'
import { join, organisationsOn, rolesIn, setRoles } from '../services/organisation-store/membership.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'

/**
 * Org roles (authz v2, design §2.2) — what replaces the roster, org grants and the service map. Exist
 * only under v2 (`model: 'v2'`): 404 while v1 decides.
 *
 *   GET /api/organizations/:organizationId/roles               org.members:read   the org roles, which the caller may assign
 *   PUT /api/organizations/:organizationId/users/:id/roles     org.members:write  one member's org roles (holding rule)
 *   PUT /api/admin/organizations/:organizationId/owners        orgs.owners:write  name an org's owners (platform, step-up)
 *
 * Assignments live on the identity, `metadata_admin.organization_roles[org] = ["jinbe:owner", …]`,
 * written under the identity's lock. Names that are not a qualified `svc:role` (v1 data) are kept
 * as they are: v2 ignores them and the plan lists them.
 */

const ORG = { org: 'organizationId', model: 'v2' } as const

const rolesBody = {
  type: 'object',
  required: ['roles'],
  additionalProperties: false,
  properties: { roles: { type: 'array', maxItems: 32, items: { type: 'string', pattern: '^[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$' } } },
}

const ownersBody = {
  type: 'object',
  required: ['owners'],
  additionalProperties: false,
  properties: { owners: { type: 'array', maxItems: 16, items: { type: 'string', minLength: 1, maxLength: 64 } } },
}

// 404 keeps its `code`: route_not_active (v1 decides) reads differently from an unknown member.
const notFound = { ...notFoundResponseSchema, properties: { ...notFoundResponseSchema.properties, error: { type: 'string' }, code: { type: 'string' } } }
const errors = { 401: unauthorizedResponseSchema, 403: forbiddenResponseSchema, 404: notFound, 503: serviceUnavailableResponseSchema }

function caller(request: FastifyRequest): string {
  return request.userContext?.email ?? ''
}

async function model(reply: FastifyReply): Promise<DataV2 | null> {
  try {
    return await loadDataV2()
  } catch (err) {
    reply.status(503).send({ error: POLICY_UNAVAILABLE, message: `The v2 model could not be read: ${(err as Error).message}` })
    return null
  }
}

/** Exactly `wanted` as the qualified roles in `org`, v1 names left untouched. */
function withQualifiedRoles(state: AdminState, org: string, wanted: readonly string[]): AdminState {
  const legacy = rolesIn(state, org).filter((r) => !isQualifiedOrgRole(r))
  return setRoles(state, org, [...legacy, ...wanted])
}

export async function orgRolesRoutes(fastify: FastifyInstance) {
  // 404 before any gate while v1 decides; then the org clause for this request (rbacv2 via the router).
  fastify.addHook('preHandler', onlyInModel('v2'))
  fastify.addHook('preHandler', requireOrgPermission())

  fastify.get('/roles', {
    ...needs('org.members:read', ORG),
    schema: {
      description: "The org roles of this organization (jinbe's and its entitled sites'), each with its permissions and whether the caller may assign it (holding rule). authz v2 only.",
      tags: ['organization-users'],
      params: organizationIdParamJsonSchema,
      response: {
        200: {
          type: 'object',
          properties: {
            roles: {
              type: 'array',
              items: {
                type: 'object',
                properties: { role: { type: 'string' }, permissions: { type: 'array', items: { type: 'string' } }, assignable: { type: 'boolean' } },
              },
            },
          },
        },
        ...errors,
      },
    },
  }, async (request, reply) => {
    const { organizationId } = request.params as { organizationId: string }
    const d = await model(reply)
    if (!d) return
    const assignable = new Set(assignableOrgRoles(d, caller(request), organizationId))
    const entitled = d.org_sites[organizationId] ?? [JINBE]
    const roles = Object.entries(d.org_roles)
      .filter(([svc]) => entitled.includes(svc))
      .flatMap(([svc, roles]) => Object.entries(roles).map(([name, permissions]) => {
        const role = qualified(svc, name)
        return { role, permissions, assignable: assignable.has(role) }
      }))
      .sort((a, b) => a.role.localeCompare(b.role))
    return reply.send({ roles })
  })

  fastify.put('/users/:id/roles', {
    ...needs('org.members:write', ORG),
    schema: {
      description:
        "Replace one member's org roles in this organization. Every role being ADDED must pass the holding rule: the caller " +
        'holds org.members:write here and every permission of the role here. Removing a role needs nothing more. authz v2 only.',
      tags: ['organization-users'],
      params: organizationUserIdParamJsonSchema,
      body: rolesBody,
      response: {
        200: { type: 'object', properties: { id: { type: 'string' }, roles: { type: 'array', items: { type: 'string' } } } },
        ...errors,
        403: {
          ...forbiddenResponseSchema,
          properties: {
            ...forbiddenResponseSchema.properties,
            refused: { type: 'array', items: { type: 'object', properties: { role: { type: 'string' }, reason: { type: 'string' } } } },
          },
        },
      },
    },
  }, async (request, reply) => {
    const { organizationId, id } = request.params as { organizationId: string; id: string }
    const wanted = [...new Set((request.body as { roles: string[] }).roles)].sort()
    const d = await model(reply)
    if (!d) return

    const identity = await kratosService.getIdentity(id).catch(() => null)
    const state: AdminState | null = identity
      ? {
          organizationId: ((identity as Record<string, unknown>).organization_id as string | null | undefined) ?? null,
          metadataAdmin: (identity.metadata_admin as Record<string, unknown> | null) ?? {},
        }
      : null
    if (!state || !organisationsOn(state).includes(organizationId)) {
      return reply.status(404).send({ error: 'Not Found', message: `No member '${id}' in organization '${organizationId}'` })
    }
    const before = rolesIn(state, organizationId).filter(isQualifiedOrgRole)
    const added = wanted.filter((r) => !before.includes(r))
    const refused = added
      .map((role) => ({ role, verdict: mayAssignOrgRole(d, caller(request), organizationId, role, true) }))
      .filter((r) => !r.verdict.ok)
      .map((r) => ({ role: r.role, reason: r.verdict.ok ? '' : r.verdict.reason }))
    const actor = auditActor(request)
    if (refused.length > 0) {
      auditEventService.emit({
        type: 'organization_user.roles_refused', actor, target: { type: 'user', id },
        details: { organizationId, refused }, source: 'jinbe-api',
      }).catch(() => {})
      return reply.status(403).send({ error: 'Forbidden', message: `Not allowed to assign: ${refused.map((r) => r.role).join(', ')}`, refused })
    }

    await kratosService.updateAdminState(id, (s) => withQualifiedRoles(s, organizationId, wanted))
    rbacService.notifyBindingsChanged('org_roles_changed', actor).catch(() => {})
    auditEventService.emit({
      type: 'organization_user.roles_changed', actor, target: { type: 'user', id },
      details: { organizationId, before, after: wanted }, source: 'jinbe-api',
    }).catch(() => {})
    return reply.send({ id, roles: wanted })
  })
}

/** Platform side: `PUT /api/admin/organizations/:organizationId/owners` (onboarding, break-glass). */
export async function orgOwnersRoutes(fastify: FastifyInstance) {
  fastify.put('/owners', {
    ...needs('org.admins:write', { model: 'v2' }),
    schema: {
      description:
        "Name this organization's owners (jinbe:owner) by identity id: each joins the org if needed and holds jinbe:owner; " +
        'everyone else loses it. Step-up; four-eyes in prod. authz v2 only (the v1 roster is PUT /admin/rbac/org-admin-map).',
      tags: ['organizations'],
      params: organizationIdParamJsonSchema,
      body: ownersBody,
      response: {
        200: { type: 'object', properties: { owners: { type: 'array', items: { type: 'string' } } } },
        ...errors,
      },
    },
  }, async (request, reply) => {
    const { organizationId } = request.params as { organizationId: string }
    const owners = [...new Set((request.body as { owners: string[] }).owners)].sort()
    const owner = qualified(JINBE, 'owner')
    const directory = await kratosService.getAllIdentitiesWithBindings()
    const current = [...directory.values()]
      .filter((b) => (b.organizationRoles[organizationId] ?? []).includes(owner))
      .map((b) => b.id)
    const actor = auditActor(request)
    for (const id of owners) {
      await kratosService.updateAdminState(id, (s) => {
        const joined = join(s, organizationId)
        return withQualifiedRoles(joined, organizationId, [...new Set([...rolesIn(joined, organizationId).filter(isQualifiedOrgRole), owner])])
      })
    }
    for (const id of current.filter((c) => !owners.includes(c))) {
      await kratosService.updateAdminState(id, (s) =>
        withQualifiedRoles(s, organizationId, rolesIn(s, organizationId).filter((r) => isQualifiedOrgRole(r) && r !== owner)))
    }
    rbacService.notifyBindingsChanged('org_owners_changed', actor).catch(() => {})
    auditEventService.emit({
      type: 'organization.owners_changed', actor, target: { type: 'organization', id: organizationId },
      details: { before: current.sort(), after: owners }, source: 'jinbe-api',
    }).catch(() => {})
    return reply.send({ owners })
  })
}
