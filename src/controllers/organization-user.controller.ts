import { FastifyReply, FastifyRequest } from 'fastify'
import { kratosService, KratosApiError } from '../services/kratos.service.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { userGroupsService } from '../services/user-groups.service.js'
import {
  KratosIdentity,
  KratosIdentityCreate,
  updateUserGroupsBodySchema,
} from '../schemas/admin.schema.js'
import {
  OrganizationUserCreateBody,
  OrganizationUserUpdateBody,
  OrganizationUsersQuery,
  organizationUserCreateBodySchema,
  organizationUserUpdateBodySchema,
  organizationUsersQuerySchema,
} from '../schemas/organization-user.schema.js'

/**
 * Path 3 hybrid: an identity matches an organization when EITHER
 *  (a) the new `metadata_admin.organizations` array includes the
 *      requested org UUID (authoritative), OR
 *  (b) the legacy `organization_id` traits pointer equals it
 *      (backward compat for identities that haven't been migrated
 *      to the multi-org array yet).
 *
 * Both checks are kept in sync with the rego `user_in_org` helper
 * (rbac.rego) and the `bindings.user_organizations[email]` /
 * `bindings.user_organization_primary[email]` Redis-mirrored datasets.
 *
 * Exported so jinbe-side unit tests can exercise the predicate
 * without spinning up Fastify; the controllers continue to call it
 * the same way as before.
 */
export function assertOrganizationMatch(identity: KratosIdentity, organizationId: string): void {
  const legacy = (identity as Record<string, unknown>).organization_id as string | null | undefined
  if (legacy === organizationId) return

  const metadataAdmin = identity.metadata_admin as
    | { organizations?: unknown }
    | null
    | undefined
  const orgs = Array.isArray(metadataAdmin?.organizations)
    ? (metadataAdmin!.organizations as unknown[]).filter((s): s is string => typeof s === 'string')
    : []
  if (orgs.includes(organizationId)) return

  throw new KratosApiError(404, 'User not found in this organization')
}

export class OrganizationUserController {
  /**
   * List users belonging to an organization
   * GET /api/organizations/:organizationId/users
   */
  async listUsers(
    request: FastifyRequest<{
      Params: { organizationId: string }
      Querystring: OrganizationUsersQuery
    }>,
    reply: FastifyReply
  ) {
    const { organizationId } = request.params
    const { page_size, credentials_identifier } =
      organizationUsersQuerySchema.parse(request.query)

    const { identities } = await kratosService.listIdentitiesByOrganization(
      organizationId,
      page_size
    )

    let filtered = identities
    if (credentials_identifier) {
      const search = credentials_identifier.toLowerCase()
      filtered = filtered.filter((i) =>
        i.traits?.email?.toLowerCase().includes(search)
      )
    }

    return reply.send({ data: filtered, total: filtered.length })
  }

  /**
   * Get a user by ID within an organization
   * GET /api/organizations/:organizationId/users/:id
   */
  async getUser(
    request: FastifyRequest<{ Params: { organizationId: string; id: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId, id } = request.params
    const identity = await kratosService.getIdentity(id)
    assertOrganizationMatch(identity, organizationId)
    return reply.send(identity)
  }

  /**
   * Create a user in an organization
   * POST /api/organizations/:organizationId/users
   */
  async createUser(
    request: FastifyRequest<{
      Params: { organizationId: string }
      Body: OrganizationUserCreateBody
    }>,
    reply: FastifyReply
  ) {
    const { organizationId } = request.params
    const { email, name, sendInvite } = organizationUserCreateBodySchema.parse(
      request.body
    )

    const kratosBody: KratosIdentityCreate = {
      schema_id: 'default',
      state: 'active',
      traits: { email, ...(name ? { name } : {}) },
      organization_id: organizationId,
    }

    const identity = await kratosService.createIdentity(kratosBody)

    if (sendInvite) {
      try {
        await kratosService.sendRecoveryEmail(identity.id)
        request.log.info(
          { id: identity.id, email },
          'Recovery email dispatched for organization user'
        )
      } catch (err) {
        request.log.warn(
          { err, id: identity.id },
          'Created organization user but failed to send invite'
        )
      }
    }

    auditEventService
      .emit({
        type: 'organization_user.created',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id: identity.id },
        details: { email, organizationId, sendInvite },
        source: 'jinbe-api',
      })
      .catch(() => {})

    return reply.status(201).send(identity)
  }

  /**
   * Update a user within an organization
   * PUT /api/organizations/:organizationId/users/:id
   */
  async updateUser(
    request: FastifyRequest<{
      Params: { organizationId: string; id: string }
      Body: OrganizationUserUpdateBody
    }>,
    reply: FastifyReply
  ) {
    const { organizationId, id } = request.params
    const body = organizationUserUpdateBodySchema.parse(request.body)

    const current = await kratosService.getIdentity(id)
    assertOrganizationMatch(current, organizationId)

    const identity = await kratosService.updateIdentity(id, body)

    auditEventService
      .emit({
        type: 'organization_user.updated',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id },
        details: { organizationId, ...body },
        source: 'jinbe-api',
      })
      .catch(() => {})

    return reply.send(identity)
  }

  /**
   * Get a user's groups within an organization
   * GET /api/organizations/:organizationId/users/:id/groups
   */
  async getUserGroups(
    request: FastifyRequest<{ Params: { organizationId: string; id: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId, id } = request.params

    const identity = await kratosService.getIdentity(id)
    assertOrganizationMatch(identity, organizationId)

    const email = identity.traits?.email as string
    const groups = await kratosService.getUserGroups(email)
    const availableGroups = await rbacService.getAvailableGroups()

    return reply.send({ email, groups, availableGroups })
  }

  /**
   * Update a user's groups within an organization
   * PUT /api/organizations/:organizationId/users/:id/groups
   */
  async updateUserGroups(
    request: FastifyRequest<{
      Params: { organizationId: string; id: string }
      Body: { groups: string[] }
    }>,
    reply: FastifyReply
  ) {
    const { organizationId, id } = request.params
    const { groups } = updateUserGroupsBodySchema.parse(request.body)

    const identity = await kratosService.getIdentity(id)
    assertOrganizationMatch(identity, organizationId)

    const email = identity.traits?.email as string

    await rbacService.validateGroups(groups)

    const result = await userGroupsService.applyGroupUpdate({
      identity: { id, email, organizationId },
      newGroups: groups,
      actor: { email: request.userContext?.email, ip: request.ip },
      privilegePolicy: {
        kind: 'wildcard_in_org',
        orgId: organizationId,
        actorPermissions: request.rbacInfo?.permissions ?? [],
      },
      auditEventType: 'organization_user.groups_changed',
      auditExtraDetails: { organizationId },
    })

    if (!result.ok) return reply.status(result.status).send(result.body)
    return reply.send(result.response)
  }

  /**
   * Delete a user from an organization
   * DELETE /api/organizations/:organizationId/users/:id
   */
  async deleteUser(
    request: FastifyRequest<{ Params: { organizationId: string; id: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId, id } = request.params

    const identity = await kratosService.getIdentity(id)
    assertOrganizationMatch(identity, organizationId)

    await kratosService.deleteIdentity(id)

    auditEventService
      .emit({
        type: 'organization_user.deleted',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id },
        details: { organizationId },
        source: 'jinbe-api',
      })
      .catch(() => {})

    return reply.status(204).send()
  }
}

export const organizationUserController = new OrganizationUserController()
