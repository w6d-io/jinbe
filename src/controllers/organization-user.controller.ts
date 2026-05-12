import { FastifyReply, FastifyRequest } from 'fastify'
import { kratosService, KratosApiError } from '../services/kratos.service.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
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

function assertOrganizationMatch(identity: KratosIdentity, organizationId: string): void {
  const orgId = (identity as Record<string, unknown>).organization_id as string | null | undefined
  if (orgId !== organizationId) {
    throw new KratosApiError(404, 'User not found in this organization')
  }
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

    // Validate groups exist in groups.json
    await rbacService.validateGroups(groups)

    let oldGroups: string[] = []
    try {
      const fetched = await kratosService.getUserGroups(email)
      if (Array.isArray(fetched)) oldGroups = fetched
    } catch { /* user may not have groups yet */ }

    const finalGroups = groups.length > 0 ? groups : ['users']
    const newlyAdded = finalGroups.filter(g => !oldGroups.includes(g))

    // Privilege-escalation guard: use the OPA-resolved permissions from
    // requireServiceAdmin (scoped to the organizationId) instead of the
    // global super_admin check. The actor already passed
    // requireServicePermission('rbac:write') so we only block if they
    // lack the wildcard permission for this org.
    if (newlyAdded.length > 0) {
      const actorPermissions = request.rbacInfo?.permissions ?? []
      const hasWildcard = actorPermissions.includes('*')
      for (const g of newlyAdded) {
        if (await rbacService.isAdminPowerGroup(g)) {
          if (!hasWildcard) {
            return reply.status(422).send({
              error: 'privilege_escalation_blocked',
              message: `Cannot assign group '${g}' (grants admin privileges) — wildcard permission required for this organization`,
              targetEmail: email,
              blockingGroup: g,
              hint: 'The actor must hold the wildcard (*) permission for this organization.',
            })
          }
        }
      }
    }

    // MFA gate
    if (newlyAdded.length > 0) {
      const blocker = await rbacService.findPrivilegedGroupRequiringMFA(newlyAdded, id)
      if (blocker) {
        return reply.status(422).send({
          error: 'mfa_required',
          message: `Group '${blocker}' grants admin privileges; the target user must enroll a second factor (TOTP, security key, or backup codes) before being added.`,
          targetEmail: email,
          targetGroups: newlyAdded,
          hint: 'Have the user complete /settings → Authenticator app, then retry.',
        })
      }
    }

    await kratosService.updateUserGroups(email, finalGroups)
    rbacService.notifyBindingsChanged('groups_changed', { email: request.userContext?.email, ip: request.ip }).catch(() => {})

    auditEventService
      .emit({
        type: 'organization_user.groups_changed',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id },
        details: { organizationId, oldGroups, newGroups: finalGroups },
        source: 'jinbe-api',
      })
      .catch(() => {})

    return reply.send({
      id,
      organizationId,
      email,
      groups: finalGroups,
      updatedAt: new Date().toISOString(),
    })
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
