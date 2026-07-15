import { FastifyReply, FastifyRequest } from 'fastify'
import { kratosService, KratosApiError } from '../services/kratos.service.js'
import { rbacService } from '../services/rbac.service.js'
import { opaService } from '../services/opa.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { auditEventService } from '../services/audit-event.service.js'
import { userGroupsService } from '../services/user-groups.service.js'
import {
  KratosIdentity,
  KratosIdentityCreate,
  updateUserGroupsBodySchema,
} from '../schemas/admin.schema.js'
import { notificationService } from '../server.js'
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

    // Paginates across ALL pages (J9) and applies the identifier filter
    // server-side (exact match, Kratos `credentials_identifier`).
    const { identities } = await kratosService.listIdentitiesByOrganization(organizationId, {
      pageSize: page_size,
      credentialsIdentifier: credentials_identifier,
    })

    return reply.send({ data: identities, total: identities.length })
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
    const { email, name, sendInvite, groups } = organizationUserCreateBodySchema.parse(
      request.body
    )

    // Omitted / base `users` → no privileged grant, no delegation check. Any
    // other group is validated + containment-checked through the shared guard.
    const desiredGroups = groups && groups.length > 0 ? groups : ['users']
    const needsGrantCheck = !(desiredGroups.length === 1 && desiredGroups[0] === 'users')

    // Validate group existence BEFORE creating the identity so a bad request
    // never leaves an orphaned user.
    if (needsGrantCheck) {
      await rbacService.validateGroups(desiredGroups)
    }

    const kratosBody: KratosIdentityCreate = {
      schema_id: 'default',
      state: 'active',
      traits: { email, ...(name ? { name } : {}) },
      organization_id: organizationId,
    }

    const identity = await kratosService.createIdentity(kratosBody)

    // Assign the requested groups through the SAME containment guard as the
    // group-assign endpoint (delegation can_grant + global backstop + MFA).
    // A blocked grant rolls the just-created identity back so a refused
    // privilege escalation can never strand a half-provisioned user.
    if (needsGrantCheck) {
      const grant = await userGroupsService.applyGroupUpdate({
        identity: { id: identity.id, email, organizationId },
        newGroups: desiredGroups,
        actor: { email: request.userContext?.email, ip: request.ip },
        privilegePolicy: {
          kind: 'wildcard_in_org',
          orgId: organizationId,
          actorIsServiceAdmin: request.rbacInfo?.permissions.includes('*') ?? false,
        },
        auditEventType: 'organization_user.groups_changed',
        auditExtraDetails: { organizationId },
      })
      if (!grant.ok) {
        await kratosService.deleteIdentity(identity.id).catch((err) => {
          request.log.error(
            { err, id: identity.id },
            'Failed to roll back user after a blocked group assignment'
          )
        })
        return reply.status(grant.status).send(grant.body)
      }
    }

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

    kratosService.invalidateGroupsCache()
    rbacService.notifyBindingsChanged('user_created', { email: request.userContext?.email, ip: request.ip }).catch(() => {})

    auditEventService
      .emit({
        type: 'organization_user.created',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id: identity.id },
        details: { email, organizationId, sendInvite },
        source: 'jinbe-api',
      })
      .catch(() => {})

    notificationService.emit({
      action: 'created', entity_type: 'user',
      payload: { id: identity.id, organization_id: organizationId, email, display_name: name, status: identity.state, created_at: identity.created_at, updated_at: identity.updated_at },
    })
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

    kratosService.invalidateGroupsCache()
    rbacService.notifyBindingsChanged('user_updated', { email: request.userContext?.email, ip: request.ip }).catch(() => {})

    auditEventService
      .emit({
        type: 'organization_user.updated',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id },
        details: { organizationId, ...body },
        source: 'jinbe-api',
      })
      .catch(() => {})

    notificationService.emit({
      action: 'updated', entity_type: 'user',
      payload: { id, organization_id: organizationId, email: identity.traits?.email, display_name: identity.traits?.name, status: identity.state, created_at: identity.created_at, updated_at: identity.updated_at },
    })
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
        // Server-resolved by requireServiceAdmin (OPA getUserInfo), never client
        // input: does the caller hold `*` for this org's service?
        actorIsServiceAdmin: request.rbacInfo?.permissions.includes('*') ?? false,
      },
      auditEventType: 'organization_user.groups_changed',
      auditExtraDetails: { organizationId },
    })

    if (!result.ok) return reply.status(result.status).send(result.body)
    return reply.send(result.response)
  }

  /**
   * List the groups the caller may assign within this organization —
   * `assignable_groups` (delegation) scoped to the org's mapped service.
   * GET /api/organizations/:organizationId/assignable-groups
   *
   * The set is resolved by OPA from the caller's email (containment-bounded,
   * single-service, never global) and then narrowed to groups whose single
   * service is the one backing this org, so the UI can only ever offer groups
   * that the mutation guard (can_grant) would also accept. Fail-closed: OPA
   * error → []; org with no service mapping → [].
   */
  async listAssignableGroups(
    request: FastifyRequest<{ Params: { organizationId: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId } = request.params
    const email = request.userContext?.email
    if (!email || email === 'unknown') {
      return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    }

    const service = await redisRbacRepository.getServiceForOrg(organizationId)
    const assignable = await opaService.assignableGroups(email)
    if (!service || assignable.length === 0) {
      return reply.send({ groups: [] })
    }

    // Narrow to groups whose single (non-global) service is this org's service.
    const defs = await redisRbacRepository.getGroups()
    const groups = assignable.filter((g) => {
      const def = defs[g]
      if (!def) return false
      const svcs = Object.keys(def).filter(
        (s) => s !== 'global' && Array.isArray(def[s]) && def[s].length > 0
      )
      return svcs.length === 1 && svcs[0] === service
    })

    return reply.send({ groups })
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

    kratosService.invalidateGroupsCache()
    rbacService.notifyBindingsChanged('user_deleted', { email: request.userContext?.email, ip: request.ip }).catch(() => {})

    auditEventService
      .emit({
        type: 'organization_user.deleted',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id },
        details: { organizationId },
        source: 'jinbe-api',
      })
      .catch(() => {})

    notificationService.emit({ action: 'deleted', entity_type: 'user', payload: { id, organization_id: organizationId } })
    return reply.status(204).send()
  }
}

export const organizationUserController = new OrganizationUserController()
