import { FastifyReply, FastifyRequest } from 'fastify'
import { kratosService, KratosApiError } from '../services/kratos.service.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { orgRolesRepository } from '../services/org-roles.repository.js'
import { directGrantsRepository } from '../services/direct-grants.repository.js'
import { holdsInJinbe } from '../authz/opa.js'
import { auditActor } from '../utils/audit-actor.js'
import { KratosIdentity } from '../schemas/admin.schema.js'
import { notificationService } from '../server.js'
import {
  OrganizationUserUpdateBody,
  OrganizationUsersQuery,
  organizationUserUpdateBodySchema,
  organizationUsersQuerySchema,
} from '../schemas/organization-user.schema.js'
import { OrganisationStoreUnavailableError } from '../services/organisation-store.js'
import {
  identitiesInOrganisation,
  isMemberOf,
  joinOrganisation,
  leaveOrganisation,
} from '../services/org-membership.service.js'

/**
 * Refuses, as not found, an identity that does not belong to the organisation. Belonging is any of
 * its organisations — not only the primary one, which hid a second organisation's members from it.
 */
async function assertOrganizationMatch(identity: KratosIdentity, organizationId: string): Promise<void> {
  if (!(await isMemberOf(identity, organizationId))) {
    throw new KratosApiError(404, 'User not found in this organization')
  }
}

/** A membership write the directory refused: an outage to retry, never a silent partial success. */
function storeUnavailable(reply: FastifyReply, err: unknown) {
  if (!(err instanceof OrganisationStoreUnavailableError)) throw err
  return reply.status(503).send({
    error: 'Service Unavailable',
    message: 'The membership could not be changed. Please try again later.',
  })
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
    // server-side (exact match, Kratos `credentials_identifier`). Includes the members whose
    // primary organisation is another one.
    const identities = await identitiesInOrganisation(organizationId, {
      pageSize: page_size,
      credentialsIdentifier: credentials_identifier,
    })

    // Each member's org roles here, in the same answer (one read of the org's assignments, no N+1).
    const roles = await orgRolesRepository.getForOrg(organizationId)
    const data = identities.map((i) => ({ ...i, roles: roles[i.id] ?? [] }))
    return reply.send({ data, total: data.length })
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
    await assertOrganizationMatch(identity, organizationId)
    return reply.send(identity)
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
    await assertOrganizationMatch(current, organizationId)

    // Only the name, merged into the traits the account has (never its address or state).
    const traits = { ...((current.traits ?? {}) as Record<string, unknown>), ...(body.traits?.name !== undefined ? { name: body.traits.name } : {}) }
    const identity = await kratosService.updateIdentity(id, { traits } as never)

    kratosService.invalidateGroupsCache()
    rbacService.notifyBindingsChanged('user_updated', auditActor(request)).catch(() => {})

    auditEventService
      .emit({
        type: 'organization_user.updated',
        actor: auditActor(request),
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
   * Remove a user from an organization — that membership only
   * DELETE /api/organizations/:organizationId/users/:id
   *
   * The identity stays, and so do its other organisations and its site access: leaving one company
   * is not leaving the platform. What this replaced deleted the whole identity and then dropped its
   * memberships everywhere. Deleting a person is a platform act (`DELETE /api/admin/users/:id`).
   */
  async deleteUser(
    request: FastifyRequest<{ Params: { organizationId: string; id: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId, id } = request.params

    const identity = await kratosService.getIdentity(id)
    await assertOrganizationMatch(identity, organizationId)

    try {
      await leaveOrganisation(identity, organizationId)
      // Their org roles and direct grants there go with the membership (without it they grant nothing anyway).
      await orgRolesRepository.forgetMember(organizationId, id)
      await directGrantsRepository.forgetOrg(id, organizationId)
    } catch (err) {
      return storeUnavailable(reply, err)
    }

    kratosService.invalidateGroupsCache()
    rbacService.notifyBindingsChanged('organization_changed', auditActor(request)).catch(() => {})

    auditEventService
      .emit({
        type: 'organization_user.membership_removed',
        actor: auditActor(request),
        target: { type: 'user', id },
        details: { organizationId },
        source: 'jinbe-api',
      })
      .catch(() => {})

    notificationService.emit({ action: 'updated', entity_type: 'user', payload: { id, organization_id: organizationId } })
    return reply.status(204).send()
  }

  /**
   * Add an existing user to this organization, keeping every other membership
   * PUT /api/organizations/:organizationId/users/:id/membership
   */
  async addMembership(
    request: FastifyRequest<{ Params: { organizationId: string; id: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId, id } = request.params

    // Adding somebody's existing account by id is the platform's (orgs.members:write): an org admin
    // could otherwise pull any account into its org, then act on it as a member. Org admins invite.
    const caller = request.userContext?.email
    if (!caller || !(await holdsInJinbe(caller, 'orgs.members:write'))) {
      return reply.status(403).send({
        error: 'Forbidden',
        code: 'invite_instead',
        message: "Adding an existing account to an organization by its id is done by the platform. Invite the person by email instead.",
      })
    }

    const identity = await kratosService.getIdentity(id)
    try {
      await joinOrganisation(identity, organizationId)
    } catch (err) {
      return storeUnavailable(reply, err)
    }

    kratosService.invalidateGroupsCache()
    rbacService.notifyBindingsChanged('organization_changed', auditActor(request)).catch(() => {})

    auditEventService
      .emit({
        type: 'organization_user.membership_added',
        actor: auditActor(request),
        target: { type: 'user', id },
        details: { organizationId },
        source: 'jinbe-api',
      })
      .catch(() => {})

    notificationService.emit({ action: 'updated', entity_type: 'user', payload: { id, organization_id: organizationId } })
    return reply.status(200).send(await kratosService.getIdentity(id))
  }
}

export const organizationUserController = new OrganizationUserController()
