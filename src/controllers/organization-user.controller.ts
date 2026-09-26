import { FastifyReply, FastifyRequest } from 'fastify'
import { kratosService, KratosApiError } from '../services/kratos.service.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { userGroupsService } from '../services/user-groups.service.js'
import { auditActor } from '../utils/audit-actor.js'
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
import { env } from '../config/index.js'
import { addMember, OrganisationStoreUnavailableError } from '../services/organisation-store.js'
import { declaredGroups } from '../services/group-catalogue.js'
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

/**
 * Record an assignment where this service owns membership.
 *
 * Does nothing in the other modes: there the set is inferred from groups or asserted by a token,
 * and writing a record would create a second answer that nothing reconciles.
 *
 * A failure is reported and never swallowed, but it does not undo the identity: the person exists
 * and can be assigned again, whereas rolling back would delete an account somebody may already have
 * been told about.
 */
async function recordMembership(
  organisationId: string,
  subjectId: string,
  request: FastifyRequest
): Promise<void> {
  if (env.ORGANISATION_SOURCE !== 'directory') return
  try {
    await addMember(organisationId, subjectId, 'member')
  } catch (err) {
    request.log.error(
      { err, organisationId, subjectId },
      'Created the identity but could not record its membership'
    )
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
    // server-side (exact match, Kratos `credentials_identifier`). Includes the members whose
    // primary organisation is another one.
    const identities = await identitiesInOrganisation(organizationId, {
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
    await assertOrganizationMatch(identity, organizationId)
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

    const kratosBody: KratosIdentityCreate = {
      schema_id: 'default',
      state: 'active',
      traits: { email, ...(name ? { name } : {}) },
      organization_id: organizationId,
      // Persist the base `users` group up front for the no-privileged-group
      // case, so an invited user visibly holds `users` rather than showing
      // null/empty in the UI. When groups need a grant check, applyGroupUpdate
      // below sets them (with rollback), so leave metadata_admin unset here.
      ...(needsGrantCheck ? {} : { metadata_admin: { groups: desiredGroups } }),
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
        actor: { ...auditActor(request), aal: request.userContext?.aal, authenticatedAt: request.userContext?.authenticatedAt, secondFactorAt: request.userContext?.secondFactorAt, authVia: request.userContext?.authVia },
        privilegePolicy: {
          kind: 'wildcard_in_org',
          orgId: organizationId,
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

    // Where this service owns membership, the assignment is a record here — not something read
    // back out of the identity's own metadata. Written AFTER the grant check, so a refused
    // privilege never leaves a membership behind the rollback.
    await recordMembership(organizationId, identity.id, request)

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
    rbacService.notifyBindingsChanged('user_created', auditActor(request)).catch(() => {})

    auditEventService
      .emit({
        type: 'organization_user.created',
        actor: auditActor(request),
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
    await assertOrganizationMatch(current, organizationId)

    const identity = await kratosService.updateIdentity(id, body)

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
   * Get a user's groups within an organization
   * GET /api/organizations/:organizationId/users/:id/groups
   */
  async getUserGroups(
    request: FastifyRequest<{ Params: { organizationId: string; id: string } }>,
    reply: FastifyReply
  ) {
    const { organizationId, id } = request.params

    const identity = await kratosService.getIdentity(id)
    await assertOrganizationMatch(identity, organizationId)

    const email = identity.traits?.email as string
    const groups = await kratosService.getUserGroups(email)
    const availableGroups = await declaredGroups()

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
    await assertOrganizationMatch(identity, organizationId)

    const email = identity.traits?.email as string

    const result = await userGroupsService.applyGroupUpdate({
      identity: { id, email, organizationId },
      newGroups: groups,
      actor: { ...auditActor(request), aal: request.userContext?.aal, authenticatedAt: request.userContext?.authenticatedAt, secondFactorAt: request.userContext?.secondFactorAt, authVia: request.userContext?.authVia },
      privilegePolicy: {
        kind: 'wildcard_in_org',
        orgId: organizationId,
      },
      auditEventType: 'organization_user.groups_changed',
      auditExtraDetails: { organizationId },
    })

    if (!result.ok) return reply.status(result.status).send(result.body)
    return reply.send(result.response)
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
