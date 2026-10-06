import { FastifyReply, FastifyRequest } from 'fastify'
import { kratosService, KratosApiError } from '../services/kratos.service.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { orgRolesRepository } from '../services/org-roles.repository.js'
import { directGrantsRepository } from '../services/direct-grants.repository.js'
import { orgRoleRefusals } from '../services/org-role-grants.js'
import { AuthzUnavailableError, holdsInJinbe } from '../authz/opa.js'
import { directGrantsService, GrantNeedsSecondFactorError, GrantsRefusedError } from '../services/direct-grants.service.js'

/** A grant refusal at creation, as PUT …/users/:id/grants answers it. */
function grantRefusal(reply: FastifyReply, err: unknown) {
  if (err instanceof GrantsRefusedError) return reply.status(403).send({ error: 'Forbidden', code: 'grant_exceeds_own', message: err.message, refused: err.refused })
  if (err instanceof GrantNeedsSecondFactorError) return reply.status(422).send(err.body())
  if (err instanceof AuthzUnavailableError) return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: `Unable to verify authorization: ${err.message}` })
  if ((err as { statusCode?: number }).statusCode === 400) return reply.status(400).send({ error: 'Bad Request', message: (err as Error).message })
  throw err
}
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { auditActor } from '../utils/audit-actor.js'
import {
  KratosIdentity,
  KratosIdentityCreate,
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
import { addMember, membershipRowsKept, OrganisationStoreUnavailableError } from '../services/organisation-store.js'
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
 * Record an assignment where memberships are kept as rows (the postgres store).
 *
 * Does nothing otherwise: in the kratos store the identity just created already names the
 * organisation, and with a token the set is asserted by its issuer — a record here would be a second
 * answer that nothing reconciles.
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
  if (!membershipRowsKept()) return
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
    const { email, name, sendInvite, roles, grants } = organizationUserCreateBodySchema.parse(
      request.body
    )
    const grantsWanted = grants ?? []
    const grantOpts = {
      granteeEmail: email, wanted: grantsWanted, joining: true,
      actor: { ...auditActor(request), email: request.userContext?.email ?? '' },
      within: (scope: string) => scope === organizationId,
    }

    // Org roles given at creation clear the same holding rule as PUT …/users/:id/roles, BEFORE
    // anything is created: a refused role never leaves a half-provisioned person behind.
    const wanted = [...new Set(roles ?? [])]
    let refused
    try {
      refused = await orgRoleRefusals(request.userContext?.email ?? '', organizationId, wanted, { email, joining: true })
    } catch (err) {
      if (!(err instanceof AuthzUnavailableError)) throw err
      return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: `Unable to verify authorization: ${err.message}` })
    }
    if (refused.length > 0) {
      return reply.status(403).send({ error: 'Forbidden', message: `Not allowed to assign: ${refused.map((r) => r.role).join(', ')}`, refused })
    }
    // Direct grants given at creation (this org's only): the same verdicts as PUT …/users/:id/grants, up front.
    if (grantsWanted.length > 0) {
      try {
        await directGrantsService.check({ subjectId: '', ...grantOpts })
      } catch (err) {
        return grantRefusal(reply, err)
      }
    }

    const kratosBody: KratosIdentityCreate = {
      schema_id: 'default',
      state: 'active',
      traits: { email, ...(name ? { name } : {}) },
      organization_id: organizationId,
      // No platform group: what a member may do here comes from their org roles.
      metadata_admin: { groups: [] },
    }

    const identity = await kratosService.createIdentity(kratosBody)

    // Where this service owns membership, the assignment is a record here — not something read
    // back out of the identity's own metadata. Written AFTER the grant check, so a refused
    // privilege never leaves a membership behind the rollback.
    await recordMembership(organizationId, identity.id, request)
    if (wanted.length > 0) await orgRolesRepository.setForMember(organizationId, identity.id, wanted)
    if (grantsWanted.length > 0) {
      try {
        await directGrantsService.replace({ subjectId: identity.id, ...grantOpts })
      } catch (err) {
        // Allowed a moment ago: the person exists and is a member; say what did not land.
        request.log.warn({ err: (err as Error).message, id: identity.id }, 'Created the member, but the direct grants were refused on write')
        return grantRefusal(reply, err)
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
