import { FastifyReply, FastifyRequest } from 'fastify'
import { kratosService, KratosApiError } from '../services/kratos.service.js'
import { rbacResolverService } from '../services/rbac-resolver.service.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { env } from '../config/env.js'
import {
  KratosIdentity,
  KratosIdentityCreate,
  KratosIdentityUpdate,
  UsersQueryParams,
  usersQuerySchema,
  updateUserGroupsBodySchema,
} from '../schemas/admin.schema.js'

/**
 * Identity with RBAC information resolved directly from Kratos + Git
 */
interface IdentityWithRbac extends KratosIdentity {
  groups: string[]
  roles: string[]
  permissions: string[]
}

/**
 * Admin Controller
 * Handles user management via Kratos Admin API
 */
export class AdminController {
  /**
   * Enrich identity with RBAC info resolved directly from Kratos + Git
   * (No OPAL dependency - uses rbacResolverService for direct resolution)
   */
  private async enrichWithRbac(identity: KratosIdentity): Promise<IdentityWithRbac> {
    const email = identity.traits?.email
    if (!email) {
      return { ...identity, groups: [], roles: [], permissions: [] }
    }

    // Direct resolution from Kratos (groups) + Git (definitions)
    const rbacInfo = await rbacResolverService.resolveUserRbac(email, env.APP_NAME)

    return {
      ...identity,
      groups: rbacInfo.groups,
      roles: rbacInfo.roles,
      permissions: rbacInfo.permissions,
    }
  }

  /**
   * List all users
   * GET /api/admin/users
   */
  async listUsers(
    request: FastifyRequest<{ Querystring: UsersQueryParams }>,
    reply: FastifyReply
  ) {
    const { page_size, page_token, credentials_identifier } =
      usersQuerySchema.parse(request.query)

    // Pull TOTP / WebAuthn / lookup_secret credentials so the admin UI
    // can show the per-user 2FA column and gate privileged-group
    // assignment without an extra round trip per identity.
    const { identities, nextPageToken } = await kratosService.listIdentities(
      page_size,
      page_token,
      credentials_identifier,
      ['totp', 'webauthn', 'lookup_secret'],
    )

    // Enrich all identities with RBAC info in parallel
    const identitiesWithRbac = await Promise.all(
      identities.map((identity) => this.enrichWithRbac(identity))
    )

    return reply.send({
      data: identitiesWithRbac,
      next_page_token: nextPageToken,
    })
  }

  /**
   * Get user by ID
   * GET /api/admin/users/:id
   */
  async getUser(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const identity = await kratosService.getIdentity(id)
    const identityWithRbac = await this.enrichWithRbac(identity)
    return reply.send(identityWithRbac)
  }

  /**
   * Create new user
   * POST /api/admin/users
   * Accepts simplified body: { email, name?, groups?, sendInvite? }
   * or full Kratos body: { traits: { email, ... }, ... }
   */
  async createUser(
    request: FastifyRequest<{ Body: KratosIdentityCreate & { email?: string; name?: string; groups?: string[]; sendInvite?: boolean } }>,
    reply: FastifyReply
  ) {
    const body = request.body as Record<string, unknown>

    // Normalize simplified { email, name, groups, sendInvite } → Kratos format
    let kratosBody: KratosIdentityCreate
    let groups: string[] | undefined
    let sendInvite = false

    if (body.email && !body.traits) {
      groups = body.groups as string[] | undefined
      sendInvite = Boolean(body.sendInvite)
      kratosBody = {
        schema_id: 'default',
        state: 'active',
        traits: { email: body.email as string, ...(body.name ? { name: body.name as string } : {}) },
      } as KratosIdentityCreate
    } else {
      kratosBody = body as KratosIdentityCreate
    }

    const identity = await kratosService.createIdentity(kratosBody)

    // Set groups if provided
    if (groups && groups.length > 0) {
      try {
        await kratosService.updateUserGroups(identity.traits?.email as string, groups)
        rbacService.notifyBindingsChanged('user_created', { email: request.userContext?.email, ip: request.ip }).catch(() => {})
      } catch (err) {
        request.log.warn({ err, id: identity.id }, 'Created user but failed to set groups')
      }
    }

    // Send invite email via Kratos self-service recovery flow
    if (sendInvite) {
      try {
        await kratosService.sendRecoveryEmail(identity.id)
        request.log.info({ id: identity.id, email: identity.traits?.email }, 'Recovery email dispatched')
      } catch (err) {
        request.log.warn({ err, id: identity.id }, 'Created user but failed to send invite email')
      }
    }

    auditEventService.emit({
      type: 'user.created',
      actor: { email: request.userContext?.email, ip: request.ip },
      target: { type: 'user', id: identity.id },
      details: { email: identity.traits?.email, groups, sendInvite },
      source: 'jinbe-api',
    }).catch(() => {})
    return reply.status(201).send(identity)
  }

  /**
   * Patch user metadata_public or metadata_admin
   * PATCH /api/admin/users/:id/metadata
   */
  async setUserMetadata(
    request: FastifyRequest<{
      Params: { id: string }
      Body: { metadata_public?: Record<string, unknown>; metadata_admin?: Record<string, unknown> }
    }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const { metadata_public, metadata_admin } = request.body
    const current = await kratosService.getIdentity(id)
    const identity = await kratosService.updateIdentity(id, {
      metadata_public: metadata_public !== undefined
        ? { ...(current.metadata_public as Record<string, unknown> ?? {}), ...metadata_public }
        : current.metadata_public,
      metadata_admin: metadata_admin !== undefined
        ? { ...(current.metadata_admin as Record<string, unknown> ?? {}), ...metadata_admin }
        : current.metadata_admin,
    } as KratosIdentityUpdate)
    if (metadata_admin !== undefined) {
      kratosService.invalidateGroupsCache()
      rbacService.notifyBindingsChanged('metadata_updated', { email: request.userContext?.email, ip: request.ip }).catch(() => {})
    }
    auditEventService.emit({
      type: 'user.updated',
      actor: { email: request.userContext?.email, ip: request.ip },
      target: { type: 'user', id },
      details: { metadata_public, metadata_admin },
      source: 'jinbe-api',
    }).catch(() => {})
    return reply.send(identity)
  }

  /**
   * Set user state (active/inactive)
   * PATCH /api/admin/users/:id/state
   */
  async setUserState(
    request: FastifyRequest<{ Params: { id: string }; Body: { state: 'active' | 'inactive' } }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const { state } = request.body
    const identity = await kratosService.updateIdentity(id, { state } as KratosIdentityUpdate)
    auditEventService.emit({
      type: 'user.updated',
      actor: { email: request.userContext?.email, ip: request.ip },
      target: { type: 'user', id },
      details: { state },
      source: 'jinbe-api',
    }).catch(() => {})
    return reply.send(identity)
  }

  /**
   * Update user by ID
   * PUT /api/admin/users/:id
   */
  async updateUser(
    request: FastifyRequest<{
      Params: { id: string }
      Body: KratosIdentityUpdate
    }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const identity = await kratosService.updateIdentity(id, request.body)
    if ((request.body as Record<string, unknown>).metadata_admin !== undefined) {
      kratosService.invalidateGroupsCache()
      rbacService.notifyBindingsChanged('metadata_updated', { email: request.userContext?.email, ip: request.ip }).catch(() => {})
    }
    auditEventService.emit({
      type: 'user.updated',
      actor: { email: request.userContext?.email, ip: request.ip },
      target: { type: 'user', id },
      details: { email: identity.traits?.email },
      source: 'jinbe-api',
    }).catch(() => {})
    return reply.send(identity)
  }

  /**
   * Delete user by ID
   * DELETE /api/admin/users/:id
   */
  async deleteUser(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    kratosService.invalidateGroupsCache()
    await kratosService.deleteIdentity(id)
    rbacService.notifyBindingsChanged('user_deleted', { email: request.userContext?.email, ip: request.ip }).catch(() => {})
    auditEventService.emit({
      type: 'user.deleted',
      actor: { email: request.userContext?.email, ip: request.ip },
      target: { type: 'user', id },
      source: 'jinbe-api',
    }).catch(() => {})
    return reply.status(204).send()
  }

  /**
   * Get a user's groups
   * GET /api/admin/users/:email/groups
   */
  async getUserGroups(
    request: FastifyRequest<{
      Params: { email: string }
    }>,
    reply: FastifyReply
  ) {
    const { email } = request.params

    request.log.info({ email }, 'Fetching user groups')

    try {
      // Get user's current groups from Kratos
      const groups = await kratosService.getUserGroups(email)

      // Get available groups from RBAC service
      const availableGroups = await rbacService.getAvailableGroups()

      return reply.send({
        email,
        groups,
        availableGroups,
      })
    } catch (error) {
      if (error instanceof KratosApiError && error.statusCode === 404) {
        return reply.status(404).send({
          error: 'Not Found',
          message: `User not found: ${email}`,
        })
      }
      throw error
    }
  }

  /**
   * Update a user's groups
   * PUT /api/admin/users/:email/groups
   */
  async updateUserGroups(
    request: FastifyRequest<{
      Params: { email: string }
      Body: { groups: string[] }
    }>,
    reply: FastifyReply
  ) {
    const { email } = request.params
    const { groups } = updateUserGroupsBodySchema.parse(request.body)

    request.log.info(
      { email, groups, adminEmail: request.userContext?.email },
      'Updating user groups'
    )

    try {
      // Validate groups exist in groups.json
      await rbacService.validateGroups(groups)

      // Get old groups for audit trail. Default empty so the diff
      // computation below can't choke on undefined when Kratos returns
      // nothing or the call short-circuits.
      let oldGroups: string[] = []
      try {
        const fetched = await kratosService.getUserGroups(email)
        if (Array.isArray(fetched)) oldGroups = fetched
      } catch { /* ignore — user may not have groups yet */ }

      // Ensure user always has at least ['users'] if empty
      const finalGroups = groups.length > 0 ? groups : ['users']

      const newlyAdded = finalGroups.filter(g => !oldGroups.includes(g))

      // Privilege-escalation guard: an actor with rbac:write permission
      // (admin) must NOT be able to grant a group that confers admin or
      // super_admin power to someone else (or themselves). Only a
      // super_admin can grant such a group. Run BEFORE the MFA gate so
      // the failure mode is "you can't" rather than "the target needs
      // MFA" — the latter would hint at a workaround that doesn't exist.
      if (newlyAdded.length > 0) {
        for (const g of newlyAdded) {
          if (await rbacService.isAdminPowerGroup(g)) {
            try {
              await rbacService.assertSuperAdmin(
                `assign group '${g}' (grants admin privileges)`,
                { email: request.userContext?.email },
              )
            } catch (e) {
              const err = e as Error & { statusCode?: number }
              // Map to 422 (not 403) for the same ingress-nginx body/CORS
              // reason as the MFA gate below.
              return reply.status(err.statusCode === 401 ? 401 : 422).send({
                error: 'privilege_escalation_blocked',
                message: err.message,
                targetEmail: email,
                blockingGroup: g,
                hint: 'Only an existing super_admin can grant admin or super_admin groups.',
              })
            }
          }
        }
      }

      // MFA gate: block assignment to a privileged group (one whose
      // metadata is system: true AND that grants admin/super_admin) when
      // the target identity has no second factor configured. Prevents
      // an operator from one-clicking a fresh user into super_admins
      // without SOC2-grade auth.
      if (newlyAdded.length > 0) {
        let identityId: string | null = null
        try {
          const ident = await kratosService.findByEmail(email)
          identityId = ident?.id ?? null
        } catch { /* identity lookup failed — fall through, MFA gate skipped */ }
        if (identityId) {
          const blocker = await rbacService.findPrivilegedGroupRequiringMFA(newlyAdded, identityId)
          if (blocker) {
            // 422 Unprocessable Entity: request well-formed but a business
            // rule (privileged-group MFA requirement) refuses it. We cannot
            // use 403 because the cluster ingress-nginx ConfigMap reroutes
            // 4xx/5xx through a custom default-backend that strips the JSON
            // body and CORS headers, leaving the browser with "Failed to
            // fetch". 422 is not in that intercepted list, so the body and
            // ACAO header reach the kuma client and the toast can fire.
            return reply.status(422).send({
              error: 'mfa_required',
              message: `Group '${blocker}' grants admin privileges; the target user must enroll a second factor (TOTP, security key, or backup codes) before being added.`,
              targetEmail: email,
              targetGroups: newlyAdded,
              hint: 'Have the user complete /settings → Authenticator app, then retry.',
            })
          }
        }
      }

      // Update in Kratos (also invalidates in-memory cache)
      await kratosService.updateUserGroups(email, finalGroups)

      // Notify OPAL immediately so OPA doesn't wait up to 30s for next poll
      rbacService.notifyBindingsChanged('groups_changed', { email: request.userContext?.email, ip: request.ip }).catch(() => {})

      auditEventService.emit({
        type: 'user.groups_changed',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id: email },
        details: { oldGroups, newGroups: finalGroups },
        source: 'jinbe-api',
      }).catch(() => {})

      return reply.send({
        email,
        groups: finalGroups,
        updatedAt: new Date().toISOString(),
      })
    } catch (error) {
      if (error instanceof Error && error.message.includes('Invalid groups')) {
        return reply.status(400).send({
          error: 'Bad Request',
          message: error.message,
        })
      }
      if (error instanceof KratosApiError && error.statusCode === 404) {
        return reply.status(404).send({
          error: 'Not Found',
          message: `User not found: ${email}`,
        })
      }
      throw error
    }
  }
  /**
   * Set organization_id on an existing user via JSON Patch
   * PATCH /api/admin/users/:id/organization
   */
  async setUserOrganization(
    request: FastifyRequest<{
      Params: { id: string }
      Body: { organization_id: string | null }
    }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const { organization_id } = request.body

    const identity = await kratosService.patchIdentity(id, [
      { op: 'replace', path: '/organization_id', value: organization_id },
    ])

    auditEventService.emit({
      type: 'user.organization_changed',
      actor: { email: request.userContext?.email, ip: request.ip },
      target: { type: 'user', id },
      details: { organization_id },
      source: 'jinbe-api',
    }).catch(() => {})

    return reply.send(identity)
  }

  async listUserSessions(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    const sessions = await kratosService.listIdentitySessions(id)
    return reply.send(sessions)
  }

  async revokeSession(
    request: FastifyRequest<{ Params: { sessionId: string } }>,
    reply: FastifyReply
  ) {
    const { sessionId } = request.params
    await kratosService.revokeSession(sessionId)
    return reply.status(204).send()
  }

  async revokeAllUserSessions(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    await kratosService.revokeAllIdentitySessions(id)
    return reply.status(204).send()
  }

  async sendRecoveryEmail(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
  ) {
    const { id } = request.params
    try {
      await kratosService.sendRecoveryEmail(id)
      auditEventService.emit({
        type: 'user.recovery_email_sent',
        actor: { email: request.userContext?.email, ip: request.ip },
        target: { type: 'user', id },
        source: 'jinbe-api',
      }).catch(() => {})
      return reply.status(204).send()
    } catch (error) {
      if (error instanceof KratosApiError && error.statusCode === 404) {
        return reply.status(404).send({ error: 'Not Found', message: 'User not found' })
      }
      throw error
    }
  }
}

export const adminController = new AdminController()
