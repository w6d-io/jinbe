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

    const { identities, nextPageToken } = await kratosService.listIdentities(
      page_size,
      page_token,
      credentials_identifier
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
    await kratosService.deleteIdentity(id)
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

      // Get old groups for audit trail
      let oldGroups: string[] = []
      try {
        oldGroups = await kratosService.getUserGroups(email)
      } catch { /* ignore — user may not have groups yet */ }

      // Ensure user always has at least ['users'] if empty
      const finalGroups = groups.length > 0 ? groups : ['users']

      // Update in Kratos
      await kratosService.updateUserGroups(email, finalGroups)

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
}

export const adminController = new AdminController()
