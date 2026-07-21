import { FastifyReply, FastifyRequest } from 'fastify'
import { kratosService, KratosApiError } from '../services/kratos.service.js'
import { rbacResolverService } from '../services/rbac-resolver.service.js'
import { rbacService } from '../services/rbac.service.js'
import { auditEventService } from '../services/audit-event.service.js'
import { userGroupsService } from '../services/user-groups.service.js'
import { env } from '../config/env.js'
import { notificationService } from '../server.js'
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
 * `metadata_admin.groups` is the AUTHORITATIVE group-membership source — it
 * drives the OPA bindings that grant every permission (kratos.service resolves
 * groups from it). It must therefore only ever change through the hardened
 * group endpoint (PUT /admin/users/:email/groups → userGroupsService.
 * applyGroupUpdate), which enforces the super_admin check, the can_grant
 * delegation/tenant-containment gate, and the MFA-enrolment gate.
 *
 * The generic identity writers (POST /users, PUT /users/:id, PATCH
 * /users/:id/metadata) must never be an escalation path, so they refuse any
 * attempt to set/alter groups and pin the persisted groups to their current
 * value. 422 (not 403) is deliberate and load-bearing: cluster ingress-nginx
 * `custom-http-errors` strips bodies from 4xx/5xx but lets 422 through, so the
 * client actually sees this message. See user-groups.service.ts.
 */
const GROUPS_NOT_MUTABLE_HERE = {
  error: 'groups_not_mutable_here',
  message:
    'Group membership (metadata_admin.groups) cannot be changed through this endpoint. ' +
    'Use PUT /admin/users/:email/groups (or the org-scoped groups endpoint), which enforces ' +
    'the super_admin, delegation, and MFA checks.',
}

/** Order-insensitive equality between a requested groups value and current groups. */
function sameGroups(requested: unknown, current: string[] | undefined): boolean {
  const cur = Array.isArray(current) ? current.map(String) : []
  if (!Array.isArray(requested)) return cur.length === 0
  if (requested.length !== cur.length) return false
  const a = [...requested].map(String).sort()
  const b = [...cur].sort()
  return a.every((v, i) => v === b[i])
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
   * Directory stats for the dashboard — cached counts, no full directory walk.
   * GET /api/admin/stats
   */
  async getStats(_request: FastifyRequest, reply: FastifyReply) {
    const stats = await rbacService.getDirectoryStats()
    return reply.send(stats)
  }

  /**
   * Substring search over identities (email + name) for the admin UI, backed by
   * the cached in-memory identity map — no directory walk per query.
   * GET /api/admin/users/search?q=&limit=
   */
  async searchUsers(
    request: FastifyRequest<{ Querystring: { q?: string; limit?: string } }>,
    reply: FastifyReply,
  ) {
    const q = (request.query.q ?? '').toString()
    const limit = Math.min(Math.max(parseInt(request.query.limit ?? '50', 10) || 50, 1), 200)
    const data = await kratosService.searchIdentities(q, limit)
    // Enrich each hit with its REAL second-factor status so the search table shows
    // ON/OFF instead of "—". searchIdentities is a lightweight cache (no
    // credentials), so hasMFA is resolved per hit here — bounded by `limit`, run in
    // parallel, and fail-soft (an error → undefined → that row shows "unknown"
    // rather than failing the whole search).
    const withMfa = await Promise.all(
      data.map(async (u) => {
        let mfa: boolean | undefined
        try {
          mfa = await kratosService.hasMFA(u.id)
        } catch {
          mfa = undefined
        }
        return { ...u, mfa }
      }),
    )
    return reply.send({ data: withMfa })
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
    let requestedGroups: string[] | undefined
    let sendInvite = false

    if (body.email && !body.traits) {
      requestedGroups = body.groups as string[] | undefined
      sendInvite = Boolean(body.sendInvite)
      kratosBody = {
        schema_id: 'default',
        state: 'active',
        traits: { email: body.email as string, ...(body.name ? { name: body.name as string } : {}) },
      } as KratosIdentityCreate
    } else {
      // Full Kratos body. metadata_admin.groups is authoritative membership and
      // must not be set on this generic create path — extract it so it goes
      // through the hardened grant gate below, then strip it from the create body.
      kratosBody = { ...(body as KratosIdentityCreate) }
      const meta = (kratosBody as Record<string, unknown>).metadata_admin as Record<string, unknown> | undefined
      if (meta && 'groups' in meta) {
        requestedGroups = meta.groups as string[] | undefined
        const { groups: _drop, ...rest } = meta
        ;(kratosBody as Record<string, unknown>).metadata_admin = rest
      }
    }

    // Base `users` confers nothing → no grant check (Kratos' default resolves an
    // ungrouped identity to `users` anyway). Any other group must clear the same
    // super_admin + MFA + validation gate as PUT /users/:email/groups.
    const desiredGroups = requestedGroups && requestedGroups.length > 0 ? requestedGroups : ['users']
    const needsGrantCheck = !(desiredGroups.length === 1 && desiredGroups[0] === 'users')

    // Validate group existence BEFORE creating so a bad request never orphans a user.
    if (needsGrantCheck) {
      await rbacService.validateGroups(desiredGroups)
    }

    const identity = await kratosService.createIdentity(kratosBody)

    // A new identity bumps total/active (and perGroup['users'] via the default)
    // even when no groups are passed — the groups-gated notify below can miss
    // it, so bust stats unconditionally.
    rbacService.invalidateDirectoryStats().catch(() => {})

    // Assign requested groups through the SAME containment/MFA guard as the
    // group-assign endpoint. A blocked grant rolls the just-created identity
    // back so a refused privilege escalation can never strand a half-provisioned
    // user (mirrors organization-user.controller.createUser).
    if (needsGrantCheck) {
      const grant = await userGroupsService.applyGroupUpdate({
        identity: {
          id: identity.id,
          email: identity.traits?.email as string,
          organizationId: ((identity as Record<string, unknown>).organization_id as string | null) ?? null,
        },
        newGroups: desiredGroups,
        actor: { email: request.userContext?.email, ip: request.ip, aal: request.userContext?.aal, authenticatedAt: request.userContext?.authenticatedAt },
        privilegePolicy: { kind: 'super_admin_required' },
        auditEventType: 'user.groups_changed',
      })
      if (!grant.ok) {
        await kratosService.deleteIdentity(identity.id).catch((err) => {
          request.log.error({ err, id: identity.id }, 'Failed to roll back user after a blocked group assignment')
        })
        return reply.status(grant.status).send(grant.body)
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
      details: { email: identity.traits?.email, groups: desiredGroups, sendInvite },
      source: 'jinbe-api',
    }).catch(() => {})
    notificationService.emit({
      action: 'created', entity_type: 'user',
      payload: { id: identity.id, organization_id: (identity as any).organization_id ?? null, email: identity.traits?.email, display_name: identity.traits?.name, status: identity.state, created_at: identity.created_at, updated_at: identity.updated_at },
    })
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
    const currentGroups = (current.metadata_admin as Record<string, unknown> | undefined)?.groups as string[] | undefined

    // Group membership is authoritative and only mutable via the hardened group
    // endpoint. Refuse an attempt to change it; strip a no-op `groups` key so the
    // merge below preserves the current membership rather than this write setting it.
    let adminToMerge = metadata_admin
    if (metadata_admin !== undefined && 'groups' in metadata_admin) {
      if (!sameGroups(metadata_admin.groups, currentGroups)) {
        return reply.status(422).send(GROUPS_NOT_MUTABLE_HERE)
      }
      const { groups: _drop, ...rest } = metadata_admin
      adminToMerge = rest
    }

    const identity = await kratosService.updateIdentity(id, {
      metadata_public: metadata_public !== undefined
        ? { ...(current.metadata_public as Record<string, unknown> ?? {}), ...metadata_public }
        : current.metadata_public,
      metadata_admin: adminToMerge !== undefined
        ? { ...(current.metadata_admin as Record<string, unknown> ?? {}), ...adminToMerge }
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
    notificationService.emit({
      action: 'updated', entity_type: 'user',
      payload: { id, email: identity.traits?.email, display_name: identity.traits?.name, status: identity.state },
    })
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
    // active count changed; this path bypasses invalidateBundle, so bust stats
    // directly (state doesn't affect RBAC bindings — no OPA notify needed).
    rbacService.invalidateDirectoryStats().catch(() => {})
    auditEventService.emit({
      type: 'user.updated',
      actor: { email: request.userContext?.email, ip: request.ip },
      target: { type: 'user', id },
      details: { state },
      source: 'jinbe-api',
    }).catch(() => {})
    notificationService.emit({
      action: 'updated', entity_type: 'user',
      payload: { id, email: identity.traits?.email, display_name: identity.traits?.name, status: identity.state },
    })
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
    const body = { ...(request.body as Record<string, unknown>) }

    // This is a FULL-REPLACE write (Kratos PUT). metadata_admin.groups is the
    // authoritative membership source; a caller must be able to neither set it
    // (escalation) nor accidentally wipe it (a replace that omits it). Read the
    // current groups, refuse any attempt to change them, and pin them to their
    // current value so the replace preserves membership. Group changes go only
    // through PUT /users/:email/groups.
    const current = await kratosService.getIdentity(id)
    const currentGroups = (current.metadata_admin as Record<string, unknown> | undefined)?.groups as string[] | undefined
    const incomingMeta = body.metadata_admin as Record<string, unknown> | undefined
    if (incomingMeta && 'groups' in incomingMeta && !sameGroups(incomingMeta.groups, currentGroups)) {
      return reply.status(422).send(GROUPS_NOT_MUTABLE_HERE)
    }
    if (currentGroups !== undefined) {
      body.metadata_admin = { ...(incomingMeta ?? {}), groups: currentGroups }
    } else if (incomingMeta && 'groups' in incomingMeta) {
      const { groups: _drop, ...rest } = incomingMeta
      body.metadata_admin = rest
    }

    const identity = await kratosService.updateIdentity(id, body as KratosIdentityUpdate)
    if (body.metadata_admin !== undefined) {
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
    notificationService.emit({
      action: 'updated', entity_type: 'user',
      payload: { id, email: identity.traits?.email, display_name: identity.traits?.name, status: identity.state },
    })
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
    notificationService.emit({ action: 'deleted', entity_type: 'user', payload: { id } })
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
      await rbacService.validateGroups(groups)

      // Fail-closed identity resolution. Previously this was wrapped in a
      // try/catch that silently set identityId=null on failure, which let
      // the MFA gate fall through (`if (identityId)`) and allowed group
      // assignment without an MFA check when Kratos was degraded. Now any
      // resolution failure short-circuits with 404 / propagated error.
      const ident = await kratosService.findByEmail(email)
      if (!ident) {
        return reply.status(404).send({
          error: 'Not Found',
          message: `User not found: ${email}`,
        })
      }

      const result = await userGroupsService.applyGroupUpdate({
        identity: {
          id: ident.id,
          email,
          organizationId: ((ident as Record<string, unknown>).organization_id as string | null) ?? null,
        },
        newGroups: groups,
        actor: { email: request.userContext?.email, ip: request.ip, aal: request.userContext?.aal, authenticatedAt: request.userContext?.authenticatedAt },
        privilegePolicy: { kind: 'super_admin_required' },
        auditEventType: 'user.groups_changed',
      })

      if (!result.ok) return reply.status(result.status).send(result.body)
      return reply.send(result.response)
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

    kratosService.invalidateGroupsCache()
    rbacService.notifyBindingsChanged('organization_changed', { email: request.userContext?.email, ip: request.ip }).catch(() => {})

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
