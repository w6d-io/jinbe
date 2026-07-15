import { kratosService } from './kratos.service.js'
import { rbacService } from './rbac.service.js'
import { auditEventService } from './audit-event.service.js'

/**
 * Identity the helper operates on. Resolved by the controller (different
 * lookups per route) and passed in fully populated — the helper never
 * looks up identities itself. Fail-closed: if the controller can't
 * resolve it, the request must 404 before reaching here.
 */
export type ResolvedIdentity = {
  id: string
  email: string
  organizationId: string | null
}

/**
 * Discriminated policy for the privilege-escalation gate.
 *
 * - `super_admin_required` — global admin endpoint. Refuses unless the
 *   actor holds the global super_admin role (queried via OPA inside
 *   rbacService.assertSuperAdmin).
 * - `wildcard_in_org` — org-scoped endpoint. Refuses unless the actor
 *   holds the `*` wildcard permission for the target organization
 *   (already resolved by requireServiceAdmin middleware).
 */
export type ActorPrivilegePolicy =
  | { kind: 'super_admin_required' }
  | { kind: 'wildcard_in_org'; orgId: string; actorPermissions: string[] }

export type ApplyGroupUpdateInput = {
  identity: ResolvedIdentity
  newGroups: string[]
  actor: { email?: string; ip?: string }
  privilegePolicy: ActorPrivilegePolicy
  auditEventType: string
  auditExtraDetails?: Record<string, unknown>
}

export type ApplyGroupUpdateResult =
  | { ok: true; response: Record<string, unknown> }
  | { ok: false; status: number; body: Record<string, unknown> }

/**
 * Shared core of "update a user's groups". Both the global admin endpoint
 * and the org-scoped endpoint funnel through here so the MFA gate, the
 * priv-escalation guard, the Kratos mutation, the OPAL notification and
 * the audit emit cannot drift between routes.
 *
 * 422 status preservation is load-bearing: cluster ingress-nginx
 * `custom-http-errors` strips bodies + CORS headers from 4xx/5xx but lets
 * 422 through, which is why the gate responses are pinned to 422 not 403.
 * Do not change the status codes without verifying the ingress config.
 */
class UserGroupsService {
  async applyGroupUpdate(input: ApplyGroupUpdateInput): Promise<ApplyGroupUpdateResult> {
    const { identity, newGroups, actor, privilegePolicy, auditEventType, auditExtraDetails } = input

    // Pre-existing race: another request can mutate between fetch and
    // updateUserGroups below. Kratos has no ETag/CAS on identities — fixing
    // would require a Kratos schema change. Window is microseconds; the
    // only consequence is a stale audit `oldGroups` snapshot.
    let oldGroups: string[] = []
    try {
      const fetched = await kratosService.getUserGroups(identity.email)
      if (Array.isArray(fetched)) oldGroups = fetched
    } catch { /* user may not have groups yet */ }

    const finalGroups = newGroups.length > 0 ? newGroups : ['users']
    const newlyAdded = finalGroups.filter(g => !oldGroups.includes(g))

    if (newlyAdded.length > 0) {
      for (const g of newlyAdded) {
        if (await rbacService.isAdminPowerGroup(g)) {
          const denial = await this.checkPrivilegeEscalation(g, identity.email, actor, privilegePolicy)
          if (denial) return denial
        }
      }
    }

    if (newlyAdded.length > 0) {
      const blocker = await rbacService.findPrivilegedGroupRequiringMFA(newlyAdded, identity.id)
      if (blocker) {
        return {
          ok: false,
          status: 422,
          body: {
            error: 'mfa_required',
            message: `Group '${blocker}' grants admin privileges; the target user must enroll a second factor (TOTP, security key, or backup codes) before being added.`,
            targetEmail: identity.email,
            targetGroups: newlyAdded,
            hint: 'Have the user complete /settings → Authenticator app, then retry.',
          },
        }
      }
    }

    await kratosService.updateUserGroups(identity.email, finalGroups)

    // Fire-and-forget: OPAL cache invalidation. On failure, OPA stays
    // stale until its next poll (~30s). Mutation is already persisted in
    // Kratos so the inconsistency is bounded.
    rbacService.notifyBindingsChanged('groups_changed', actor).catch(() => {})

    auditEventService.emit({
      type: auditEventType,
      actor: { email: actor.email, ip: actor.ip },
      target: { type: 'user', id: identity.id },
      details: { ...(auditExtraDetails ?? {}), oldGroups, newGroups: finalGroups },
      source: 'jinbe-api',
    }).catch(() => {})

    return {
      ok: true,
      response: {
        id: identity.id,
        organizationId: identity.organizationId,
        email: identity.email,
        groups: finalGroups,
        updatedAt: new Date().toISOString(),
      },
    }
  }

  private async checkPrivilegeEscalation(
    groupName: string,
    targetEmail: string,
    actor: { email?: string; ip?: string },
    policy: ActorPrivilegePolicy,
  ): Promise<ApplyGroupUpdateResult | null> {
    if (policy.kind === 'super_admin_required') {
      try {
        await rbacService.assertSuperAdmin(
          `assign group '${groupName}' (grants admin privileges)`,
          { email: actor.email },
        )
        return null
      } catch (e) {
        const err = e as Error & { statusCode?: number }
        return {
          ok: false,
          status: err.statusCode === 401 ? 401 : 422,
          body: {
            error: 'privilege_escalation_blocked',
            message: err.message,
            targetEmail,
            blockingGroup: groupName,
            hint: 'Only an existing super_admin can grant admin or super_admin groups.',
          },
        }
      }
    }

    // J1 backstop: a group that grants GLOBAL power (global super_admin or a
    // global role resolving to "*") must NEVER be assignable on the strength
    // of an org-scoped ("*"-in-org) wildcard alone — that would let an org
    // admin cross the tenant boundary and mint a global super_admin. Regardless
    // of the actor's org wildcard, force the super_admin authority check by
    // delegating to the super_admin path. Scoped (non-global) admin groups keep
    // the org-"*" behaviour below unchanged.
    if (await rbacService.groupGrantsGlobalPower(groupName)) {
      return this.checkPrivilegeEscalation(groupName, targetEmail, actor, { kind: 'super_admin_required' })
    }

    if (!policy.actorPermissions.includes('*')) {
      return {
        ok: false,
        status: 422,
        body: {
          error: 'privilege_escalation_blocked',
          message: `Cannot assign group '${groupName}' (grants admin privileges) — wildcard permission required for this organization`,
          targetEmail,
          blockingGroup: groupName,
          hint: 'The actor must hold the wildcard (*) permission for this organization.',
        },
      }
    }
    return null
  }
}

export const userGroupsService = new UserGroupsService()
