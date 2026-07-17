import { kratosService } from './kratos.service.js'
import { rbacService } from './rbac.service.js'
import { opaService } from './opa.service.js'
import { auditEventService } from './audit-event.service.js'
import { withRedisLock } from './redis-lock.js'

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
 * - `wildcard_in_org` — org-scoped endpoint. EVERY newly-added group (except
 *   the base `users` group, which confers nothing) is put to OPA
 *   `data.rbac.delegation.can_grant`, which is the SOLE authority. The rego
 *   re-resolves the actor's permissions from `email` (via the same
 *   `data.rbac.user_permissions` resolver the request authorizer uses, so the
 *   two cannot drift) and enforces the tenant boundary for everyone —
 *   delegated org admins AND service/super admins alike:
 *     • the group must be non-global and confined to the target org's single
 *       service (multi-service and global groups are NEVER grantable here — they
 *       go through the global admin endpoint), and
 *     • the actor must either administer the org and contain the group's
 *       permissions (delegated org admin), or hold `*` for the service
 *       (service/super admin).
 *   No permission set is carried in this policy; OPA always re-resolves it.
 */
export type ActorPrivilegePolicy =
  | { kind: 'super_admin_required' }
  | { kind: 'wildcard_in_org'; orgId: string }

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

// The base group every identity implicitly holds. It confers no permissions, so
// assigning it is never a privilege change and is exempt from the delegation
// gate (the rego would deny it anyway — it enforces "no vacuous grant").
const BASE_GROUP = 'users'

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

    // Serialize all group updates for THIS user under a per-user lock. The
    // removal privilege gate is computed from the oldGroups pre-image (read
    // below) but the write is a full REPLACE. Without serialization, a
    // concurrent grant landing between our read and write — e.g. a super_admin
    // adding `super_admins` — is invisible to the removal gate, so our replace
    // silently strips it: an UNGATED strip + a lost update. Holding the lock
    // across read → gate → write makes the pre-image authoritative for the
    // duration. Every jinbe group writer (this method + removeGroupFromAllUsers)
    // takes the SAME lock. See audit finding #9.
    return withRedisLock(`user-groups:${identity.email}`, async () => {

    // Pre-image: the target's CURRENT groups. This is SECURITY-LOAD-BEARING —
    // it drives the removal gate (which groups the update drops) and the audit
    // snapshot. getUserGroups returns ['users'] for a user with no special
    // groups and only THROWS on 404 / infra error; it never signals "no groups"
    // by throwing. So a throw means we cannot compute `removed`, and continuing
    // would run the replace write below with `removed = []` — an UNGATED STRIP
    // (the exact bug the symmetric gate closes, resurrected on a read blip).
    // FAIL-CLOSED: refuse the whole update rather than risk stripping groups we
    // failed to read.
    //
    // Residual: Kratos itself has no ETag/CAS, so a group write originating
    // OUTSIDE jinbe could still race; within jinbe the per-user lock above
    // serializes every writer, so the pre-image is authoritative here.
    let oldGroups: string[]
    try {
      const fetched = await kratosService.getUserGroups(identity.email)
      oldGroups = Array.isArray(fetched) ? fetched : []
    } catch {
      return {
        ok: false,
        status: 422,
        body: {
          error: 'groups_precondition_failed',
          message:
            "Could not read the user's current groups to verify this change is within your authority; no change was made. Please retry.",
          targetEmail: identity.email,
        },
      }
    }

    const finalGroups = newGroups.length > 0 ? newGroups : [BASE_GROUP]
    const newlyAdded = finalGroups.filter(g => !oldGroups.includes(g))
    // Groups this (replace-semantics) update REMOVES. Containment must be
    // SYMMETRIC — an org admin may only remove a group they could also grant.
    // Without gating removals, a delegated admin could STRIP a more-privileged
    // co-tenant: a replace PUT of {groups:["users"]} on a super_admin silently
    // drops super_admins, because only *added* groups were ever checked. A
    // removal the actor could not grant is refused (422), which preserves it.
    const removed = oldGroups.filter(g => !finalGroups.includes(g))

    // Per-group privilege gate. Org-scoped (`wildcard_in_org`) is SYMMETRIC —
    // both adds and removes go through can_grant. Global (`super_admin_required`)
    // gates only *added* admin-power groups: that endpoint is already
    // super_admin-gated at the route, and a super_admin may freely remove.
    const toCheck: Array<{ group: string; op: 'add' | 'remove' }> = [
      ...newlyAdded.map((group) => ({ group, op: 'add' as const })),
      ...(privilegePolicy.kind === 'wildcard_in_org'
        ? removed.map((group) => ({ group, op: 'remove' as const }))
        : []),
    ]

    for (const { group: g, op } of toCheck) {
      // Which changes must clear the privilege gate:
      //  - org-scoped (`wildcard_in_org`): EVERY group except a genuinely empty
      //    base group. The rego enforces single-service containment for ALL
      //    groups, not just `*`-bearing ones, so gating on isAdminPowerGroup here
      //    would let a multi-service read group (e.g. a cross-service `viewers`)
      //    slip the tenant boundary. The base-group exemption is keyed on the
      //    group actually conferring nothing (isEmptyGroup), not its name, so a
      //    redefined base group is still put to can_grant — on add AND remove.
      //  - global (`super_admin_required`): only admin-power groups need the
      //    super_admin authority check; the endpoint is super_admin-gated.
      const mustCheck = privilegePolicy.kind === 'wildcard_in_org'
        ? !(g === BASE_GROUP && await rbacService.isEmptyGroup(g))
        : await rbacService.isAdminPowerGroup(g)
      if (mustCheck) {
        const denial = await this.checkPrivilegeEscalation(g, identity.email, actor, privilegePolicy, op)
        if (denial) return denial
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
    }) // end withRedisLock(user-groups:<email>)
  }

  private async checkPrivilegeEscalation(
    groupName: string,
    targetEmail: string,
    actor: { email?: string; ip?: string },
    policy: ActorPrivilegePolicy,
    op: 'add' | 'remove' = 'add',
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

    // Org-scoped grant. OPA `can_grant` is the SOLE authority: it enforces the
    // single-service tenant boundary (non-global, confined to the org's service)
    // and the authority tier (delegated org admin with containment, OR a
    // service-`*` admin), re-resolving the actor's permissions from `email` — so
    // we pass ONLY the email, never a caller-supplied permission set. Fail-closed:
    // canGrant returns false on any OPA error, and we require an actor email.
    const blocked: ApplyGroupUpdateResult = {
      ok: false,
      status: 422,
      body: {
        error: 'privilege_escalation_blocked',
        message:
          op === 'remove'
            ? `Cannot remove group '${groupName}' — removal is bounded by the same authority as granting, so you may only remove a group scoped to your organization's service whose permissions you already hold (an org admin cannot strip a more-privileged user)`
            : `Cannot assign group '${groupName}' — on this endpoint you may only grant a group scoped to your organization's service whose permissions you already hold`,
        targetEmail,
        blockingGroup: groupName,
        operation: op,
        hint: 'Global or multi-service groups are not managed here — use the global admin endpoint (super_admin only).',
      },
    }

    // Defense-in-depth: independently refuse a GLOBAL-power group so it is denied
    // here even if OPA misbehaves (J1 — an org-scoped actor must never mint a
    // global super_admin). OPA `can_grant` ALSO denies every global-bound group
    // (`not group_has_global`) and is the authoritative, broader guard — this
    // local check only catches wildcard globals, so it is NOT the sole global
    // guard, just a safety net. Global groups go through the global admin
    // endpoint, never here — for everyone, super_admins included.
    if (await rbacService.groupGrantsGlobalPower(groupName)) return blocked

    if (!actor.email) return blocked
    const allowed = await opaService.canGrant({
      actor: { email: actor.email },
      target_group: groupName,
      target_org: policy.orgId,
    })
    if (!allowed) return blocked
    return null
  }
}

export const userGroupsService = new UserGroupsService()
