import { kratosService } from './kratos.service.js'
import { rbacService } from './rbac.service.js'
import { auditEventService } from './audit-event.service.js'
import { diffUserGroups } from './audit-diff.js'
import { withRedisLock } from './redis-lock.js'
import { addToGroup, removeFromGroup } from './organisation-store.js'
import {
  AuthorizationModelUnavailableError,
  groupFacts,
  type GroupFacts,
} from './authorization-model.service.js'

/** Actor threaded from a request — audit fields (A4) + the R2 step-up state. */
export type GroupUpdateActor = {
  /** The immutable identity. The gate that decides who may hand out rights reads THIS, not the address. */
  id?: string | null
  email?: string | null
  ip?: string | null
  name?: string | null
  ua?: string | null
  sessionId?: string | null
  requestId?: string | null
  aal?: string
  authenticatedAt?: Date | string
}

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
  // `aal` / `authenticatedAt` carry the actor's second-factor state for the R2
  // step-up gate; sourced from the Kratos-validated session (request.userContext).
  actor: GroupUpdateActor
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

// The single service-agnostic org-admin flag group. Its authority is POSITIONAL
// (granted in policy: rbac.is_org_admin + delegation.manageable_orgs), so it
// carries an EMPTY binding and therefore does NOT register as admin-power. On the
// global endpoint the priv gate keys on isAdminPowerGroup, which would SKIP this
// group — letting a non-super platform admin mint an org admin. We force it
// through the super_admin gate below. On the org-scoped endpoint it is already
// gated (it is not the base group, so it goes to can_grant, which denies it —
// 0 perms → not bundle-containable). Name must match the rego constant
// rbac.org_admin_group.
const ORG_ADMIN_FLAG_GROUP = 'org_admins'

// R2 — a privilege-gated group assignment requires the ACTOR to have proven a
// second factor (AAL2) within this window. Time-boxed step-up: a long-lived
// session cannot keep minting privileged access without re-verifying TOTP. The
// window matches the operator-chosen 15 minutes; a refresh=true AAL2 login
// re-stamps `authenticated_at`, resetting it.
const STEP_UP_MAX_AGE_MS = 15 * 60 * 1000

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
    // ONE read of the model, for every question the gates below ask of it. What this replaces asked
    // Redis — the retired model — and got `false` for exactly the groups that had become the
    // powerful ones, so the escalation gate, the target's second factor and the actor's step-up all
    // quietly decided they were not needed.
    let facts: Map<string, GroupFacts>
    try {
      facts = await groupFacts([...newlyAdded, ...removed])
    } catch (error) {
      if (!(error instanceof AuthorizationModelUnavailableError)) throw error
      // "Confers nothing" and "I could not tell what it confers" are opposite facts, and the second
      // one must never quietly hand out a group unguarded.
      return {
        ok: false,
        status: 503,
        body: {
          error: 'authorization_model_unavailable',
          message:
            'The authorization model could not be read, so this change could not be checked; no change was made. Please retry.',
          targetEmail: identity.email,
        },
      }
    }
    const factsFor = (group: string): GroupFacts =>
      facts.get(group) ?? { declared: false, everyOrganisation: false, empty: true }

    // A group the model does not declare confers nothing, so recording it would write a membership
    // the engine never reads — an assignment that looks applied and grants nothing. Only ADDITIONS
    // are checked: a group predating the model must stay removable. The base group is jinbe's own
    // bookkeeping rather than an operator's choice, and it is exempt for that reason.
    const undeclared = newlyAdded.filter((g) => g !== BASE_GROUP && !factsFor(g).declared)
    if (undeclared.length > 0) {
      this.emitDenied('group_not_in_model', identity, actor, undeclared[0], 400)
      return {
        ok: false,
        status: 400,
        body: {
          error: 'Bad Request',
          message: `Not in the authorization model: ${undeclared.join(', ')}. Assignable groups come from GET /admin/assignable-groups.`,
          targetEmail: identity.email,
        },
      }
    }

    const gated: Array<{ group: string; op: 'add' | 'remove' }> = []
    for (const { group: g, op } of toCheck) {
      const mustCheck = privilegePolicy.kind === 'wildcard_in_org'
        ? !(g === BASE_GROUP && factsFor(g).empty)
        : factsFor(g).everyOrganisation || g === ORG_ADMIN_FLAG_GROUP
      if (mustCheck) gated.push({ group: g, op })
    }

    for (const { group: g, op } of gated) {
      const denial = await this.checkPrivilegeEscalation(g, identity.email, actor, privilegePolicy, op, factsFor(g).everyOrganisation)
      if (denial) {
        // Emit the currently-silent denied write (highest-signal audit event).
        // checkPrivilegeEscalation only ever returns the ok:false variant.
        this.emitDenied('privilege_escalation_blocked', identity, actor, g, denial.ok ? 422 : denial.status)
        return denial
      }
    }

    // The target's own second factor, required before receiving a platform-wide grant. Keyed on the
    // same scope predicate as the gate above so the two cannot drift apart.
    const platformGrants = newlyAdded.filter((g) => factsFor(g).everyOrganisation)
    if (platformGrants.length > 0) {
      const blocker = (await this.hasSecondFactor(identity.id)) ? null : platformGrants[0]
      if (blocker) {
        this.emitDenied('mfa_required', identity, actor, blocker, 422)
        return {
          ok: false,
          status: 422,
          body: {
            error: 'mfa_required',
            message: `Group '${blocker}' grants admin privileges; the target user must enroll a second factor (TOTP, security key, or backup codes) before being added.`,
            targetEmail: identity.email,
            targetGroups: platformGrants,
            hint: 'Have the user complete /settings → Authenticator app, then retry.',
          },
        }
      }
    }

    // STEP-UP (R2, final gate): the actor is authorized and the target satisfies
    // the MFA requirement — now require the ACTOR's own second factor to be recent
    // (AAL2 within STEP_UP_MAX_AGE). Placed LAST so an unauthenticated/unauthorized
    // actor still gets the precise authority denial (401/403/privilege_escalation),
    // and a stale factor blocks the WRITE. Fires only for a privilege-gated change;
    // fail-closed on missing AAL/timestamp.
    if (gated.length > 0) {
      const stale = this.stepUpDenial(actor, identity.email)
      if (stale) {
        this.emitDenied('reauth_required', identity, actor, gated[0]?.group, 422)
        return stale
      }
    }

    // Two stores, and the ORDER between them is a safety property rather than a detail.
    //
    // `group_members` in this database is what the engine decides against — the artefact carries it.
    // Kratos metadata is a display copy nothing enforces; both are written from the SAME value so a
    // screen that edits still saves what it shows, until every reader moves off it.
    //
    // REVOCATIONS GO TO THE ENFORCED STORE FIRST. Taking a group away in the display and then
    // failing to take it away where it counts would leave a right that is still enforced and no
    // longer visible — the one failure nobody would notice.
    //
    // GRANTS GO TO THE ENFORCED STORE LAST, for the mirror reason: a right that is enforced before
    // anything shows it is a silent privilege. Shown-but-not-yet-enforced is merely broken, and
    // visibly so.
    const revoked = oldGroups.filter((g) => !finalGroups.includes(g))
    const granted = finalGroups.filter((g) => !oldGroups.includes(g))

    for (const group of revoked) await removeFromGroup(identity.id, group)

    await kratosService.updateUserGroups(identity.email, finalGroups)

    for (const group of granted) await addToGroup(identity.id, group, actor.email ?? undefined)

    // Fire-and-forget: OPAL cache invalidation. On failure, OPA stays
    // stale until its next poll (~30s). Mutation is already persisted in
    // Kratos so the inconsistency is bounded.
    rbacService.notifyBindingsChanged('groups_changed', actor).catch(() => {})

    auditEventService.emit({
      type: auditEventType,
      actor: { id: actor.id, email: actor.email, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId },
      requestId: actor.requestId,
      target: { type: 'user', id: identity.id },
      // Keep oldGroups/newGroups in details for back-compat; the structural
      // before→after (A3) lives in `changes`, and targetEmail powers the
      // per-user "done-to" trail (P1-4).
      details: { ...(auditExtraDetails ?? {}), oldGroups, newGroups: finalGroups, targetEmail: identity.email },
      changes: diffUserGroups(identity.id, oldGroups, finalGroups),
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

  /**
   * Emit a denied group-mutation (A2). These are the highest-signal audit
   * events (an attempted privilege change that was refused) and were previously
   * silent. Fail-open on the emit — never block the denial itself.
   */
  /**
   * Whether the target has a second factor enrolled. A lookup failure answers NO — refusing a
   * privileged grant we could not verify is the safe way to be wrong.
   */
  private async hasSecondFactor(identityId: string): Promise<boolean> {
    try {
      return await kratosService.hasMFA(identityId)
    } catch {
      return false
    }
  }

  private emitDenied(
    reason: string,
    identity: ResolvedIdentity,
    actor: GroupUpdateActor,
    blockingGroup: string | undefined,
    status: number,
  ): void {
    auditEventService.emit({
      category: 'access',
      kind: 'change',
      verb: 'assign',
      target: `user:${identity.email}`,
      result: 'denied',
      severity: 'warn',
      reason,
      actor: { id: actor.id, email: actor.email ?? null, ip: actor.ip, name: actor.name, ua: actor.ua, sessionId: actor.sessionId },
      requestId: actor.requestId,
      targetId: identity.id,
      targetType: 'user',
      statusCode: status,
      details: { blockingGroup, targetEmail: identity.email },
      source: 'jinbe-api',
    }).catch(() => {})
  }

  // R2 step-up gate: the actor must hold AAL2 proven within STEP_UP_MAX_AGE.
  // Returns a 422 `reauth_required` denial (status pinned to 422 so cluster
  // ingress does not strip the body/headers) when the second factor is absent or
  // stale; null when satisfied. Fail-closed: a missing aal/authenticatedAt denies.
  private stepUpDenial(
    actor: { aal?: string; authenticatedAt?: Date | string },
    targetEmail: string,
  ): ApplyGroupUpdateResult | null {
    const reauth = (message: string): ApplyGroupUpdateResult => ({
      ok: false,
      status: 422,
      body: {
        error: 'reauth_required',
        message,
        targetEmail,
        stepUp: { requiredAal: 'aal2', maxAgeMinutes: STEP_UP_MAX_AGE_MS / 60000 },
        hint: 'Re-verify your second factor at /login?aal=aal2&refresh=true, then retry.',
      },
    })
    if (actor.aal !== 'aal2') {
      return reauth(
        'This change assigns privileged access and requires two-factor authentication (TOTP). Complete 2FA and retry.',
      )
    }
    const authedAt = actor.authenticatedAt ? new Date(actor.authenticatedAt).getTime() : 0
    if (!authedAt || Number.isNaN(authedAt) || Date.now() - authedAt > STEP_UP_MAX_AGE_MS) {
      return reauth(
        `Your two-factor verification is older than ${STEP_UP_MAX_AGE_MS / 60000} minutes; re-verify (TOTP) to assign privileged access.`,
      )
    }
    return null
  }

  private async checkPrivilegeEscalation(
    groupName: string,
    targetEmail: string,
    actor: { id?: string | null; email?: string | null; ip?: string | null },
    policy: ActorPrivilegePolicy,
    op: 'add' | 'remove' = 'add',
    platformWide = false,
  ): Promise<ApplyGroupUpdateResult | null> {
    if (policy.kind === 'super_admin_required') {
      try {
        await rbacService.assertSuperAdmin(
          `assign group '${groupName}' (grants admin privileges)`,
          { id: actor.id, email: actor.email },
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

    // Org-scoped grant. NOT AVAILABLE in this model, and refused with a reason that says so rather
    // than through a query that answers nothing: `strada.authz` has no delegation concept — no
    // permission expresses "may hand out this group here", so there is nothing to check against.
    // Assignment therefore goes through the global gate above until that permission is designed.
    //
    // Below is what it asked before, kept for what it documents about the intent.
    //
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

    // J1: an org-scoped actor must never mint a platform-wide grant. Both branches refuse, so this
    // only decides WHICH refusal the caller reads — but the two say different things, and a screen
    // that reports "not managed here" for a global group is telling the operator where to go.
    if (platformWide) return blocked

    return {
      ok: false,
      status: 422,
      body: {
        error: 'delegation_not_defined',
        message:
          'This model defines no delegated authority to assign a group within one organisation. ' +
          'A group granting in every organisation can make this change.',
        targetEmail,
        blockingGroup: groupName,
        hint: 'Use the global assignment endpoint, or define a permission that expresses this delegation.',
      },
    }
  }
}

export const userGroupsService = new UserGroupsService()
