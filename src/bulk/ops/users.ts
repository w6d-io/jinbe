import { z } from 'zod'
import { auditEventService } from '../../services/audit-event.service.js'
import { addressDigest } from '../../services/email-change.service.js'
import { KratosApiError, kratosService } from '../../services/kratos.service.js'
import { rbacService } from '../../services/rbac.service.js'
import {
  AlreadyVerifiedError,
  countVerificationLink,
  sendVerificationLink,
  unverifiedAddress,
  VERIFY_CALLER_LIMIT,
  VerificationRateLimitedError,
  VerificationUnavailableError,
} from '../../services/verification.service.js'
import type { KratosIdentityCreate } from '../../schemas/admin.schema.js'
import { groupFacts } from '../../services/group-catalogue.js'
import { userGroupsService } from '../../services/user-groups.service.js'
import { assertMayAssignGroup } from '../../services/rbac-escalation-guard.js'
import { directGrantsService, grantRequestSchema, GrantNeedsSecondFactorError, GrantsRefusedError } from '../../services/direct-grants.service.js'
import type { GrantRequest } from '../../services/direct-grants.repository.js'
import { secondFactorIsFresh } from '../../services/step-up.js'
import { isSelf, may, notFound, resolveUser, type BulkOp, type Caller, type Outcome } from '../types.js'

const userRef = z.string().trim().min(1).max(320)
const noParams = z.object({}).strict().default({})

// ── users.verification ─────────────────────────────────────────────────────────────────────────────

/** Resend the verification link, like POST /admin/users/:id/verification, item by item. */
export const usersVerification: BulkOp<{ user: string }, Record<string, never>, null> = {
  permission: 'users:verify',
  item: z.object({ user: userRef }).strict(),
  params: noParams as never,
  key: (item) => item.user.toLowerCase(),
  load: async () => null,

  async plan(caller, _params, _state, item) {
    const identity = await resolveUser(item.user)
    if (!identity) return notFound(caller)
    if (isSelf(caller, identity)) return { status: 'refused', reason: 'self_change' }
    try {
      unverifiedAddress(identity)
    } catch (err) {
      if (err instanceof AlreadyVerifiedError) return { status: 'skip', reason: 'already_verified' }
      throw err
    }
    return { status: 'ok', action: 'send' }
  },

  async run(caller, _params, _state, item, ctx) {
    const identity = await resolveUser(item.user)
    if (!identity) return { status: 'refused', reason: 'not_found' }
    let address: string
    try {
      address = unverifiedAddress(identity)
    } catch (err) {
      if (err instanceof AlreadyVerifiedError) return { status: 'skipped', reason: 'already_verified' }
      throw err
    }
    try {
      await countVerificationLink(identity.id, caller.id)
      await sendVerificationLink(address)
    } catch (err) {
      if (err instanceof VerificationRateLimitedError) return { status: 'failed', reason: `rate_limited:${err.scope}` }
      if (err instanceof VerificationUnavailableError) return { status: 'failed', reason: 'verification_link_unavailable' }
      throw err
    }
    auditEventService.emit({
      category: 'auth', kind: 'change', verb: 'verification_sent', target: `user:${identity.id}`, targetType: 'user', targetId: identity.id,
      result: 'applied', actor: caller.audit, requestId: caller.audit.requestId, source: 'jinbe-api', v1Event: 'user.verification_sent',
      details: { address: addressDigest(address), bulk: ctx.jobId },
    }).catch(() => {})
    return { status: 'done', action: 'send' }
  },

  warnings(_caller, _params, outcomes) {
    const sends = outcomes.filter((o) => o.status === 'ok').length
    return sends > VERIFY_CALLER_LIMIT ? [`caller_limit: at most ${VERIFY_CALLER_LIMIT} verification links per hour; the rest will fail rate_limited`] : []
  },
}

// ── users.invite ───────────────────────────────────────────────────────────────────────────────────

type Invite = { email: string; name?: string }
type InviteParams = { sendInvite: boolean; groups?: string[]; grants?: GrantRequest[] }

/**
 * Create users, like POST /admin/users: users:create, and users:recovery when the invite mail is sent,
 * for the user AND the key's scopes. Optionally, every invited person also gets:
 *   - `groups`: platform groups, as groups.members.add gives them (groups.members:write, the holding
 *     rule per group, the caller's step-up), add-only;
 *   - `grants`: platform direct grants, as PUT /admin/users/:id/grants gives them (users.grants:write,
 *     never through a key, a recent second factor, the policy's verdict per grant).
 * The plan checks both up front for every row, so a run rarely creates somebody it cannot finish.
 */
export const usersInvite: BulkOp<Invite, InviteParams, null> = {
  permission: 'users:create',
  item: z.object({ email: z.string().trim().toLowerCase().email().max(254), name: z.string().trim().min(1).max(120).optional() }).strict(),
  params: z.object({
    sendInvite: z.boolean().default(false),
    groups: z.array(z.string().trim().min(1).max(64)).max(20).optional(),
    grants: z.array(grantRequestSchema.refine((g) => g.scope === 'platform', 'bulk invite gives platform grants only')).max(20).optional(),
  }).strict().default({ sendInvite: false }),
  key: (item) => item.email,
  load: async () => null,

  async plan(caller, params, _state, item): Promise<Outcome> {
    if (params.sendInvite && !may(caller, 'users:recovery')) return { status: 'refused', reason: 'missing:users:recovery' }
    const extra = await extrasRefusal(caller, params, item.email)
    if (extra) return { status: 'refused', reason: extra }
    if (await kratosService.findByEmail(item.email)) {
      return may(caller, 'users:read') ? { status: 'skip', reason: 'already_exists' } : { status: 'refused', reason: 'address_unavailable' }
    }
    return { status: 'ok', action: 'create' }
  },

  async run(caller: Caller, params, _state, item, ctx) {
    if (params.sendInvite && !may(caller, 'users:recovery')) return { status: 'refused', reason: 'missing:users:recovery' }
    const extra = await extrasRefusal(caller, params, item.email)
    if (extra) return { status: 'refused', reason: extra }
    let id: string
    try {
      const created = await kratosService.createIdentity({
        schema_id: 'default',
        state: 'active',
        traits: { email: item.email, ...(item.name ? { name: item.name } : {}) },
      } as KratosIdentityCreate)
      id = created.id
    } catch (err) {
      if (err instanceof KratosApiError && err.statusCode === 409) return { status: 'skipped', reason: 'already_exists' }
      throw err
    }
    rbacService.invalidateDirectoryStats().catch(() => {})
    let invited = false
    if (params.sendInvite) {
      invited = await kratosService.sendRecoveryEmail(id).then(() => true, () => false)
    }
    auditEventService.emit({
      type: 'user.created',
      actor: caller.audit,
      target: { type: 'user', id },
      details: { sendInvite: params.sendInvite, invited, bulk: ctx.jobId },
      source: 'jinbe-api',
    }).catch(() => {})
    // What does not land is said, never hidden: the person exists either way.
    const unfinished: string[] = []
    if (params.groups?.length) {
      const result = await userGroupsService.applyGroupUpdate({
        identity: { id, email: item.email, organizationId: null },
        newGroups: [], addGroups: params.groups, actor: caller.groupActor,
        auditEventType: 'user.groups_changed', auditExtraDetails: { bulk: ctx.jobId },
      })
      if (!result.ok) unfinished.push(`groups_refused:${String(result.body.error ?? result.status)}`)
    }
    if (params.grants?.length) {
      try {
        await directGrantsService.replace({ subjectId: id, granteeEmail: item.email, wanted: params.grants, actor: { ...caller.audit, email: caller.audit.email ?? '' } })
      } catch (err) {
        unfinished.push(`grants_refused:${(err as { code?: string }).code ?? (err as Error).name}`)
      }
    }
    const action = params.sendInvite && !invited ? 'create:invite_failed' : 'create'
    return { status: 'done', action: unfinished.length ? `${action}:${unfinished.join(':')}` : action }
  },
}

/**
 * Why the groups or grants of an invite would be refused for `email` (null: they would not): the same
 * checks the run makes, asked before anybody is created.
 */
async function extrasRefusal(caller: Caller, params: InviteParams, email: string): Promise<string | null> {
  if (params.groups?.length) {
    if (!may(caller, 'groups.members:write')) return 'missing:groups.members:write'
    const facts = await groupFacts(params.groups)
    const undeclared = params.groups.find((g) => !facts.get(g)?.declared)
    if (undeclared) return `group_not_in_model:${undeclared}`
    for (const g of params.groups) {
      try {
        await assertMayAssignGroup(g, { id: caller.id, email: caller.audit.email ?? null, ip: caller.audit.ip ?? null })
      } catch (e) {
        const err = e as { statusCode?: number; code?: string }
        if (err.statusCode === 401 || err.statusCode === 503) return 'unavailable'
        return `${err.code ?? 'privilege_escalation_blocked'}:${g}`
      }
    }
  }
  if (params.grants?.length) {
    if (!may(caller, 'users.grants:write')) return 'missing:users.grants:write'
    if (!secondFactorIsFresh(caller.groupActor)) return 'reauth_required'
    try {
      await directGrantsService.check({ subjectId: '', granteeEmail: email, wanted: params.grants, actor: { ...caller.audit, email: caller.audit.email ?? '' } })
    } catch (e) {
      if (e instanceof GrantNeedsSecondFactorError) return 'mfa_required'
      if (e instanceof GrantsRefusedError) return `grant_refused:${e.refused.map((r) => `${r.grant.app}:${r.grant.name}`).join(',')}`
      return 'unavailable'
    }
  }
  return null
}
