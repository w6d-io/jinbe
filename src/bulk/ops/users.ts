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
type InviteParams = { sendInvite: boolean }

/**
 * Create users, like POST /admin/users without groups (a group is groups.members.add): users:create,
 * and users:recovery when the invite mail is sent, for the user AND the key's scopes.
 */
export const usersInvite: BulkOp<Invite, InviteParams, null> = {
  permission: 'users:create',
  item: z.object({ email: z.string().trim().toLowerCase().email().max(254), name: z.string().trim().min(1).max(120).optional() }).strict(),
  params: z.object({ sendInvite: z.boolean().default(false) }).strict().default({ sendInvite: false }),
  key: (item) => item.email,
  load: async () => null,

  async plan(caller, params, _state, item): Promise<Outcome> {
    if (params.sendInvite && !may(caller, 'users:recovery')) return { status: 'refused', reason: 'missing:users:recovery' }
    if (await kratosService.findByEmail(item.email)) {
      return may(caller, 'users:read') ? { status: 'skip', reason: 'already_exists' } : { status: 'refused', reason: 'address_unavailable' }
    }
    return { status: 'ok', action: 'create' }
  },

  async run(caller: Caller, params, _state, item, ctx) {
    if (params.sendInvite && !may(caller, 'users:recovery')) return { status: 'refused', reason: 'missing:users:recovery' }
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
    return { status: 'done', action: params.sendInvite && !invited ? 'create:invite_failed' : 'create' }
  },
}
