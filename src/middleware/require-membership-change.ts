import type { FastifyReply, FastifyRequest } from 'fastify'
import { enforcing } from '../policy/declared-routes.js'
import { kratosService } from '../services/kratos.service.js'
import { groupsForSubjects } from '../services/organisation-store.js'
import { allows } from '../services/user-permissions.js'
import { callerRights, demandPermissions } from './require-permission.js'
import { requireRecentMfa } from './require-admin.js'
import { delegationRefusal } from './delegation-gate.js'
import { keyStepUpVerdict } from './delegated-step-up.js'
import { denyAudit } from '../audit/deny.js'

/**
 * PUT /api/admin/users/:email/groups replaces a person's platform groups. What it needs depends on
 * the diff: removing only is `groups.members:revoke` (incident response takes access away); adding
 * anybody to anything is `groups.members:write` and a second factor proven within 15 minutes.
 *
 * Decided on the caller first — somebody who may do neither learns nothing about the target. The
 * current groups are read from the store that decides (as the write path does); a read that fails
 * refuses rather than guessing the diff. The service re-checks the diff under its lock, with the
 * escalation guard (rbac-escalation-guard.ts): this gate only chooses which permission to ask for.
 */
export const requireMembershipChange = enforcing(async function (
  request: FastifyRequest<{ Params: { email: string }; Body: { groups?: unknown } }>,
  reply: FastifyReply,
) {
  const rights = await callerRights(request, reply)
  if (!rights) return reply
  if (!allows(rights.permissions, 'groups.members:write') && !allows(rights.permissions, 'groups.members:revoke')) {
    await demandPermissions(request, reply, ['groups.members:revoke'])
    return reply
  }

  const wanted = Array.isArray(request.body?.groups) ? request.body.groups.map(String) : []
  let current: string[] = []
  const identity = await kratosService.findByEmail(request.params.email)
  if (identity) current = (await groupsForSubjects([identity.id])).get(identity.id) ?? []

  const adds = wanted.some((g) => !current.includes(g))
  const removes = current.some((g) => !wanted.includes(g))
  // Through a key (owner decision 2026-09-30): adding is normal work, removing is a deletion — by hand.
  // The global gate leaves this route to its guard (guard-checked); what the call really is is decided here.
  if (request.userContext?.authVia === 'delegated') {
    const refusal = delegationRefusal(request, removes ? 'groups.members:revoke' : 'groups.members:write')
    if (refusal) {
      denyAudit(request, refusal)
      return reply.status(403).send({ error: 'Forbidden', code: 'delegation_refused', message: 'This credential acts for a user through a client and may not use this route.', reason: refusal })
    }
  }
  if (!(await demandPermissions(request, reply, [adds ? 'groups.members:write' : 'groups.members:revoke']))) return reply
  // A key's creation-time second factor stands in for an addition (delegated-step-up.ts): asked with
  // the permission this call really is, not the route's declared one.
  if (adds && !keyStepUpVerdict(request, 'groups.members:write').ok) {
    await requireRecentMfa(request, reply)
    if (reply.sent) return reply
  }
}, 'groups.members:revoke')
