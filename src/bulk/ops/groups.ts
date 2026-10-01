import { z } from 'zod'
import { groupFacts, type GroupFacts } from '../../services/group-catalogue.js'
import { groupsForSubjects } from '../../services/organisation-store.js'
import { userGroupsService } from '../../services/user-groups.service.js'
import { assertMayAssignGroup } from '../../services/rbac-escalation-guard.js'
import { isSelf, may, notFound, resolveUser, type BulkOp, type Outcome } from '../types.js'

type Add = { user: string; groups: string[] }

/**
 * Add people to platform groups, like PUT /admin/users/:email/groups with the adds only: the route
 * carries groups.members:write and its step-up, and each item goes through the same grant gate
 * (userGroupsService.applyGroupUpdate: the model, the escalation guard, the target's second factor,
 * the actor's step-up) in add-only mode, so nothing is ever taken away. Never the caller themselves,
 * never a staff group or one granting what the caller does not hold (the plan says so up front).
 *
 * A key hands out a platform-wide group only on its creation-time second factor (a key created with
 * protected actions, less than 30 days ago); otherwise the plan refuses it (step_up_unavailable).
 */
export const groupsMembersAdd: BulkOp<Add, Record<string, never>, Map<string, GroupFacts>> = {
  permission: 'groups.members:write',
  item: z.object({
    user: z.string().trim().min(1).max(320),
    groups: z.array(z.string().trim().min(1).max(64)).min(1).max(20),
  }).strict(),
  params: z.object({}).strict().default({}) as never,
  key: (item) => item.user.toLowerCase(),
  load: async () => new Map(),

  async plan(caller, _params, facts, item): Promise<Outcome> {
    if (!may(caller, 'groups.members:write')) return { status: 'refused', reason: 'missing:groups.members:write' }
    const identity = await resolveUser(item.user)
    if (!identity) return notFound(caller)
    if (isSelf(caller, identity)) return { status: 'refused', reason: 'self_change' }

    const missing = item.groups.filter((g) => !facts.has(g))
    if (missing.length) for (const [g, f] of await groupFacts(missing)) facts.set(g, f)
    const undeclared = item.groups.find((g) => !facts.get(g)?.declared)
    if (undeclared) return { status: 'refused', reason: `group_not_in_model:${undeclared}` }

    const held = (await groupsForSubjects([identity.id])).get(identity.id) ?? []
    const adds = item.groups.filter((g) => !held.includes(g))
    if (adds.length === 0) return { status: 'skip', reason: 'already_member' }
    const privileged = adds.find((g) => facts.get(g)?.platform)
    // A key stands on its creation-time second factor for group grants (owner decision 2026-09-30);
    // without that proof (key created without protected actions, or too old) a platform-wide grant is refused.
    if (privileged && caller.delegated && !caller.groupActor.stepUpViaKey) return { status: 'refused', reason: `step_up_unavailable:${privileged}` }
    // The holding rule as the run will ask it: nothing the caller does not hold.
    for (const g of adds) {
      try {
        await assertMayAssignGroup(g, { id: caller.id, email: caller.audit.email ?? null, ip: caller.audit.ip ?? null })
      } catch (e) {
        const err = e as { statusCode?: number; code?: string }
        if (err.statusCode === 401 || err.statusCode === 503) return { status: 'refused', reason: 'unavailable' }
        return { status: 'refused', reason: `${err.code ?? 'privilege_escalation_blocked'}:${g}` }
      }
    }
    return { status: 'ok', action: `add:${adds.join(',')}` }
  },

  async run(caller, _params, _facts, item, ctx) {
    if (!may(caller, 'groups.members:write')) return { status: 'refused', reason: 'missing:groups.members:write' }
    const identity = await resolveUser(item.user)
    if (!identity) return { status: 'refused', reason: 'not_found' }
    if (isSelf(caller, identity)) return { status: 'refused', reason: 'self_change' }
    const email = typeof identity.traits?.email === 'string' ? identity.traits.email : null
    if (!email) return { status: 'refused', reason: 'no_address' }

    const result = await userGroupsService.applyGroupUpdate({
      identity: { id: identity.id, email, organizationId: ((identity as Record<string, unknown>).organization_id as string | null) ?? null },
      newGroups: [],
      addGroups: item.groups,
      actor: caller.groupActor,
      auditEventType: 'user.groups_changed',
      auditExtraDetails: { bulk: ctx.jobId },
    })
    if (!result.ok) return { status: result.status >= 500 ? 'failed' : 'refused', reason: String(result.body.error ?? `status_${result.status}`) }
    return { status: 'done', action: 'add' }
  },
}
