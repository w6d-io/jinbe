import { kratosService } from '../services/kratos.service.js'
import { userGroupsService } from '../services/user-groups.service.js'
import { applyAwaitingGroups, type ApplyAwaitingDeps } from './awaiting.js'

/**
 * The real wiring of awaiting.ts: the person's enrolled factors from Kratos, and the add-only group
 * update replayed as the person who added them — holding rule included, their step-up not asked again
 * (it was when they added them). Kept apart from awaiting.ts so the group service can import that one.
 */
export const awaitingDeps: ApplyAwaitingDeps = {
  hasSecondFactor: (identityId) => kratosService.hasMFA(identityId),
  async addGroups(identityId, groups, by) {
    const identity = await kratosService.getIdentity(identityId)
    const email = typeof identity?.traits?.email === 'string' ? identity.traits.email : null
    if (!identity || !email) return { ok: false, status: 404 }
    const result = await userGroupsService.applyGroupUpdate({
      identity: { id: identity.id, email, organizationId: ((identity as Record<string, unknown>).organization_id as string | null) ?? null },
      newGroups: [],
      addGroups: groups,
      actor: { id: by.id, email: by.email },
      auditEventType: 'user.groups_changed',
      auditExtraDetails: { via: 'second_factor_enrolled' },
      awaitedSecondFactor: true,
    })
    return result.ok ? { ok: true } : { ok: false, status: result.status }
  },
}

/** Applies what waits for this person, once enrolled (the Kratos settings hook, the status check). */
export function applyAwaiting(identityId: string | null | undefined, log?: { warn: (o: object, m: string) => void }) {
  return applyAwaitingGroups(identityId, awaitingDeps, log)
}
