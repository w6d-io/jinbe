import { kratosService } from './kratos.service.js'
import { getRedisClient } from './redis-client.service.js'
import { componentLogger } from '../telemetry/logger.js'

/**
 * A group that no longer exists leaves nobody holding it. Memberships live on the identities
 * (Kratos metadata_admin.groups), the definitions in the RBAC store: every path that deletes a
 * definition — the API, a site publish dropping its group, a full restore, a staff group retired
 * from code — also takes the name off its members, so a person never shows a group that gives
 * nothing. Best effort and logged: the definition is gone either way, and a stale name grants nothing.
 *
 * Never a sweep of "unknown" names: only the groups a path just deleted, or the explicit
 * RETIRED_GROUPS, so a half-read group list can never wipe real memberships.
 */

/** Staff groups removed from code before the cascade existed; cleaned once per environment. */
export const RETIRED_GROUPS = ['staff-viewers', 'staff-auditors'] as const
const RETIRED_DONE_KEY = 'rbac:retired_groups_pruned'

export async function forgetGroupMembers(names: Iterable<string>): Promise<number> {
  let updated = 0
  for (const name of new Set(names)) {
    try {
      const n = await kratosService.removeGroupFromAllUsers(name)
      if (n > 0) componentLogger('rbac').info({ group: name, usersUpdated: n }, 'deleted group removed from its members')
      updated += n
    } catch (err) {
      componentLogger('rbac').error({ err, group: name }, 'could not remove a deleted group from its members')
    }
  }
  return updated
}

/** Takes RETIRED_GROUPS off their members once (a Redis set remembers which names are done). */
export async function pruneRetiredGroups(defined: Readonly<Record<string, unknown>>): Promise<void> {
  const redis = getRedisClient()
  const done = new Set(await redis.smembers(RETIRED_DONE_KEY))
  const due = RETIRED_GROUPS.filter((g) => !done.has(g) && !(g in defined))
  if (due.length === 0) return
  await forgetGroupMembers(due)
  await redis.sadd(RETIRED_DONE_KEY, ...due)
}
