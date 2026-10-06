import { getRedisClient } from '../services/redis-client.service.js'
import { withRedisLock } from '../services/redis-lock.js'

/**
 * Groups waiting for their member's second factor. Rule (b) of "Members must use 2FA"
 * (settings.ts): nobody holds such a group before they have enrolled. Refusing the addition outright
 * left a new colleague with no way in: the platform asks for a second factor only of people whose
 * groups require one, and they could not join a group before having one.
 *
 * So an addition of somebody who has not enrolled is kept here instead of refused, already past the
 * holding rule and the actor's own step-up (user-groups.service.ts). It is NOT a membership: OPA,
 * Kratos and the enforced store know nothing of it. What it does:
 *   - counts as "a second factor is required" for that person (status.ts), so login-ui's two-step
 *     gate and the console's banner send them straight to enrolment;
 *   - is applied the moment they have one (the Kratos settings hook, or their next status check),
 *     through the same group update, holding rule included, as of the person who added them.
 *
 *   jinbe:groups:awaiting_second_factor   Hash identityId → JSON AwaitingGroups
 *
 * Kept AWAITING_TTL_DAYS; a newer addition for the same person merges with it and restarts the clock.
 */

export const AWAITING_TTL_DAYS = 7
const KEY = 'jinbe:groups:awaiting_second_factor'
const DAY_MS = 24 * 60 * 60 * 1000

export interface AwaitingGroups {
  groups: string[]
  /** Who added them: the group update is replayed as theirs. */
  by: { id: string; email: string }
  at: string
  expiresAt: string
}

const redis = () => getRedisClient()

function parse(raw: string | null | undefined): AwaitingGroups | null {
  if (!raw) return null
  try {
    const v = JSON.parse(raw) as Partial<AwaitingGroups>
    if (!Array.isArray(v.groups) || typeof v.expiresAt !== 'string' || typeof v.by?.id !== 'string' || typeof v.by?.email !== 'string') return null
    return { groups: v.groups.filter((g): g is string => typeof g === 'string'), by: v.by, at: v.at ?? '', expiresAt: v.expiresAt }
  } catch {
    return null
  }
}

export const awaitingSecondFactor = {
  /** Records (or adds to) the groups waiting for this person's second factor. */
  async add(identityId: string, groups: readonly string[], by: AwaitingGroups['by'], now = Date.now()): Promise<AwaitingGroups> {
    return withRedisLock(`awaiting-second-factor:${identityId}`, async () => {
      const held = await this.get(identityId, now)
      const entry: AwaitingGroups = {
        groups: [...new Set([...(held?.groups ?? []), ...groups])].sort(),
        by,
        at: new Date(now).toISOString(),
        expiresAt: new Date(now + AWAITING_TTL_DAYS * DAY_MS).toISOString(),
      }
      await redis().hset(KEY, identityId, JSON.stringify(entry))
      return entry
    })
  },

  /** The live entry, or null (an expired one is dropped). */
  async get(identityId: string, now = Date.now()): Promise<AwaitingGroups | null> {
    const entry = parse(await redis().hget(KEY, identityId))
    if (entry && Date.parse(entry.expiresAt) > now && entry.groups.length > 0) return entry
    if (entry) await redis().hdel(KEY, identityId)
    return null
  },

  async remove(identityId: string): Promise<void> {
    await redis().hdel(KEY, identityId)
  },
}

/** What applying the entry needs, injected so this module does not import the group service (cycle). */
export interface ApplyAwaitingDeps {
  hasSecondFactor: (identityId: string) => Promise<boolean>
  /** The group update as the person who added them, add-only. True when it was applied. */
  addGroups: (identityId: string, groups: string[], by: AwaitingGroups['by']) => Promise<{ ok: boolean; status?: number }>
}

/**
 * Applies what waits for `identityId` once they have a second factor. A refusal of the update (the
 * adder lost the right meanwhile, a group left the model) drops the entry: retrying would only be
 * refused again. A failure to tell (Kratos, Redis) keeps it for the next try. Never throws.
 */
export async function applyAwaitingGroups(identityId: string | null | undefined, deps: ApplyAwaitingDeps, log?: { warn: (o: object, m: string) => void }): Promise<'applied' | 'refused' | 'waiting' | 'none'> {
  if (!identityId) return 'none'
  try {
    const entry = await awaitingSecondFactor.get(identityId)
    if (!entry) return 'none'
    if (!(await deps.hasSecondFactor(identityId))) return 'waiting'
    const result = await deps.addGroups(identityId, entry.groups, entry.by)
    if (!result.ok && (result.status ?? 500) >= 500) return 'waiting'
    await awaitingSecondFactor.remove(identityId)
    return result.ok ? 'applied' : 'refused'
  } catch (err) {
    log?.warn({ err, identityId }, 'Groups waiting for a second factor were not applied')
    return 'waiting'
  }
}
